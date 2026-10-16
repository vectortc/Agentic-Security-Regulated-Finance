"""Casebound as an MCP gateway: an outside agent reaches the tools only through Algorithm 2."""
import pytest

from casebound import AllowRedactedOnly, EventType, InMemoryLedger
from casebound_mcp import build_gateway
from casebound_mcp.contract import CASE_ID_PATTERN
from conftest import call, list_tools, open_case
from demo.kyc.data import applicant
from demo.kyc.tools import ROLE, authorizer

KYC_STEPS = ("doc_verify", "bureau_pull", "ach_check")
PAYLOAD = {"city": "Rockville", "state": "MD", "product": "consumer_credit", "full_name": "TOK_1a2b3c4d"}


@pytest.fixture
def ledger():
    return InMemoryLedger()


@pytest.fixture
def gateway(ledger, kyc_tools, store):
    fixture = applicant("borderline")["fixture"]
    return build_gateway(ledger, authorizer, AllowRedactedOnly(), kyc_tools, store, ROLE,
                         context_for=lambda case_id: {"fixture": fixture})


def _types(ledger, case_id):
    return [e.type for e in ledger.fetch_by_case(case_id)]


def test_the_gateway_publishes_case_id_and_payload_as_the_only_inputs(gateway):
    for tool in list_tools(gateway):
        schema = tool.input_schema
        assert sorted(schema["properties"]) == ["case_id", "payload"] and "case_id" in schema["required"]
        assert schema["properties"]["case_id"]["pattern"] == CASE_ID_PATTERN


def test_each_call_is_gated_and_recorded_before_and_after(gateway, ledger, store, tool_log):
    case_id = open_case(ledger, store)
    for tool in KYC_STEPS:
        r = call(gateway, tool, {"case_id": case_id, "payload": PAYLOAD})
        assert not r.is_error, r.content
        assert r.structured_content["case_id"] == case_id
    chain = ledger.fetch_by_case(case_id)
    assert [e.type for e in chain][2:] == [EventType.TOOL_INVOKED, EventType.TOOL_COMPLETED] * len(KYC_STEPS)
    invoked = [e.data for e in chain if e.type == EventType.TOOL_INVOKED]
    assert [d["tool"] for d in invoked] == list(KYC_STEPS)
    assert all(d["agent_role"] == ROLE and d["workflow"] == "kyc_onboarding" and d["policy_ref"] for d in invoked)
    assert [r["idempotency_key"] for r in tool_log] == [d["idempotency_key"] for d in invoked]


def test_a_call_without_a_case_id_never_reaches_the_ledger_or_the_tool(gateway, ledger, tool_log):
    before = ledger.count()
    assert call(gateway, "bureau_pull", {"payload": PAYLOAD}).is_error
    assert ledger.count() == before and tool_log == []


def test_a_case_the_ledger_never_opened_is_refused_and_nothing_is_appended(gateway, ledger, tool_log):
    r = call(gateway, "bureau_pull", {"case_id": "c-0123456789ab", "payload": PAYLOAD})
    assert r.is_error and "not open" in r.content[0].text
    assert ledger.count() == 0 and tool_log == []


def test_c2_a_capability_outside_the_role_is_denied_and_the_denial_recorded(gateway, ledger, store, tool_log):
    case_id = open_case(ledger, store)
    r = call(gateway, "account_close", {"case_id": case_id, "payload": PAYLOAD})
    assert r.is_error and "AuthorizationError" in r.content[0].text
    assert _types(ledger, case_id)[-1] == EventType.TOOL_AUTHZ_DENIED and tool_log == []


def test_c4_a_payload_carrying_pii_is_stopped_at_the_gate(gateway, ledger, store, tool_log):
    case_id = open_case(ledger, store)
    leaky = {**PAYLOAD, "contact": {"email": "aisha.okafor59@example.test"}}   # nested, fiction-reserved
    r = call(gateway, "bureau_pull", {"case_id": case_id, "payload": leaky})
    assert r.is_error and "BoundaryViolationError" in r.content[0].text
    last = ledger.fetch_by_case(case_id)[-1]
    assert last.type == EventType.BOUNDARY_VIOLATION and last.data["boundary_class"] == "raw-pii"
    assert tool_log == []


def test_c3_a_case_with_no_recorded_policy_fails_grounding(gateway, ledger, store, tool_log):
    case_id = open_case(ledger, store, retrieve_policy=False)
    r = call(gateway, "bureau_pull", {"case_id": case_id, "payload": PAYLOAD})
    assert r.is_error and "PolicyGroundingError" in r.content[0].text
    assert _types(ledger, case_id)[-1] == EventType.POLICY_GROUNDING_FAILED and tool_log == []


def test_c3_a_recorded_policy_the_feed_does_not_hold_fails_grounding(gateway, ledger, store, tool_log):
    case_id = open_case(ledger, store)
    other = open_case(ledger, store)
    forged = next(e for e in ledger.fetch_by_case(other) if e.type == EventType.POLICY_RETRIEVED).data
    ledger.append(case_id, EventType.POLICY_RETRIEVED, {**forged, "digest": "0" * 16})
    r = call(gateway, "bureau_pull", {"case_id": case_id, "payload": PAYLOAD})
    assert r.is_error and _types(ledger, case_id)[-1] == EventType.POLICY_GROUNDING_FAILED and tool_log == []


def test_a_closed_case_takes_no_more_calls(gateway, ledger, store):
    case_id = open_case(ledger, store)
    ledger.append(case_id, EventType.ROUTED_TO_HUMAN_REVIEW, {"reason": "test"})
    before = ledger.count()
    r = call(gateway, "bureau_pull", {"case_id": case_id, "payload": PAYLOAD})
    assert r.is_error and "closed" in r.content[0].text and ledger.count() == before


def test_a_repeated_call_is_a_new_attempt_with_its_own_idempotency_key(gateway, ledger, store):
    case_id = open_case(ledger, store)
    keys = [call(gateway, "bureau_pull", {"case_id": case_id, "payload": PAYLOAD}).structured_content["idempotency_key"]
            for _ in range(2)]
    invoked = [e.data for e in ledger.fetch_by_case(case_id) if e.type == EventType.TOOL_INVOKED]
    assert [d["attempt"] for d in invoked] == [1, 2] and keys[0] != keys[1]
