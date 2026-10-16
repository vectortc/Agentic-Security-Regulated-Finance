"""The gated path to a real model (M3): GatedModelAdapter + ModelClient + casebound.llm.

A scripted ModelClient stands in for the provider, so these run without network. What they pin:
the gate scans and records the *whole* payload the model receives (tool results included), a
real client never receives a payload that still carries PII, every call lands as an INFERENCE
event even when it fails, invalid model output routes to human review, and Theorem 1 still
holds when the planner and decider are model-backed.
"""
from datetime import date, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from casebound import (COMPLETE, FAILED, AllowRedactedOnly, EventType, InMemoryLedger, InMemoryPolicyStore,
                       LLMDecider, LLMPlanner, ModelRequest, ModelResponse, Request, StaticAuthorizer, ToolRegistry,
                       WorkflowContext, execute_regulated_workflow, make_version, phi, reconstruct)
from demo.kyc.data import SCHEMA
from demo.kyc.run import run_scenario
from demo.kyc.stubs import policy_decision

TODAY = date(2026, 9, 5)


class ScriptedClient:
    """Answers plan requests with `plan` (or the policy's required checks) and decide requests with
    `decision`, or with the policy-grounded rule over the tool results it was sent."""

    def __init__(self, plan=None, decision=None, fail: Exception | None = None):
        self.plan, self.decision, self.fail, self.requests = plan, decision, fail, []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if self.fail:
            raise self.fail
        if request.purpose == "plan":
            out = {"steps": self.plan if self.plan is not None
                   else request.payload["policy"]["body"].get("required_checks", []), "rationale": "policy"}
        else:
            if self.decision is not None:
                out = self.decision
            else:
                body = request.payload["policy"]["body"]
                d = policy_decision(request.payload["tool_results"], "", body["stepup_threshold"])
                out = {"decision": d.decision,
                       "factors": [f.split("(")[0] for f in d.factors]}
        return ModelResponse(out, "scripted", "scripted-1", "scripted-1-served", "req_123",
                             {"max_tokens": 1000}, {"input_tokens": 10, "output_tokens": 5, "inference_geo": "us"})


def _inferences(ledger, case_id):
    return [e for e in ledger.fetch_by_case(case_id) if e.type == EventType.INFERENCE]


# --- the KYC demo through the gated path ---------------------------------------------------------

def test_model_backed_case_completes_and_records_who_served_it():
    client = ScriptedClient()
    outcome, v, _, ledger = run_scenario("happy", return_ledger=True, model_client=client)
    assert v.status == COMPLETE, v.checks
    inf = _inferences(ledger, outcome.case_id)
    assert [e.data["purpose"] for e in inf] == ["plan", "decide"]
    for e in inf:
        assert e.data["model"] == "scripted-1-served" and e.data["requested_model"] == "scripted-1"
        assert e.data["provider"] == "scripted" and e.data["request_id"] == "req_123"
        assert e.data["usage"]["inference_geo"] == "us" and e.data["payload_pii"] == []
        assert e.data["instructions_digest"] and e.data["output_digest"] and e.data["redaction_ev"]
    assert inf[0].data["plan_steps"]                    # line 8 traversability still reads the plan
    assert "tool_results" in inf[1].data["payload_fields"]


def test_the_decide_payload_the_gate_records_is_the_one_the_model_received():
    client = ScriptedClient()
    outcome, _, _, ledger = run_scenario("happy", return_ledger=True, model_client=client)
    from casebound import digest
    recorded = [e.data["payload_digest"] for e in _inferences(ledger, outcome.case_id)]
    assert recorded == [digest(r.payload) for r in client.requests]


def test_pii_in_a_tool_result_never_reaches_a_real_model():
    """The C4 hole a real decider opens: tool responses ride along to the model. The stub scan
    looked only at the redacted record; the gate scans everything and refuses to send."""
    L = InMemoryLedger()
    outcome = _run_with_tool_response(L, {"ok": True, "contact": "applicant@example.test"}, block=True,
                                      client=(client := ScriptedClient()))
    assert outcome.outcome == "HUMAN_REVIEW" and "InferenceBoundaryError" in outcome.reason
    assert [r.purpose for r in client.requests] == ["plan"]          # decide was never sent
    denied = [e for e in L.fetch_by_case(outcome.case_id) if e.type == EventType.REDACTION_BOUNDARY_FAILED]
    assert denied and denied[0].data["payload_pii"] == ["tool_results[0].response.contact"]


def test_without_blocking_the_leak_is_recorded_and_the_gate_fails_the_case():
    """Detect-at-audit, as in the paper: line 6 fires on the full payload, not just the record."""
    L = InMemoryLedger()
    outcome = _run_with_tool_response(L, {"ok": True, "contact": "applicant@example.test"}, block=False,
                                      client=ScriptedClient())
    decide = [e for e in _inferences(L, outcome.case_id) if e.data["purpose"] == "decide"][0]
    assert decide.data["payload_pii"] == ["tool_results[0].response.contact"]
    assert outcome.status == FAILED


def test_a_failed_model_call_still_leaves_an_inference_event():
    L = InMemoryLedger()
    with pytest.raises(TimeoutError):
        _run_with_tool_response(L, {"ok": True}, block=True, client=ScriptedClient(fail=TimeoutError("provider")))
    inf = [e for e in L._events if e.type == EventType.INFERENCE]
    assert inf and inf[0].data["error"] == "TimeoutError" and inf[0].data["model"] is None


@pytest.mark.parametrize("decision, why", [
    ({"decision": "APPROVE", "factors": ["x"]}, "is not one of"),
    ({"decision": "PASS", "factors": []}, "no factors"),
])
def test_invalid_model_output_routes_to_human_review(decision, why):
    L = InMemoryLedger()
    outcome = _run_with_tool_response(L, {"ok": True}, block=True, client=ScriptedClient(decision=decision))
    assert outcome.outcome == "HUMAN_REVIEW" and "ModelOutputError" in outcome.reason and why in outcome.reason
    decide = [e for e in _inferences(L, outcome.case_id) if e.data["purpose"] == "decide"][0]
    assert why in decide.data["output_error"]           # the call happened, so the event is there


def test_a_planned_tool_outside_the_authorized_set_is_still_denied_by_the_gate():
    """A mis-configured catalogue offers a tool the role is not authorized for; the model picks it.
    Algorithm 2 still denies it: the planner proposes, the gate disposes."""
    L = InMemoryLedger()
    outcome = _run_with_tool_response(L, {"ok": True}, block=True, client=ScriptedClient(plan=["t1", "t2"]),
                                      allowed={"t1"})
    assert outcome.outcome == "HUMAN_REVIEW" and "AuthorizationError" in outcome.reason


def test_model_backed_ports_never_hold_a_client():
    planner = LLMPlanner(_registry, "r", {"t1": "tool one"})
    decider = LLMDecider(("PASS", "REFER"))
    for port in (planner, decider):
        assert not any(hasattr(v, "complete") for v in vars(port).values())


# --- helpers ------------------------------------------------------------------------------------

_registry = ToolRegistry()
_TOOL_RESPONSE: dict = {}
for _n in ["t1", "t2", "t3"]:
    _registry.controlled_tool(_n)(lambda env: dict(_TOOL_RESPONSE))


def _store(approved=True, eff_offset=-10, exp_len=None, required=("t1",)):
    store = InMemoryPolicyStore()
    eff = TODAY + timedelta(days=eff_offset)
    exp = None if exp_len is None else eff + timedelta(days=exp_len)
    store.deliver(make_version("p", 1, "APPROVED" if approved else "DELIVERED", eff, exp, workflow="w",
                               jurisdiction="US", required_checks=list(required), stepup_threshold=600))
    store.ingest()
    return store


def _ctx(L, store, client, allowed, block):
    return WorkflowContext(L, store, store, StaticAuthorizer({("r", "w"): set(allowed)}), AllowRedactedOnly(), _registry,
                           LLMPlanner(_registry, "r", {"t1": "one", "t2": "two", "t3": "three"}),
                           LLMDecider(("PASS", "REFER", "REJECT")), SCHEMA, today=lambda: TODAY,
                           model_client=client, block_unredacted_inference=block)


def _run_with_tool_response(L, response, block, client, allowed=("t1", "t2", "t3")):
    _TOOL_RESPONSE.clear()
    _TOOL_RESPONSE.update(response)
    ctx = _ctx(L, _store(), client, allowed, block)
    return execute_regulated_workflow(ctx, Request("w", "US", "r", {"employer_name": "x", "product": "y"}))


# --- Theorem 1, model-backed ----------------------------------------------------------------------

@settings(max_examples=150, deadline=None)
@given(allowed=st.frozensets(st.sampled_from(["t1", "t2", "t3"])),
       plan=st.lists(st.sampled_from(["t1", "t2", "t3"]), max_size=3),
       eff_offset=st.integers(-400, 30), exp_len=st.one_of(st.none(), st.integers(0, 400)),
       approved=st.booleans(), leak=st.booleans(), block=st.booleans(),
       decision=st.sampled_from([None, {"decision": "PASS", "factors": ["all_checks_passed"]},
                                 {"decision": "MAYBE", "factors": ["x"]}]))
def test_theorem1_holds_on_the_model_backed_path(allowed, plan, eff_offset, exp_len, approved, leak, block, decision):
    """Same equivalence as tests/test_theorem1.py, with a model-backed planner and decider behind
    the gate, random model outputs (including invalid ones) and PII smuggled in a tool result."""
    _TOOL_RESPONSE.clear()
    _TOOL_RESPONSE.update({"ok": True, **({"contact": "a@example.test"} if leak else {}), "channels": 2, "score": 700})
    L = InMemoryLedger()
    store = _store(approved, eff_offset, exp_len)
    ctx = _ctx(L, store, ScriptedClient(plan=plan, decision=decision), allowed, block)
    execute_regulated_workflow(ctx, Request("w", "US", "r", {"employer_name": "x", "product": "y"}))
    case_id = L._events[0].case_id
    v = reconstruct(L, case_id, ctx.authorizer, store)
    assert (v.status == COMPLETE) == all(phi(case_id, L.fetch_by_case(case_id), ctx.authorizer, store).values())
