"""Algorithm 2's C4 gate decides on the boundary class its caller supplies.

Algorithm 1 passes Algorithm 4's output, so the default class is redacted-structured. A caller that
cannot vouch for the payload (the MCP gateway) classifies it and passes the result; the gate then
stops a raw-PII payload before TOOL_INVOKED, and the tool never runs.
"""
from datetime import date

import pytest

from casebound import (AllowRedactedOnly, EventType, InMemoryLedger, PolicyEvidence, StaticAuthorizer, ToolRegistry,
                       ToolStep, invoke_controlled_tool, make_version)
from casebound.ports import BoundaryViolationError

STEP = ToolStep("bureau_pull", "bureau_pull", "kyc_agent", "kyc_onboarding")
AUTHZ = StaticAuthorizer({("kyc_agent", "kyc_onboarding"): {"bureau_pull"}})
POLICY = PolicyEvidence("kyc-policy@v14", make_version("kyc-policy", 14, "APPROVED", date(2026, 1, 1), None), "h")


def _registry(ran: list):
    reg = ToolRegistry()
    reg.controlled_tool("bureau_pull")(lambda env: ran.append(env["case_id"]) or {"score": 700})
    return reg


def test_default_boundary_class_is_what_algorithm_1_guarantees():
    ledger, ran = InMemoryLedger(), []
    invoke_controlled_tool(ledger, "c-1", STEP, {"state": "MD"}, POLICY, AUTHZ, AllowRedactedOnly(), _registry(ran))
    invoked = ledger.fetch_by_case("c-1")[0]
    assert invoked.type == EventType.TOOL_INVOKED and invoked.data["boundary_class"] == "redacted-structured"
    assert ran == ["c-1"]


def test_a_caller_supplied_raw_pii_class_is_stopped_before_invocation():
    ledger, ran = InMemoryLedger(), []
    with pytest.raises(BoundaryViolationError):
        invoke_controlled_tool(ledger, "c-1", STEP, {"email": "x@example.test"}, POLICY, AUTHZ, AllowRedactedOnly(),
                               _registry(ran), boundary_class="raw-pii")
    assert [e.type for e in ledger.fetch_by_case("c-1")] == [EventType.BOUNDARY_VIOLATION]
    assert ran == []
