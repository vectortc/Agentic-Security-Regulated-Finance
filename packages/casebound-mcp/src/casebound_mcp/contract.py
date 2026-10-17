"""The case-bound tool-call contract: Section 5.3's case-ID propagation layer as an interface.

Section 7.2 reports that MCP tools built without audit in scope carry no case identifier, session
context or provenance in their call signatures, and that retrofitting them was the expensive part.
This module is the contract a tool has to meet before it can sit behind the gateway:

  request   case_id   required, in the engine's format; the protocol rejects a call without one
            payload   what the workflow sends the tool (Algorithm 4's output on the in-process path)
            envelope  Algorithm 2's provenance: tool, capability, policy_ref, attempt, idempotency_key...
            context   synthetic back ends only: the scenario's fixture. A real tool ignores it.
  response  {"case_id", "idempotency_key", "result"}: the tool echoes both keys, so the caller can
            check that the answer belongs to this case and this attempt before it is recorded.

The paper describes the case id as "a mandatory header". Here it is a required argument in the
tool's input schema, which MCP clients discover through tools/list and the server validates before
the tool runs, on every MCP transport.
"""
from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from casebound import ControlException

#: `casebound.workflow.new_case_id()` format.
CASE_ID_PATTERN = r"^c-[0-9a-f]{12}$"
#: Tool metadata key carrying the capability Algorithm 2 authorizes (C2), published in tools/list.
CAPABILITY_META = "casebound/capability"

CaseId = Annotated[str, Field(pattern=CASE_ID_PATTERN,
                              description="The case this call belongs to. Mandatory: an untagged call is refused.")]

#: Keys `casebound.gateway.build_tool_envelope` writes. Everything else in the envelope Algorithm 2
#: hands the adapter is the payload or the request context.
ENVELOPE_KEYS = frozenset({"tool", "capability", "agent_role", "workflow", "payload_digest", "policy_ref",
                           "boundary_class", "attempt", "idempotency_key", "authz_digest"})


class ToolContractError(ControlException):
    """A tool answered, but not for this case or this attempt (the propagation check failed).

    A ControlException, so Algorithm 1 routes the case to human review. The ledger then holds
    TOOL_INVOKED without TOOL_COMPLETED for the attempt, which Algorithm 5 reports as unmatched.
    """


class ToolExecutionError(RuntimeError):
    """The tool failed after TOOL_INVOKED was recorded: an infrastructure failure, like a worker crash.

    Deliberately not a ControlException. Algorithm 1 re-raises it with the case id attached and the
    ledger keeps the invoked-without-completed pair, exactly as for the in-process `crash` scenario.
    """


def to_arguments(envelope: dict[str, Any]) -> dict[str, Any]:
    """Split the dict Algorithm 2 passes to `ToolAdapter.invoke` into the contract's arguments."""
    provenance = {k: v for k, v in envelope.items() if k in ENVELOPE_KEYS}
    context = {k: v for k, v in envelope.items() if k not in ENVELOPE_KEYS | {"case_id", "payload"}}
    return {"case_id": envelope["case_id"], "payload": envelope.get("payload", {}),
            "envelope": provenance, "context": context}


def respond(case_id: str, idempotency_key: str | None, result: dict[str, Any]) -> dict[str, Any]:
    return {"case_id": case_id, "idempotency_key": idempotency_key, "result": result}


def check_response(tool: str, case_id: str, idempotency_key: str | None, response: Any) -> dict[str, Any]:
    """The result, if the response echoes this case and attempt; ToolContractError otherwise."""
    if not isinstance(response, dict) or not isinstance(response.get("result"), dict):
        raise ToolContractError(f"{tool} returned no contract response for case {case_id}")
    if response.get("case_id") != case_id:
        raise ToolContractError(f"{tool} answered for case {response.get('case_id')!r}, not {case_id}")
    if response.get("idempotency_key") != idempotency_key:
        raise ToolContractError(f"{tool} answered attempt {response.get('idempotency_key')!r}, not {idempotency_key}")
    return response["result"]
