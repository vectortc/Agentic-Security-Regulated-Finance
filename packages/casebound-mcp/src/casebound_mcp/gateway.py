"""Casebound as an MCP gateway: any MCP client reaches the tools only through Algorithm 2.

  agent (any MCP client) --MCP--> gateway (this) --Algorithm 2--> ToolAdapter --MCP--> tool servers

Every gateway tool takes `case_id` and `payload`, nothing else; the rest of Algorithm 2's inputs
come from the gateway's own state, never from the caller:

  case_id    must name a case that is open on the gateway's ledger (CASE_OPENED, no terminal
             event). Otherwise the call is refused and nothing is appended: a case id the ledger
             has never opened has no chain to extend (C1).
  role       the caller's agent role is the gateway's configuration (its credential), and the
             workflow is the one the case was opened under. C2 is decided on (role, workflow).
  policy     the case's own POLICY_RETRIEVED event, resolved against the compliance feed and
             checked by digest. A case without one fails C3 at the gate, on the ledger.
  boundary   the payload is scanned in full: the caller is outside the workflow, so the gateway
             cannot assume Algorithm 4 ran. PII in the payload fails C4 at the gate, on the ledger.

A gate refusal comes back to the caller as a tool error and stays on the ledger as the denial event
Algorithm 2 appends, exactly as on the in-process path.

Calls on the same case are serialized: the checks above read the case's chain and Algorithm 2
extends it, and two interleaved calls would otherwise race for the case's next sequence number.
Calls on different cases run concurrently.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from casebound import (ControlException, EventType, Ledger, PolicyEvidence, ToolAdapter, ToolStep, digest,
                       invoke_controlled_tool, scan_payload_pii_deep)
from casebound.ports import Authorizer, BoundaryEnforcer, ComplianceFeed

from .contract import CAPABILITY_META, CaseId, respond

#: Events after which a case takes no more tool calls.
TERMINAL = frozenset({EventType.DECISION_PERSISTED, EventType.ROUTED_TO_HUMAN_REVIEW, EventType.REVIEW_DECISION})


def classify_payload(payload: dict[str, Any]) -> str:
    """Classify_Boundary over the whole nested payload (the gateway cannot vouch for its caller)."""
    return "raw-pii" if scan_payload_pii_deep(payload) else "redacted-structured"


def policy_evidence(events: list[Any], feed: ComplianceFeed) -> PolicyEvidence | None:
    """The case's recorded policy, as the compliance feed holds it, or None if it cannot be resolved."""
    retrieved = [e for e in events if e.type == EventType.POLICY_RETRIEVED]
    if not retrieved:
        return None
    e = retrieved[-1]
    for v in feed.versions(e.data["policy_id"]):
        if v.version == e.data["version"] and v.digest == e.data["digest"]:
            return PolicyEvidence(v.ref, v, e.hash)
    return None


def build_gateway(ledger: Ledger, authorizer: Authorizer, boundary: BoundaryEnforcer, tools: ToolAdapter,
                  compliance_feed: ComplianceFeed, agent_role: str, *,
                  context_for: Callable[[str], dict[str, Any]] | None = None,
                  classifier: Callable[[dict[str, Any]], str] = classify_payload,
                  name: str = "casebound-gateway") -> MCPServer:
    """An MCP server exposing every tool in `tools` behind Algorithm 2.

    `context_for(case_id)` supplies the synthetic back ends' fixture for a case (demo and tests
    only); a deployment's tools look the applicant up in their own systems.
    """
    server = MCPServer(name, instructions=(
        "Casebound gateway. Every tool call must carry the case_id of an open case; calls are authorized "
        "for this agent's role and the case's workflow, and recorded on the case's evidence chain."))
    guard, locks = threading.Lock(), defaultdict(threading.Lock)

    def case_lock(case_id: str) -> threading.Lock:
        with guard:
            return locks[case_id]

    for tool in tools.names():
        server.add_tool(_handler(ledger, authorizer, boundary, tools, compliance_feed, agent_role, context_for,
                                 classifier, case_lock, tool),
                        name=tool, description=f"{tool}, gated by Algorithm 2 and recorded under case_id",
                        meta={CAPABILITY_META: tools.capability(tool)})
    return server


def _handler(ledger, authorizer, boundary, tools, feed, agent_role, context_for, classifier, case_lock, tool):
    def handler(case_id: CaseId, payload: dict[str, Any]) -> dict[str, Any]:
        with case_lock(case_id):
            return _gated_call(ledger, authorizer, boundary, tools, feed, agent_role, context_for, classifier,
                               tool, case_id, payload)
    handler.__name__ = tool
    return handler


def _gated_call(ledger, authorizer, boundary, tools, feed, agent_role, context_for, classifier, tool, case_id,
                payload) -> dict[str, Any]:
    events = ledger.fetch_by_case(case_id)
    opened = next((e for e in events if e.type == EventType.CASE_OPENED), None)
    if opened is None:
        raise ToolError(f"case {case_id} is not open on this gateway's ledger; nothing was recorded")
    if any(e.type in TERMINAL for e in events):
        raise ToolError(f"case {case_id} is closed; it takes no further tool calls")
    step = ToolStep(tool, tools.capability(tool), agent_role, opened.data["workflow"])
    pd = digest(payload)
    attempt = 1 + sum(1 for e in events if e.type == EventType.TOOL_INVOKED
                      and e.data.get("tool") == tool and e.data.get("payload_digest") == pd)
    try:
        result = invoke_controlled_tool(ledger, case_id, step, payload, policy_evidence(events, feed), authorizer,
                                        boundary, tools, context_for(case_id) if context_for else None,
                                        attempt=attempt, boundary_class=classifier(payload))
    except ControlException as e:
        raise ToolError(f"{type(e).__name__}: {e} (recorded on case {case_id})") from e
    done = next(e for e in reversed(ledger.fetch_by_case(case_id)) if e.type == EventType.TOOL_COMPLETED)
    return respond(case_id, done.data["idempotency_key"], result)
