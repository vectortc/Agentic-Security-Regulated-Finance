"""Algorithm 2: Invoke_Controlled_Tool (invariants C2, C3, C4; C1 via the envelope).

Three gates in order (authorization, boundary, policy grounding), then
TOOL_INVOKED is appended *before* execution and TOOL_COMPLETED after, so a
crash in between is visible as an invoked-without-completed pair.
"""
from __future__ import annotations

from typing import Any, Callable

from .events import EventType, digest
from .ledger import Ledger
from .ports import (AuthorizationError, Authorizer, BoundaryEnforcer, BoundaryViolationError,
                    PolicyEvidence, PolicyGroundingError, ToolAdapter, ToolStep)

ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


class ToolRegistry:
    """In-process ToolAdapter; `@registry.controlled_tool(name, capability)` marks a function
    as reachable only through the gateway. `casebound_mcp` serves the same registry over MCP."""

    def __init__(self) -> None:
        self._tools: dict[str, tuple[str, ToolFn]] = {}

    def controlled_tool(self, name: str, capability: str | None = None):
        def deco(fn: ToolFn) -> ToolFn:
            self._tools[name] = (capability or name, fn)
            return fn
        return deco

    def capability(self, name: str) -> str:
        return self._tools[name][0]

    def invoke(self, tool: str, envelope: dict[str, Any]) -> dict[str, Any]:
        return self._tools[tool][1](envelope)

    def names(self) -> list[str]:
        return list(self._tools)


class StaticAuthorizer:
    """allowed[(role, workflow)] -> set of capabilities. Replace with IAM/OPA/Cedar in production."""

    def __init__(self, allowed: dict[tuple[str, str], set[str]]) -> None:
        self._allowed = allowed

    def authorize(self, agent_role: str, workflow: str, capability: str) -> bool:
        return capability in self._allowed.get((agent_role, workflow), set())

    def policy_set_digest(self) -> str:
        """Digest of the entitlement set this authorizer decided with.

        Eq. (2) quantifies over Allowed(role, wf) with no time index, so an audit run after
        entitlements change evaluates a past case against today's allowed set.
        Recording the digest in the tool envelope does not fix that by itself -- resolving a
        historical entitlement set needs a versioned authorizer -- but it makes the drift
        *visible*: `reconstruct()` reports it as a non-blocking finding rather than silently
        re-deciding an old case under new rules.
        """
        return digest(sorted((f"{r}/{w}", sorted(caps)) for (r, w), caps in self._allowed.items()))


def authorizer_digest(authorizer: Authorizer) -> str | None:
    """Optional capability: authorizers that can describe their entitlement set expose it."""
    fn = getattr(authorizer, "policy_set_digest", None)
    return fn() if callable(fn) else None


def build_tool_envelope(case_id: str, step: ToolStep, payload: dict[str, Any], policy: PolicyEvidence,
                        boundary_class: str = "redacted-structured", attempt: int = 1,
                        authz_digest: str | None = None) -> dict[str, Any]:
    """The envelope is the per-tool-call evidence record.

    `attempt` and `idempotency_key` are an extension beyond the paper:
    without them a retried step is indistinguishable from a duplicate invocation, and Lemma 1's
    invoked-without-completed pair cannot be told apart from "attempt 1 failed, attempt 2 ran".
    Traversability (line 8) is therefore defined over idempotency keys, not tool names.
    """
    env = {"case_id": case_id, "tool": step.tool, "capability": step.capability, "agent_role": step.agent_role,
           "workflow": step.workflow, "payload_digest": digest(payload), "policy_ref": policy.ref if policy else None,
           "boundary_class": boundary_class, "attempt": attempt}
    env["idempotency_key"] = digest([case_id, step.tool, step.capability, env["payload_digest"], attempt])
    if authz_digest:
        env["authz_digest"] = authz_digest
    return env


def policy_grounding_valid(policy: PolicyEvidence | None) -> bool:
    return policy is not None and policy.version.state == "APPROVED" and bool(policy.event_hash)


def invoke_controlled_tool(ledger: Ledger, case_id: str, step: ToolStep, payload: dict[str, Any],
                           policy: PolicyEvidence, authorizer: Authorizer, boundary: BoundaryEnforcer,
                           tools: ToolAdapter, request_context: dict[str, Any] | None = None,
                           attempt: int = 1, store_response_inline: bool = True,
                           boundary_class: str = "redacted-structured") -> dict[str, Any]:
    """`store_response_inline=False` records only the response digest.

    A bureau score is regulated data and production would keep it behind access control with
    the ledger holding a reference. The demo needs the payload to
    reconstruct decision factors, so it stays inline by default; the flag is here so the
    schema decision is one argument, not a rewrite.

    `boundary_class` defaults to what Algorithm 1 guarantees: its payload is Algorithm 4's output.
    A caller that cannot vouch for the payload (the MCP gateway, whose callers are outside the
    workflow) classifies it and passes the result, so the C4 gate below decides on the real class.
    """
    env = build_tool_envelope(case_id, step, payload, policy, boundary_class, attempt=attempt,
                              authz_digest=authorizer_digest(authorizer))
    if not authorizer.authorize(step.agent_role, step.workflow, step.capability):            # C2
        ledger.append(case_id, EventType.TOOL_AUTHZ_DENIED, env)
        raise AuthorizationError(f"{step.capability} not allowed for {step.agent_role}/{step.workflow}")
    if not boundary.allow(env["boundary_class"]):                                             # C4
        ledger.append(case_id, EventType.BOUNDARY_VIOLATION, env)
        raise BoundaryViolationError(env["boundary_class"])
    if not policy_grounding_valid(policy):                                                    # C3
        ledger.append(case_id, EventType.POLICY_GROUNDING_FAILED, env)
        raise PolicyGroundingError("policy evidence missing or unapproved")
    ledger.append(case_id, EventType.TOOL_INVOKED, env)                                       # C1: before execution
    response = tools.invoke(step.tool, {**env, "payload": payload, **(request_context or {})})
    completed = {"tool": step.tool, "capability": step.capability, "payload_digest": env["payload_digest"],
                 "response_digest": digest(response), "policy_ref": policy.ref,
                 "attempt": attempt, "idempotency_key": env["idempotency_key"]}
    if store_response_inline:
        completed["response"] = response
    ledger.append(case_id, EventType.TOOL_COMPLETED, completed)                                   # C1, C5
    return response
