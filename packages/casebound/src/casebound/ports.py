"""Ports (interfaces) the core depends on. Adapters live in demo/ or in your deployment.

Everything domain-specific (which tools exist, what IAM says, what the model
returns, what the policy document contains) enters through these Protocols.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Protocol, runtime_checkable


class ControlException(Exception):
    """Base for every control failure raised by Algorithms 2-4 (caught by Algorithm 1)."""


class AuthorizationError(ControlException): ...
class BoundaryViolationError(ControlException): ...
class PolicyGroundingError(ControlException): ...
class NoCurrentPolicyError(ControlException): ...
class PolicyIntegrityError(ControlException): ...
class PendingSupersededError(ControlException): ...
class InferenceBoundaryError(ControlException): ...


class ModelOutputError(ControlException):
    """A model's output failed validation (schema, refusal, truncation, unknown tool).

    Output validation is a control like the gates in Algorithms 2-4: a plan or decision that
    cannot be validated must not be acted on, so it routes to human review through Algorithm 1's
    catch branch instead of crashing the case or being silently repaired.
    """


@dataclass(frozen=True)
class ToolStep:
    tool: str
    capability: str
    agent_role: str
    workflow: str


@dataclass(frozen=True)
class PolicyVersion:
    policy_id: str
    version: int
    state: str                     # APPROVED | DELIVERED | RETIRED
    effective_from: date
    effective_to: date | None
    digest: str
    body: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@v{self.version}"

    def effective_at(self, d: date) -> bool:
        return self.effective_from <= d and (self.effective_to is None or d <= self.effective_to)


@dataclass(frozen=True)
class PolicyEvidence:
    ref: str
    version: PolicyVersion
    event_hash: str


@dataclass(frozen=True)
class RedactionEvidence:
    event_hash: str
    boundary_class: str
    pii_fields: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    steps: tuple[ToolStep, ...]


@dataclass(frozen=True)
class Decision:
    decision: str                  # PASS | REFER | REJECT (domain-defined)
    factors: tuple[str, ...]


class Authorizer(Protocol):
    def authorize(self, agent_role: str, workflow: str, capability: str) -> bool: ...


class BoundaryEnforcer(Protocol):
    def allow(self, boundary_class: str) -> bool: ...


class PolicyIndex(Protocol):
    """The retrieval index the agent reads (a snapshot; may lag the feed)."""
    def query(self, workflow: str, jurisdiction: str) -> list[PolicyVersion]: ...


class ComplianceFeed(Protocol):
    """Compliance-authored source of truth for effective dating (used by the Section 7.1 fix and by audit)."""
    def versions(self, policy_id: str) -> list[PolicyVersion]: ...


class ToolAdapter(Protocol):
    """The tool catalogue Algorithm 2 executes against.

    `ToolRegistry` is the in-process implementation; `casebound_mcp.McpToolAdapter` reaches the same
    tools over MCP. Algorithm 2 only ever calls `invoke`, and only after its gates have passed.
    """
    def names(self) -> list[str]: ...
    def capability(self, tool: str) -> str: ...
    def invoke(self, tool: str, envelope: dict[str, Any]) -> dict[str, Any]: ...


class Planner(Protocol):
    """Model-backed; must only ever see the redacted payload."""
    def plan(self, workflow: str, policy: PolicyEvidence, redacted: dict[str, Any]) -> Plan: ...


class Decider(Protocol):
    def decide(self, results: list[dict[str, Any]], policy: PolicyEvidence, redacted: dict[str, Any]) -> Decision: ...


# --- Model-backed components -----------------------------------------------------------------
#
# A real model is reached through two halves. A ModelBackedPlanner / ModelBackedDecider only
# *builds* the request and *parses* the response; it never touches the network. A ModelClient
# sends a request and nothing else. GatedModelAdapter is the one component that holds both and
# calls ModelClient.complete(), so every byte that crosses the inference boundary passes through
# the gate, where it is scanned and recorded (Assumption A1, inference-mediation).


@dataclass(frozen=True)
class ModelRequest:
    purpose: str                   # "plan" | "decide"
    instructions: str              # system prompt: stable across cases
    payload: dict[str, Any]        # everything case-specific the model will see; scanned in full
    output_schema: dict[str, Any]  # JSON Schema the response must satisfy


@dataclass(frozen=True)
class ModelResponse:
    output: dict[str, Any]         # parsed JSON, already constrained by output_schema
    provider: str
    requested_model: str
    served_model: str              # may differ from requested_model if the provider fell back
    request_id: str | None = None
    params: dict[str, Any] = field(default_factory=dict)   # effort, max_tokens, inference_geo, ...
    usage: dict[str, Any] = field(default_factory=dict)    # token counts, where inference ran


@runtime_checkable
class ModelClient(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...


@runtime_checkable
class ModelBackedPlanner(Protocol):
    def plan_request(self, workflow: str, policy: PolicyEvidence, redacted: dict[str, Any]) -> ModelRequest: ...
    def parse_plan(self, workflow: str, response: ModelResponse) -> Plan: ...


@runtime_checkable
class ModelBackedDecider(Protocol):
    def decide_request(self, results: list[dict[str, Any]], policy: PolicyEvidence,
                       redacted: dict[str, Any]) -> ModelRequest: ...
    def parse_decision(self, response: ModelResponse) -> Decision: ...
