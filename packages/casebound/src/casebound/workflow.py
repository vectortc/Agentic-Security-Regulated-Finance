"""Algorithm 1: Execute_Regulated_Workflow.

Pure orchestration over the ports. Two hooks exist only so tests and demos can
reproduce *non-gate-mediated* paths (the Section 7.2 hazard and the C4 leak);
production code must not override them.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable

from .events import Event, EventType, digest
from .gateway import invoke_controlled_tool
from .ledger import Ledger
from .model import GatedModelAdapter
from .policy import retrieve_current_policy
from .ports import (Authorizer, BoundaryEnforcer, ComplianceFeed, ControlException, Decider, ModelClient,
                    PolicyEvidence, PolicyIndex, Planner, ToolAdapter, ToolStep)
from .reconstruct import reconstruct
from .redaction import ExtractionSchema, redact_before_inference


@dataclass(frozen=True)
class Request:
    workflow: str
    jurisdiction: str
    agent_role: str
    input: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)   # passed to tools (e.g. synthetic fixtures); never to the model


@dataclass(frozen=True)
class Outcome:
    case_id: str
    outcome: str            # decision string, or HUMAN_REVIEW / CRASHED
    reason: str
    status: str | None = None   # gate status when the gate ran


@dataclass
class WorkflowContext:
    ledger: Ledger
    policy_index: PolicyIndex
    compliance_feed: ComplianceFeed
    authorizer: Authorizer
    boundary: BoundaryEnforcer
    tools: ToolAdapter          # ToolRegistry in process, or casebound_mcp.McpToolAdapter over MCP
    planner: Planner
    decider: Decider
    schema: ExtractionSchema
    today: Callable[[], date] = date.today
    effective_dating_authoritative: bool = False
    #: Algorithm 5 mode for the in-line gate. See casebound.reconstruct's module docstring.
    paper_literal: bool = False
    #: Record tool responses in the ledger (demo) or only their digests.
    store_response_inline: bool = True
    model_id: str = "stub"
    #: A real model (e.g. casebound_models.AnthropicModelClient). Used only when planner/decider are
    #: model-backed (casebound.llm); GatedModelAdapter is then the sole caller of client.complete().
    model_client: ModelClient | None = None
    #: With model_client set, refuse to send a payload that still carries PII (see GatedModelAdapter).
    block_unredacted_inference: bool = True
    #: Override Classify_Boundary / Detect_PII (Alg 4). Demos use these to model an A3 false negative.
    boundary_classifier: Callable | None = None
    pii_detector: Callable | None = None
    # test/demo-only hooks (see module docstring)
    redact_hook: Callable | None = None
    tool_invoker_hook: Callable | None = None


def new_case_id() -> str:
    return "c-" + uuid.uuid4().hex[:12]


def execute_regulated_workflow(ctx: WorkflowContext, request: Request) -> Outcome:
    L = ctx.ledger
    case_id = new_case_id()
    L.append(case_id, EventType.CASE_OPENED, {"workflow": request.workflow, "jurisdiction": request.jurisdiction,
                                              "agent_role": request.agent_role, "input_digest": digest(request.input)})
    policy: PolicyEvidence | None = None
    try:
        redact = ctx.redact_hook or (lambda: redact_before_inference(L, case_id, request.input, ctx.schema, ctx.boundary, ctx.boundary_classifier, ctx.pii_detector))
        redacted, red_ev, _vault = redact()                                                   # C4, Alg 4
        policy = retrieve_current_policy(L, case_id, ctx.policy_index, request.workflow, request.jurisdiction,
                                         ctx.today(), ctx.compliance_feed, ctx.effective_dating_authoritative)  # C3, Alg 3
        model = GatedModelAdapter(L, ctx.planner, ctx.decider, ctx.model_id,   # the only path to the model
                                  ctx.model_client, ctx.block_unredacted_inference)
        plan = model.plan(case_id, request.workflow, policy, redacted, red_ev)                # C4, INFERENCE
        results: list[dict[str, Any]] = []
        for step in plan.steps:                                                               # C2, Alg 2
            if ctx.tool_invoker_hook is not None:      # demo/test only: non-gate-mediated path
                response = ctx.tool_invoker_hook(step, case_id, redacted, policy)
            else:
                response = invoke_controlled_tool(L, case_id, step, redacted, policy, ctx.authorizer, ctx.boundary,
                                                  ctx.tools, request.context,
                                                  store_response_inline=ctx.store_response_inline)
            results.append({"tool": step.tool, "response": response})
        decision = model.decide(case_id, results, policy, redacted, red_ev)                    # C4, INFERENCE
        L.append(case_id, EventType.DECISION_RECORDED, {"decision": decision.decision, "factors": list(decision.factors)})  # C1, C5
    except ControlException as e:
        L.append(case_id, EventType.ROUTED_TO_HUMAN_REVIEW, {"reason": "CONTROL_EXCEPTION", "exception": type(e).__name__, "detail": str(e)})
        return Outcome(case_id, "HUMAN_REVIEW", f"{type(e).__name__}: {e}")
    except Exception as e:                       # infrastructure failure (crash): ledger keeps what was appended
        e.case_id = case_id                      # type: ignore[attr-defined]
        raise
    verdict = reconstruct(L, case_id, ctx.authorizer, ctx.compliance_feed,
                          paper_literal=ctx.paper_literal)                                    # C5, Alg 5
    if verdict.status != "COMPLETE":
        L.append(case_id, EventType.ROUTED_TO_HUMAN_REVIEW, {"reason": "INCOMPLETE_EVIDENCE", "status": verdict.status})
        return Outcome(case_id, "HUMAN_REVIEW", f"gate returned {verdict.status}", verdict.status)
    L.append(case_id, EventType.DECISION_PERSISTED, {"decision": decision.decision, "factors": list(decision.factors), "policy_ref": policy.ref})
    return Outcome(case_id, decision.decision, ", ".join(decision.factors), verdict.status)


def record_review_decision(ledger: Ledger, case_id: str, reviewer: str, outcome: str, rationale: str = "") -> Event:
    """Close a case that Algorithm 5 routed to human review. Extension beyond the paper.

    The manuscript's chain ends at ROUTED_TO_HUMAN_REVIEW, so a reviewed case never reaches a
    terminal state and the model does not cover the full case lifecycle.
    This appends the reviewer's disposition as a case-tagged, hash-chained event like any other,
    which keeps C1 intact and makes the human step part of the evidence rather than a gap in it.

    It deliberately does NOT make the case COMPLETE: Theorem 1 is an equivalence with Phi, and a
    human decision does not retroactively satisfy an invariant the execution violated. The
    disposition surfaces as a non-blocking finding on the verdict.
    """
    return ledger.append(case_id, EventType.REVIEW_DECISION,
                         {"reviewer": reviewer, "outcome": outcome, "rationale": rationale})


def steps_for(tools: ToolAdapter, names: list[str], agent_role: str, workflow: str) -> tuple[ToolStep, ...]:
    """Helper for planners: build ToolSteps with the registry's capability names."""
    return tuple(ToolStep(n, tools.capability(n) if n in tools.names() else n, agent_role, workflow) for n in names)
