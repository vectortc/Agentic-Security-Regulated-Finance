"""The gated model adapter: the only path by which a model call may happen.

The SPE manuscript places INFERENCE emission inside the model-backed components --
"Model inference occurs only inside Orchestrator.Plan and Decision_Engine.Decide; both
receive only the redacted payload and log an INFERENCE event carrying the redaction-evidence
reference" (Section 4, Cross-references) -- and Assumption A1 makes it a correctness
requirement: "every model call must traverse the redaction path of Algorithm 4 and emit an
INFERENCE event, so an un-instrumented inference cannot leave a C4 violation unobserved."

v0.1 emitted the event from Algorithm 1, around the model call. That works only while
Algorithm 1 is the sole caller. This adapter moves emission to the boundary itself: the
`Planner` and `Decider` ports stay pure model interfaces with no ledger dependency, and this
class is the single component that may invoke them. A second inference path is then a visible
architectural violation rather than an invisible one.

The adapter also runs the payload PII scan at the moment of the call, which is what makes
`Some_Inference_Payload_Unredacted` (Algorithm 5, line 6) decidable from the chain: the
INFERENCE event records the field names that still carried PII in the payload the model
actually received.
"""
from __future__ import annotations

from typing import Any, Callable, TypeVar

from .events import EventType, digest
from .ledger import Ledger
from .ports import (Decider, Decision, InferenceBoundaryError, ModelBackedDecider, ModelBackedPlanner, ModelClient,
                    ModelRequest, ModelResponse, Plan, Planner, PolicyEvidence, RedactionEvidence)
from .redaction import scan_payload_pii, scan_payload_pii_deep

T = TypeVar("T")


class GatedModelAdapter:
    """Wraps a Planner and a Decider; emits one INFERENCE event per model call.

    `inference-mediated` in the sense of Theorem 1 means every model call goes through here.
    Nothing enforces that at runtime -- it is an architectural property of the deployment,
    exactly as gate-mediation is for tools -- but routing every call through one class makes
    the property auditable by inspection, and the demo's `pii-leak` scenario shows what the
    ledger looks like when it is violated.

    Two paths. Plain `Planner`/`Decider` ports (the deterministic stubs) are called directly and
    the event describes the redacted record they were given. A `ModelBackedPlanner` /
    `ModelBackedDecider` paired with a `ModelClient` takes the gated path: the port builds a
    `ModelRequest`, this class scans the *entire* payload, sends it, records who served it, and
    only then hands the response back to the port to parse. The port never holds the client, so
    no model-backed component can reach the model except through here.
    """

    def __init__(self, ledger: Ledger, planner: Planner, decider: Decider, model_id: str = "stub",
                 client: ModelClient | None = None, block_unredacted: bool = True) -> None:
        self._ledger, self._planner, self._decider, self._model_id = ledger, planner, decider, model_id
        self._client = client
        #: With a real client, refuse to send a payload that still carries PII (prevention), and
        #: log it as Algorithm 4's REDACTION_BOUNDARY_FAILED. The stub path keeps the paper's
        #: detect-at-audit behaviour, since a stub sends nothing anywhere.
        self._block_unredacted = block_unredacted

    # --- gated path: a real model behind a ModelClient ----------------------------------------

    def _gated_call(self, case_id: str, request: ModelRequest, red_ev: RedactionEvidence | None,
                    parse: Callable[[ModelResponse], T], describe: Callable[[T], dict[str, Any]]) -> T:
        assert self._client is not None
        leaked = scan_payload_pii_deep(request.payload)       # everything that is about to cross
        if leaked and self._block_unredacted:
            self._ledger.append(case_id, EventType.REDACTION_BOUNDARY_FAILED, {
                "stage": "inference_gate", "purpose": request.purpose, "decision": "DENY",
                "payload_pii": leaked, "payload_digest": digest(request.payload)})
            raise InferenceBoundaryError(f"{request.purpose} payload still carries PII in {', '.join(leaked)}")

        record: dict[str, Any] = {
            "purpose": request.purpose,
            "redaction_ev": red_ev.event_hash if red_ev else None,
            "boundary_class": red_ev.boundary_class if red_ev else "UNMEDIATED",
            "payload_digest": digest(request.payload),
            "payload_fields": sorted(request.payload),
            "payload_pii": leaked,
            "instructions_digest": digest(request.instructions),
            "output_schema_digest": digest(request.output_schema),
        }
        try:
            response = self._client.complete(request)
        except Exception as e:           # the call may or may not have reached the provider: record it either way
            self._ledger.append(case_id, EventType.INFERENCE, {**record, "model": None, "error": type(e).__name__})
            raise
        record.update({
            "model": response.served_model,
            "requested_model": response.requested_model,
            "provider": response.provider,
            "request_id": response.request_id,
            "params": response.params,
            "usage": response.usage,
            "output_digest": digest(response.output),
        })
        try:
            result = parse(response)
        except Exception as e:           # invalid output: the call happened, so the event still lands
            self._ledger.append(case_id, EventType.INFERENCE, {**record, "output_error": str(e)})
            raise
        self._ledger.append(case_id, EventType.INFERENCE, {**record, **describe(result)})
        return result

    # --- the two model calls of Algorithm 1 -----------------------------------------------------

    def _emit(self, case_id: str, purpose: str, redacted: dict[str, Any], leaked: list[str],
              red_ev: RedactionEvidence | None, extra: dict[str, Any] | None = None) -> None:
        self._ledger.append(case_id, EventType.INFERENCE, {
            "purpose": purpose,
            "model": self._model_id,
            "redaction_ev": red_ev.event_hash if red_ev else None,
            "boundary_class": red_ev.boundary_class if red_ev else "UNMEDIATED",
            "payload_digest": digest(redacted),
            "payload_fields": sorted(redacted),
            "payload_pii": leaked,          # Some_Inference_Payload_Unredacted: non-empty means C4 is violated
            **(extra or {}),
        })

    def plan(self, case_id: str, workflow: str, policy: PolicyEvidence,
             redacted: dict[str, Any], red_ev: RedactionEvidence | None) -> Plan:
        if self._client is not None and isinstance(self._planner, ModelBackedPlanner):
            planner = self._planner
            return self._gated_call(case_id, planner.plan_request(workflow, policy, redacted), red_ev,
                                    lambda r: planner.parse_plan(workflow, r), _describe_plan)
        leaked = scan_payload_pii(redacted)          # scanned on the payload about to leave the boundary
        plan = self._planner.plan(workflow, policy, redacted)
        steps = [s.tool for s in plan.steps]
        self._emit(case_id, "plan", redacted, leaked, red_ev, {"plan_steps": steps, "plan_digest": digest(steps)})
        return plan

    def decide(self, case_id: str, results: list[dict[str, Any]], policy: PolicyEvidence,
               redacted: dict[str, Any], red_ev: RedactionEvidence | None) -> Decision:
        if self._client is not None and isinstance(self._decider, ModelBackedDecider):
            decider = self._decider
            return self._gated_call(case_id, decider.decide_request(results, policy, redacted), red_ev,
                                    decider.parse_decision, _describe_decision)
        leaked = scan_payload_pii(redacted)
        decision = self._decider.decide(results, policy, redacted)
        self._emit(case_id, "decide", redacted, leaked, red_ev, _describe_decision(decision))
        return decision


def _describe_plan(plan: Plan) -> dict[str, Any]:
    steps = [s.tool for s in plan.steps]
    return {"plan_steps": steps, "plan_digest": digest(steps)}


def _describe_decision(decision: Decision) -> dict[str, Any]:
    return {"decision_digest": digest([decision.decision, list(decision.factors)])}
