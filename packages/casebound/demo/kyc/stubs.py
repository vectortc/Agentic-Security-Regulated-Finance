"""Deterministic stand-ins for the model-backed components (planner, decider).

These are the `Planner` and `Decider` ports: pure model interfaces with no ledger dependency.
They never append events -- `casebound.model.GatedModelAdapter` does that around every call,
which is what makes the deployment inference-mediated in the sense Theorem 1 requires.
"""
from __future__ import annotations

from typing import Any

from casebound import Decision, Plan, PolicyEvidence, steps_for

from .tools import ROLE, WORKFLOW, registry

DEFAULT_PLAN = ["doc_verify", "bureau_pull", "ach_check"]


class StubPlanner:
    def __init__(self, extra: list[str] | None = None, empty: bool = False,
                 steps: list[str] | None = None) -> None:
        self.extra, self.empty, self.steps = extra or [], empty, steps

    def plan(self, workflow: str, policy: PolicyEvidence, redacted: dict[str, Any]) -> Plan:
        if self.empty:
            names: list[str] = []
        elif self.steps is not None:
            names = list(self.steps)
        else:                                   # the plan follows the applied policy's required checks
            required = policy.version.body.get("required_checks") if policy else None
            names = list(required) if required else list(DEFAULT_PLAN)
        return Plan(steps_for(registry, names + self.extra, ROLE, workflow))


def policy_decision(results: list[dict[str, Any]], policy_ref: str, threshold: int) -> Decision:
    """The policy-grounded rule.

    Used by the decider on the honest path AND by the Proposition 1 audit comparator. That the
    two are the same function is the demo's convenience: in production the reference has to come
    from somewhere the model does not control.

    The rule is KYC step-up determination as Section 7.1 describes it: below the applied policy's
    score threshold, refer for step-up verification. An identity document mismatch rejects.
    """
    r: dict[str, Any] = {}
    for x in results:
        r.update(x["response"])
    f = []
    if r.get("id_match") is False:
        f.append("identity_document_mismatch")
    if "score" in r and r["score"] < threshold:
        f.append(f"score_below_stepup_threshold({policy_ref})")
    d = "REJECT" if "identity_document_mismatch" in f else "REFER" if f else "PASS"
    return Decision(d, tuple(f) or ("all_checks_passed",))


class StubDecider:
    def decide(self, results, policy: PolicyEvidence, redacted: dict[str, Any]) -> Decision:
        if any("APPROVE" in str(v).upper() for v in redacted.values()):          # injected instruction steers the model
            return Decision("PASS", ("employment_stable",))
        return policy_decision(results, policy.ref, policy.version.body["stepup_threshold"])
