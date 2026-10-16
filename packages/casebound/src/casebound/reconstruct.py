"""Algorithm 5: Reconstruct_Decision_Evidence, the invariant predicates C1-C5,
and the Proposition 1 audit-time comparator.

Everything here is a function of the case's event chain (plus the authorizer
and the compliance feed, which are the reference sets the predicates quantify over).

Two behaviours admit more than one reading of the manuscript, and each is switchable in one
argument.

  LINE9_STATUS      line 9's status for a violated invariant. The default follows the status-
                    semantics paragraph (FAILED); `reconstruct(..., line9_status=INCOMPLETE)`
                    follows the pseudocode.
  PLAN_COMMITMENT   `Is_Chain_Traversable` is not spelled out in the manuscript. We read it as also
                    requiring that every step the planner declared reached the gate, which is
                    what lets a gate bypass (Section 7.2) surface as INCOMPLETE instead of
                    certifying COMPLETE. `reconstruct(..., paper_literal=True)` drops the extra
                    clause and reproduces the manuscript's own stated outcome under an A1
                    violation: "Algorithm 5 may return COMPLETE for a case whose true execution
                    violates an invariant."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable

from .events import Event, EventType
from .gateway import authorizer_digest
from .ledger import Ledger
from .ports import Authorizer, ComplianceFeed

COMPLETE, INCOMPLETE, FAILED = "COMPLETE", "INCOMPLETE", "FAILED"

#: Status returned by line 9 when the per-event invariant conjunction fails. See module docstring.
LINE9_STATUS = FAILED

#: Whether `Is_Chain_Traversable` also requires declared-plan-step coverage. See module docstring.
PLAN_COMMITMENT = True


@dataclass(frozen=True)
class Check:
    line: int
    invariant: str
    name: str
    passed: bool
    note: str


@dataclass
class Verdict:
    case_id: str
    status: str
    checks: list[Check] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    invariants: dict[str, bool] = field(default_factory=dict)
    divergence: dict[str, Any] | None = None
    #: Non-blocking audit findings: things a reviewer should see that do not change the verdict.
    findings: list[dict[str, Any]] = field(default_factory=list)
    mode: str = "extended"

    @property
    def decision(self) -> Event | None:
        return next((e for e in self.events if e.type == EventType.DECISION_RECORDED), None)

    @property
    def policy(self) -> Event | None:
        return next((e for e in self.events if e.type == EventType.POLICY_RETRIEVED), None)

    @property
    def tools(self) -> list[Event]:
        return [e for e in self.events if e.type == EventType.TOOL_COMPLETED]

    @property
    def review(self) -> Event | None:
        """Extension beyond the paper: the human closure of a routed case."""
        return next((e for e in self.events if e.type == EventType.REVIEW_DECISION), None)

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "status": self.status, "mode": self.mode, "invariants": self.invariants,
                "checks": [c.__dict__ for c in self.checks], "divergence": self.divergence,
                "findings": self.findings, "events": [e.to_dict() for e in self.events]}


def _by(events: list[Event], t: EventType) -> list[Event]:
    return [e for e in events if e.type == t]


def _plan_coverage(events: list[Event]) -> list[str]:
    """Declared plan steps with no case-tagged tool event.

    The paper leaves `Is_Chain_Traversable` (Alg 5, line 8) opaque; this is the
    reference reading of it: the planner's INFERENCE event names the steps, and the
    chain is traversable only if each declared step reached the gate (invoked, or
    denied and logged). Absence of evidence for a declared step is INCOMPLETE, not a
    proven violation - a bypassed call leaves no case-tagged trace at all, so proving
    it requires the cross-source reconciliation in `reconcile()`, outside Algorithm 5.
    """
    plan = next((e for e in _by(events, EventType.INFERENCE) if e.data.get("purpose") == "plan"), None)
    if plan is None:
        return []
    reached = ({e.data["tool"] for e in _by(events, EventType.TOOL_INVOKED)}
               | {e.data["tool"] for e in _by(events, EventType.TOOL_AUTHZ_DENIED)})
    return [t for t in plan.data["plan_steps"] if t not in reached]


def _orphan_invocations(events: list[Event]) -> list[str]:
    """TOOL_INVOKED records with no matching TOOL_COMPLETED, matched per attempt.

    Keying on the idempotency key rather than the tool name is what keeps a legitimate retry
    (attempt 1 crashed, attempt 2 completed) distinguishable from a crash that was never
    retried; on chains written before the envelope carried attempts, this falls back to the
    tool name and behaves exactly as v0.1 did.
    """
    def key(e: Event) -> str:
        return e.data.get("idempotency_key") or e.data["tool"]
    done = {key(e) for e in _by(events, EventType.TOOL_COMPLETED)}
    return sorted({e.data["tool"] for e in _by(events, EventType.TOOL_INVOKED) if key(e) not in done})


def _unredacted_inferences(events: list[Event]) -> tuple[list[Event], list[Event]]:
    """The two legs of SPE Algorithm 5, line 6.

    `not chain.has_redaction` -> an inference event with no redaction-evidence reference.
    `Some_Inference_Payload_Unredacted(events)` -> an inference event whose recorded payload
    still carried PII. The second leg is new in the SPE version; v0.1 checked only the first,
    so a chain that ran Algorithm 4 and still leaked a field passed the gate.
    """
    inf = _by(events, EventType.INFERENCE)
    return ([e for e in inf if not e.data.get("redaction_ev")],
            [e for e in inf if e.data.get("payload_pii")])


def _policy_effective(pol: Event | None, feed: ComplianceFeed) -> bool:
    if pol is None:
        return False
    ref = next((v for v in feed.versions(pol.data["policy_id"]) if v.version == pol.data["version"]), None)
    return ref is not None and ref.effective_at(date.fromisoformat(pol.ts[:10]))


def phi(case_id: str, events: list[Event], authorizer: Authorizer, feed: ComplianceFeed,
        plan_commitment: bool = PLAN_COMMITMENT) -> dict[str, bool]:
    """The five invariants as predicates over E(c) (Section 6.1). Used by tests to
    check Theorem 1: reconstruct(...).status == COMPLETE  <=>  all(phi(...).values())."""
    invoked = {e.data["tool"] for e in _by(events, EventType.TOOL_INVOKED)}
    completed = _by(events, EventType.TOOL_COMPLETED)
    seqs = [e.seq for e in events]
    c1 = (bool(events) and all(e.case_id == case_id for e in events)          # case-bound continuity
          and seqs == list(range(1, len(events) + 1))                          # no gaps
          and all(e.verify() for e in events))                                 # digests verify
    c2 = all(authorizer.authorize(e.data.get("agent_role", ""), e.data.get("workflow", ""), e.data["capability"])
             for e in _by(events, EventType.TOOL_INVOKED))
    pol = _by(events, EventType.POLICY_RETRIEVED)
    c3 = len(pol) > 0 and all(_policy_effective(p, feed) for p in pol)
    missing_ev, leaked = _unredacted_inferences(events)                        # SPE line 6, both legs
    c4 = not missing_ev and not leaked
    dec = _by(events, EventType.DECISION_RECORDED)
    c5 = (len(dec) == 1 and len(completed) > 0 and invoked == {e.data["tool"] for e in completed}
          and not (plan_commitment and _plan_coverage(events)))
    return {"C1": c1, "C2": c2, "C3": c3, "C4": c4, "C5": c5}


def reconstruct(ledger: Ledger, case_id: str, authorizer: Authorizer, feed: ComplianceFeed,
                comparator: Callable[[Verdict], dict[str, Any] | None] | None = None,
                paper_literal: bool = False, line9_status: str | None = None) -> Verdict:
    """Algorithm 5. `paper_literal=True` drops the plan-commitment clause and returns line 9's
    manuscript status, reproducing the text exactly; see the module docstring."""
    plan_commitment = PLAN_COMMITMENT and not paper_literal
    line9 = line9_status or (INCOMPLETE if paper_literal else LINE9_STATUS)

    ev = ledger.fetch_by_case(case_id)                                           # line 1: O(E_case)
    v = Verdict(case_id, COMPLETE, events=ev, mode="paper-literal" if paper_literal else "extended")
    status = [COMPLETE]

    def ck(line, inv, name, passed, note, on_fail=INCOMPLETE):
        v.checks.append(Check(line, inv, name, passed, note))
        if not passed and status[0] == COMPLETE:
            status[0] = on_fail

    if not ev:                                                                    # line 2
        ck(2, "C1", "events non-empty", False, "no events for case", FAILED)
        v.status = FAILED
        return v
    seqs = [e.seq for e in ev]
    gaps = seqs != list(range(1, len(ev) + 1))
    broken = [e.seq for e in ev if not e.verify()]
    ck(3, "C1", "sequence gaps / malformed events", not gaps and not broken,                        # line 3
       "seq not contiguous (event lost after its number was assigned)" if gaps
       else f"hash mismatch at seq {broken} (ledger tampering: A5 violated)" if broken
       else f"seq 1..{len(ev)} contiguous, hash chain intact", FAILED)
    pol = _by(ev, EventType.POLICY_RETRIEVED)
    ck(5, "C3", "policy evidence present", bool(pol), pol[0].data["policy_ref"] if pol else "no POLICY_RETRIEVED event")   # line 5
    inf = _by(ev, EventType.INFERENCE)
    missing_ev, leaked = _unredacted_inferences(ev)
    leaked_fields = sorted({f for e in leaked for f in e.data.get("payload_pii", [])})
    ck(6, "C4", "inference redacted (evidence reference and PII-free payload)", not missing_ev and not leaked,   # line 6
       "inference occurred without redaction evidence (raw payload crossed the boundary)" if missing_ev
       else f"redaction ran but the payload sent to the model still carried PII in {leaked_fields} "
            f"(Some_Inference_Payload_Unredacted)" if leaked
       else f"{len(inf)} inference event(s) reference REDACTION_COMPLETED, payloads PII-free", FAILED)
    dec = _by(ev, EventType.DECISION_RECORDED)
    tools = _by(ev, EventType.TOOL_COMPLETED)
    ck(7, "C5", "decision recorded and tool chain non-empty", len(dec) == 1 and bool(tools),             # line 7
       "no DECISION_RECORDED" if not dec else "tool chain empty (zero-tool plan)" if not tools else f"{dec[0].data['decision']} with {len(tools)} tool event(s)")
    orphan = _orphan_invocations(ev)
    uncovered = _plan_coverage(ev) if plan_commitment else []
    ck(8, "C5", "chain traversable (every INVOKED has COMPLETED"                                       # line 8
       + ("; declared steps reached the gate)" if plan_commitment else ")"),
       not orphan and not uncovered,
       f"TOOL_INVOKED {orphan} without TOOL_COMPLETED (crash between invoke and complete)" if orphan
       else f"declared plan step(s) {uncovered} have no case-tagged tool event - evidence absent, violation not proven from E(c); run reconcile()" if uncovered
       else "traversable end to end")
    p = phi(case_id, ev, authorizer, feed, plan_commitment)                                            # line 9
    v.invariants = p
    ck(9, "C1-C5", "per-event invariant checks", all(p.values()),
       " · ".join(f"{k} {'ok' if ok else 'VIOLATED'}" for k, ok in p.items()), line9)
    v.status = status[0]
    v.findings = _findings(ev, authorizer, paper_literal)
    if comparator is not None and v.status == COMPLETE:
        v.divergence = comparator(v)                                              # Proposition 1: audit-time step, outside Algs 1-5
    return v


def _findings(events: list[Event], authorizer: Authorizer, paper_literal: bool) -> list[dict[str, Any]]:
    """Non-blocking observations. These never change the status - Theorem 1 is an equivalence
    with phi, and adding a status source would break it - but an auditor needs to see them."""
    out: list[dict[str, Any]] = []
    now = authorizer_digest(authorizer)
    recorded = {e.data.get("authz_digest") for e in _by(events, EventType.TOOL_INVOKED) if e.data.get("authz_digest")}
    if now and recorded and recorded != {now}:
        out.append({"kind": "entitlement_drift", "severity": "warn",
                    "note": "the authorizer's entitlement set changed since this case ran; C2 above was evaluated "
                            "against today's allowed set, not the one in force at t(e) (Eq. 2 has no time index)",
                    "recorded": sorted(x for x in recorded if x), "current": now})
    if paper_literal and _plan_coverage(events):
        out.append({"kind": "plan_step_unevidenced", "severity": "serious",
                    "note": "a declared plan step has no case-tagged tool event. Under the manuscript's literal "
                            "line 8 this does not affect the status, which is the A1 gate-bypass hazard the paper "
                            "names in Section 7.2; only cross-source reconciliation can prove it",
                    "steps": _plan_coverage(events)})
    review = _by(events, EventType.REVIEW_DECISION)
    if review:
        r = review[-1].data
        out.append({"kind": "human_review_closed", "severity": "info",
                    "note": f"case closed by {r.get('reviewer')} as {r.get('outcome')}: {r.get('rationale', '')}",
                    "outcome": r.get("outcome"), "reviewer": r.get("reviewer")})
    return out


def reconcile(ledger: Ledger, verdict: Verdict) -> list[dict[str, Any]]:
    """Cross-source reconciliation: a deployment-level control, NOT part of Algorithm 5.

    An event emitted without a case tag never touches the case's sequence counter, so it
    is invisible to `fetch_by_case` and cannot open a gap. Only comparing the case-indexed
    ledger against the tool-adapter / gateway log for the case's execution window can prove
    a non-gate-mediated call occurred. Findings are reported alongside the verdict; they
    never change it.
    """
    uncovered = _plan_coverage(verdict.events)
    findings: list[dict[str, Any]] = []
    for e in ledger.untagged():
        tool = e.data.get("tool")
        findings.append({"source_event": e.hash, "tool": tool, "type": e.type.value,
                         "explains_uncovered_step": tool in uncovered,
                         "note": "untagged record matches a declared plan step with no case-tagged evidence"
                                 if tool in uncovered else "untagged record not attributable to this case"})
    return findings
