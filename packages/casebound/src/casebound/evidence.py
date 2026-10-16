"""Evidence packs: regulator-shaped views over a Verdict. Templates, not legal advice."""
from __future__ import annotations

from typing import Any, Callable

from .events import EventType
from .reconstruct import COMPLETE, Verdict

ReasonMap = Callable[[str], str]


def adverse_action_statement(v: Verdict, reason_text: ReasonMap, adverse_decisions=("REJECT", "REFER")) -> dict[str, Any]:
    """Statement of specific reasons in the shape of Reg B §1002.9(b)(2): reasons must
    reflect the factors actually recorded, so it is only issuable on a COMPLETE chain."""
    d = v.decision
    if d is None:
        return {"issuable": False, "why": "no decision recorded; case is in human review"}
    if d.data["decision"] not in adverse_decisions:
        return {"issuable": False, "why": f"decision {d.data['decision']} is not adverse"}
    if v.status != COMPLETE:
        return {"issuable": False, "why": f"gate returned {v.status}; notice withheld pending human review"}
    return {"issuable": True, "case_id": v.case_id, "action": d.data["decision"],
            "principal_reasons": [reason_text(f) for f in d.data["factors"]],
            "basis": {"decision_event": d.seq, "policy_ref": v.policy.data["policy_ref"] if v.policy else None,
                      "tool_events": [t.seq for t in v.tools]}}


def art12_record(v: Verdict, system_id: str) -> dict[str, Any]:
    """EU AI Act Art. 12 style automatic-logging record for one case (fields, not legal sufficiency)."""
    inf = [e for e in v.events if e.type == EventType.INFERENCE]
    return {"system": system_id, "case_id": v.case_id,
            "period": [v.events[0].ts, v.events[-1].ts] if v.events else None,
            "events_logged": len(v.events),
            "policy_versions": sorted({e.data["policy_ref"] for e in v.events if e.type == EventType.POLICY_RETRIEVED}),
            "inference_boundary": ["redacted-structured" if e.data.get("redaction_ev") else "RAW" for e in inf],
            "tools": [t.data["tool"] for t in v.tools],
            "human_oversight": any(e.type == EventType.ROUTED_TO_HUMAN_REVIEW for e in v.events),
            "verdict": v.status, "invariants": v.invariants}
