"""Event schema for the case-bound audit ledger (invariant C1).

Every consequential step appends one Event *before* the action it guards.
Events are immutable, case-tagged, sequence-numbered per case, and hash-chained.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    CASE_OPENED = "CASE_OPENED"
    REDACTION_COMPLETED = "REDACTION_COMPLETED"
    REDACTION_BOUNDARY_FAILED = "REDACTION_BOUNDARY_FAILED"
    POLICY_RETRIEVED = "POLICY_RETRIEVED"
    NO_CURRENT_POLICY = "NO_CURRENT_POLICY"
    POLICY_INTEGRITY_FAILED = "POLICY_INTEGRITY_FAILED"
    POLICY_PENDING_SUPERSEDED = "POLICY_PENDING_SUPERSEDED"
    INFERENCE = "INFERENCE"
    TOOL_AUTHZ_DENIED = "TOOL_AUTHZ_DENIED"
    BOUNDARY_VIOLATION = "BOUNDARY_VIOLATION"
    POLICY_GROUNDING_FAILED = "POLICY_GROUNDING_FAILED"
    TOOL_INVOKED = "TOOL_INVOKED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    DECISION_RECORDED = "DECISION_RECORDED"
    ROUTED_TO_HUMAN_REVIEW = "ROUTED_TO_HUMAN_REVIEW"
    DECISION_PERSISTED = "DECISION_PERSISTED"
    REVIEW_DECISION = "REVIEW_DECISION"          # extension beyond the paper: a human closes a routed case
    UNTAGGED = "UNTAGGED"  # emitted by non-gate-mediated paths; never carries a case id


def digest(obj: Any) -> str:
    """Canonical SHA-256 of any JSON-serialisable object (first 16 hex chars)."""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Event:
    case_id: str | None
    seq: int | None
    type: EventType
    ts: str
    data: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 16
    hash: str = ""

    def compute_hash(self) -> str:
        return digest([self.case_id, self.seq, self.type.value, self.ts, self.data, self.prev_hash])

    def verify(self) -> bool:
        return self.hash == self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "seq": self.seq, "type": self.type.value, "ts": self.ts,
                "data": self.data, "prev_hash": self.prev_hash, "hash": self.hash}
