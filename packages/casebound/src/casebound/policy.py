"""Algorithm 3: Retrieve_Current_Policy (invariant C3)."""
from __future__ import annotations

from datetime import date

from .events import EventType, digest
from .ledger import Ledger
from .ports import (ComplianceFeed, NoCurrentPolicyError, PendingSupersededError, PolicyEvidence,
                    PolicyIndex, PolicyIntegrityError, PolicyVersion)


def policy_digest(v: PolicyVersion) -> str:
    return digest([v.policy_id, v.version, v.body])


def retrieve_current_policy(ledger: Ledger, case_id: str, index: PolicyIndex, workflow: str, jurisdiction: str,
                            today: date, feed: ComplianceFeed | None = None,
                            effective_dating_authoritative: bool = False) -> PolicyEvidence:
    """As written in the paper, plus the optional Section 7.1 strengthening.

    effective_dating_authoritative=True: if the compliance feed holds a delivered-but-unapproved
    successor whose effective date has arrived, the incumbent is pending-superseded and the case
    is routed to human review instead of being served the stale version.
    """
    cand = index.query(workflow, jurisdiction)
    approved = [v for v in cand if v.state == "APPROVED"]
    current = [v for v in approved if v.effective_at(today)]
    if not current:
        ledger.append(case_id, EventType.NO_CURRENT_POLICY, {"workflow": workflow, "jurisdiction": jurisdiction})
        raise NoCurrentPolicyError(f"no approved policy effective on {today}")
    selected = max(current, key=lambda v: v.version)
    if effective_dating_authoritative and feed is not None:
        succ = [v for v in feed.versions(selected.policy_id)
                if v.version > selected.version and v.state != "APPROVED" and v.effective_from <= today]
        if succ:
            s = min(succ, key=lambda v: v.version)
            ledger.append(case_id, EventType.POLICY_PENDING_SUPERSEDED,
                          {"incumbent": selected.ref, "successor": s.ref, "successor_effective": str(s.effective_from)})
            raise PendingSupersededError(f"{selected.ref} pending-superseded by {s.ref}")
    if selected.digest != policy_digest(selected):
        ledger.append(case_id, EventType.POLICY_INTEGRITY_FAILED, {"policy_ref": selected.ref})
        raise PolicyIntegrityError(selected.ref)
    e = ledger.append(case_id, EventType.POLICY_RETRIEVED,
                      {"policy_ref": selected.ref, "policy_id": selected.policy_id, "version": selected.version,
                       "digest": selected.digest, "effective_from": str(selected.effective_from),
                       "effective_to": str(selected.effective_to) if selected.effective_to else None})
    return PolicyEvidence(selected.ref, selected, e.hash)


class InMemoryPolicyStore:
    """Serves as both the retrieval index and the compliance feed for tests/demos.

    `ingest()` snapshots APPROVED versions into the index (the human sign-off gate);
    `deliver()` adds a version to the feed only, reproducing the Section 7.1 window.
    """

    def __init__(self) -> None:
        self._feed: dict[str, list[PolicyVersion]] = {}
        self._index: list[PolicyVersion] = []

    def deliver(self, v: PolicyVersion) -> None:
        self._feed.setdefault(v.policy_id, []).append(v)

    def retire(self, policy_id: str, version: int, effective_to: date) -> None:
        vs = self._feed[policy_id]
        for i, v in enumerate(vs):
            if v.version == version:
                vs[i] = PolicyVersion(v.policy_id, v.version, v.state, v.effective_from, effective_to, v.digest, v.body)

    def approve(self, policy_id: str, version: int) -> None:
        vs = self._feed[policy_id]
        for i, v in enumerate(vs):
            if v.version == version:
                vs[i] = PolicyVersion(v.policy_id, v.version, "APPROVED", v.effective_from, v.effective_to, v.digest, v.body)

    def ingest(self) -> None:
        self._index = [v for vs in self._feed.values() for v in vs if v.state == "APPROVED"]

    # PolicyIndex
    def query(self, workflow: str, jurisdiction: str) -> list[PolicyVersion]:
        return [v for v in self._index if v.body.get("workflow") == workflow and v.body.get("jurisdiction") == jurisdiction]

    # ComplianceFeed
    def versions(self, policy_id: str) -> list[PolicyVersion]:
        return list(self._feed.get(policy_id, []))


def make_version(policy_id: str, version: int, state: str, effective_from: date, effective_to: date | None, **body) -> PolicyVersion:
    v = PolicyVersion(policy_id, version, state, effective_from, effective_to, "", body)
    return PolicyVersion(policy_id, version, state, effective_from, effective_to, policy_digest(v), body)
