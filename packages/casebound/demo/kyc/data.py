"""Loads the semi-synthetic dataset. Nothing here is real; see demo/kyc/generate.py.

`dataset.json` is generated, checked in, and shared: the Python demo reads it here and
`demo/build_dashboard.py` embeds the identical bytes into demo.html, so the browser prototype
and the Python core always run the same population and the same policy corpus.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from casebound import ExtractionSchema, make_version

DATASET_PATH = Path(__file__).with_name("dataset.json")
DATA: dict[str, Any] = json.loads(DATASET_PATH.read_text(encoding="utf-8"))

SCHEMA = ExtractionSchema(
    fields=tuple(DATA["schema"]["fields"]),
    pii_fields=tuple(DATA["schema"]["pii_fields"]),
    free_text_fields=tuple(DATA["schema"]["free_text_fields"]),
)

POPULATION: list[dict[str, Any]] = DATA["applicants"]
BY_ID: dict[str, dict[str, Any]] = {a["id"]: a for a in POPULATION}
POLICIES: list[dict[str, Any]] = DATA["policies"]
REASONS: dict[str, str] = DATA["reasons"]
TODAY = date.fromisoformat(DATA["meta"]["today"])


#: Stable, readable handles onto the generated population, resolved by the generator and stored in
#: the dataset so the Python demo, the browser prototype and the tests all mean the same person.
ROLES: dict[str, str] = dict(DATA["roles"])
#: Back-compatible aliases from the four hand-written applicants of v0.1.
ROLES.update({"maria": ROLES["clean"], "devon": ROLES["borderline"],
              "priya": ROLES["mismatch"], "luis": ROLES["single-channel"]})

#: v0.1 shape, kept so existing callers keep working.
APPLICANTS = {k: BY_ID[v] for k, v in ROLES.items()}


#: Section 7.3: two-factor authentication needs two active contact channels, so applicants with one
#: are excluded at intake. They never enter the automated pipeline and never become cases.
MIN_CONTACT_CHANNELS = 2


class ExcludedAtIntake(Exception):
    """The applicant cannot enter the automated pipeline (Section 7.3). No case is opened."""


def admitted(a: dict[str, Any]) -> bool:
    return a["fixture"]["channels"] >= MIN_CONTACT_CHANNELS


def applicant(ref: str) -> dict[str, Any]:
    """Resolve an applicant by generated id (APP-0007) or by role handle (borderline)."""
    if ref in BY_ID:
        return BY_ID[ref]
    if ref in ROLES:
        return BY_ID[ROLES[ref]]
    raise LookupError(f"unknown applicant {ref!r}; try an APP-#### id or one of {sorted(ROLES)}")


def policy_versions(policy_id: str = "kyc-policy", include_delivered: bool = False):
    """The corpus as PolicyVersion objects, digests computed by casebound.policy."""
    out = []
    for p in POLICIES:
        if p["policy_id"] != policy_id:
            continue
        if p["state"] != "APPROVED" and not include_delivered:
            continue
        out.append(make_version(p["policy_id"], p["version"], p["state"],
                                date.fromisoformat(p["effective_from"]),
                                date.fromisoformat(p["effective_to"]) if p["effective_to"] else None,
                                **p["body"]))
    return out


def reason_text(factor: str) -> str:
    if factor.startswith("score_below_stepup_threshold"):
        # The stub decider appends the policy ref ("...(kyc-policy@v14)"); a model-backed decider
        # returns the bare vocabulary code, and the ref is on the chain's POLICY_RETRIEVED event.
        source = factor.split("(", 1)[1].rstrip(")") if "(" in factor else "the applied policy"
        return f"Credit score below the verification threshold set by {source}; additional verification required."
    return REASONS.get(factor, factor)
