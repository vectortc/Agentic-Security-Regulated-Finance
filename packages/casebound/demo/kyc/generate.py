"""Synthetic KYC population and policy corpus for the KYC pipeline of Section 5.1.

Every value is fabricated, and every numeric parameter below is illustrative: the manuscript
reports no score distribution, no mismatch rates and no thresholds, so none of these numbers is a
claim about the production deployment, and nothing the demo computes from them is evidence for
the paper's production observations. One parameter follows the paper on purpose: the share of
applicants with a single contact channel is set to its "roughly one in nine" (Section 7.3), so the
intake exclusion that section describes is visible in the demo.

Nothing here is real and nothing is derived from any real deployment's data. Identifiers use
ranges reserved for fiction so they can never collide with a live record:

  - SSNs use area numbers 900-999, which the SSA has never issued;
  - telephone numbers use the 555-01XX fictional exchange;
  - email uses the reserved .test / .invalid TLDs;
  - street addresses are invented and paired with real state codes only.

The generator is seeded, so the dataset is reproducible and reviewable in a diff. It is the
single source of truth for both engines: `demo/kyc/data.py` loads it, and
`demo/build_dashboard.py` embeds the same bytes into demo.html.

    python -m demo.kyc.generate            # rewrite dataset.json
    python -m demo.kyc.generate --report   # print the funnel it produces
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

DATASET = Path(__file__).with_name("dataset.json")
SEED = 1729
N_APPLICANTS = 140
TODAY = "2026-09-05"

# --- population shape (illustrative; see the module docstring) --------------------------
SCORE_MEAN, SCORE_SD, SCORE_MIN, SCORE_MAX = 752, 52, 521, 848
P_SINGLE_CHANNEL = 0.11        # Section 7.3: roughly one in nine present only one contact channel
P_ID_MISMATCH = 0.065
P_ADDRESS_MISMATCH = 0.08

GIVEN = ["Maria", "Devon", "Priya", "Luis", "Amara", "Kenji", "Rosa", "Idris", "Nadia", "Tomas",
         "Grace", "Omar", "Lena", "Marcus", "Ines", "Rahul", "Freya", "Diego", "Mei", "Samuel",
         "Aisha", "Viktor", "Chloe", "Hassan", "Beatriz", "Noor", "Elias", "Yara", "Colm", "Sofia"]
FAMILY = ["Chen", "Okafor", "Raman", "Herrera", "Lindqvist", "Adeyemi", "Novak", "Tanaka", "Bassi",
          "Moreau", "Silva", "Haddad", "Kowalski", "Nakamura", "Osei", "Petrov", "Vargas", "Ferreira",
          "Ibrahim", "Delgado", "Sorensen", "Mwangi", "Rossi", "Kaur", "Bergman", "Duarte"]
EMPLOYERS = ["Northgate Labs", "Riverbend Logistics", "Halcyon Freight", "Kestrel Analytics",
             "Lantern Foods", "Meridian Dental", "Harbour Line Marine", "Cedar Point Roofing",
             "Halliwell Press", "Ashgrove Nursery", "Ninth Street Bakery", "Quarry Hill Supply",
             "Brightwater Clinic", "Sable Creek Vineyard", "Tessellate Design", "Fenwick Tooling"]
OCCUPATIONS = ["registered nurse", "logistics coordinator", "software engineer", "dental hygienist",
               "line cook", "electrician", "account manager", "physiotherapist", "graphic designer",
               "warehouse supervisor", "self-employed contractor", "teacher", "paralegal", "welder"]
SOURCE_OF_FUNDS = ["salary", "salary", "salary", "business income", "savings", "investment income",
                   "salary", "pension", "business income"]
ACCOUNT_PURPOSE = ["day-to-day banking", "credit line", "savings", "business operating", "day-to-day banking"]
STREETS = ["Elm St", "Pine Ct", "Oak Ave", "Birch Ln", "Cedar Way", "Juniper Rd", "Alder Pl",
           "Sycamore Dr", "Hawthorn Cl", "Willow Bend", "Maple Row", "Chestnut Walk"]
CITIES = [("Arlington", "VA", "222"), ("Fairfax", "VA", "220"), ("Bethesda", "MD", "208"),
          ("Reston", "VA", "201"), ("Silver Spring", "MD", "209"), ("Alexandria", "VA", "223"),
          ("Rockville", "MD", "208"), ("Washington", "DC", "200")]
ID_DOCS = ["passport", "drivers_licence", "drivers_licence", "state_id", "passport"]
INCOME_BANDS = ["20-40k", "40-60k", "60-90k", "90-130k", "130k+"]
NOTE_TEMPLATES = [
    "Applicant uploaded {doc} and a utility bill dated last month.",
    "Uploaded {doc}. Second upload attempt required; first scan was cut off.",
    "Applicant called to confirm the application; identity questions answered.",
    "Uploaded {doc}; address on document is the previous address.",
    "Applicant uploaded {doc}. No further correspondence on file.",
]


def _truncated_normal(rng: random.Random, mean: float, sd: float, lo: int, hi: int) -> int:
    for _ in range(50):
        v = rng.gauss(mean, sd)
        if lo <= v <= hi:
            return int(round(v))
    return int(round(min(max(mean, lo), hi)))


def _applicant(rng: random.Random, i: int) -> dict[str, Any]:
    given, family = rng.choice(GIVEN), rng.choice(FAMILY)
    city, state, zip3 = rng.choice(CITIES)
    doc_type = rng.choice(ID_DOCS)
    handle = f"{given.lower()}.{family.lower()}{rng.randint(1, 99)}"
    channels = 1 if rng.random() < P_SINGLE_CHANNEL else rng.choice([2, 2, 2, 3])
    record: dict[str, Any] = {
        "full_name": f"{given} {family}",
        "dob": f"{rng.randint(1962, 2004)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
        "ssn": f"{rng.randint(900, 999)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
        "email": f"{handle}@example.test",
        "phone": f"+1-{rng.choice(['202', '703', '301', '571'])}-555-{rng.randint(100, 199):04d}",
        "address_line": f"{rng.randint(1, 480)} {rng.choice(STREETS)}",
        "city": city,
        "state": state,
        "postal_code": f"{zip3}{rng.randint(10, 99)}",
        "country_of_residence": "US",
        "nationality": rng.choice(["US", "US", "US", "US", "NG", "IN", "MX", "PH", "BR", "PL"]),
        "id_document_type": doc_type,
        "id_document_number": f"{doc_type[:1].upper()}{rng.randint(10_000_000, 99_999_999)}",
        "id_document_expiry": f"{rng.randint(2027, 2034)}-{rng.randint(1, 12):02d}-15",
        "occupation": rng.choice(OCCUPATIONS),
        "employer_name": rng.choice(EMPLOYERS),
        "stated_income_band": rng.choice(INCOME_BANDS),
        "source_of_funds": rng.choice(SOURCE_OF_FUNDS),
        "account_purpose": rng.choice(ACCOUNT_PURPOSE),
        "product": "consumer_credit",
        "notes": rng.choice(NOTE_TEMPLATES).format(doc=doc_type.replace("_", " ")),
    }
    if channels == 1:                      # Section 7.3: no second contact channel; excluded at intake
        record.pop("email")
        record["notes"] = "No email on file; applicant lost access to the address on record."
    fixture = {
        "score": _truncated_normal(rng, SCORE_MEAN, SCORE_SD, SCORE_MIN, SCORE_MAX),
        "channels": channels,
        "id_match": rng.random() > P_ID_MISMATCH,
        "address_match": rng.random() > P_ADDRESS_MISMATCH,
        "doc_quality": rng.choice(["ok", "ok", "ok", "ok", "low_resolution"]),
    }
    if not fixture["id_match"]:
        record["notes"] = "Name on the identification document differs from the application."
    return {"id": f"APP-{i:04d}", "label": f"{record['full_name']} · {fixture['score']} · "
            f"{fixture['channels']} channel{'s' if fixture['channels'] > 1 else ''}"
            f"{'' if fixture['id_match'] else ' · ID mismatch'}",
            "doc": record, "fixture": fixture}


# --- policy corpus ----------------------------------------------------------------------
def _policies() -> list[dict[str, Any]]:
    """A policy corpus with real lifecycle states, not a single threshold constant.

    v15 reproduces the Section 7.1 window: compliance has updated the policy to remove step-up
    verification above a lower score threshold and retired v14, but the retrieval index has not
    been re-ingested because sign-off is pending. Algorithm 3 therefore serves v14 -- a version the
    compliance feed considers retired -- until the Section 7.1 fix consults the feed directly. The
    EU family exists so jurisdiction scoping in Algorithm 3 is visible rather than assumed. Version
    numbers, dates and thresholds are illustrative.
    """
    common = {"required_checks": ["doc_verify", "bureau_pull", "ach_check"], "retention_days": 2555}
    return [
        {"policy_id": "kyc-policy", "version": 12, "state": "APPROVED",
         "effective_from": "2024-01-01", "effective_to": "2024-12-31",
         "body": {**common, "workflow": "kyc_onboarding", "jurisdiction": "US", "stepup_threshold": 740,
                  "summary": "Step-up verification below 740.",
                  "change_note": "Initial automated onboarding policy."}},
        {"policy_id": "kyc-policy", "version": 13, "state": "APPROVED",
         "effective_from": "2025-01-01", "effective_to": "2026-05-31",
         "body": {**common, "workflow": "kyc_onboarding", "jurisdiction": "US", "stepup_threshold": 720,
                  "summary": "Step-up verification below 720.",
                  "change_note": "Threshold lowered after first-year referral volume review."}},
        {"policy_id": "kyc-policy", "version": 14, "state": "APPROVED",
         "effective_from": "2026-06-01", "effective_to": None,
         "body": {**common, "workflow": "kyc_onboarding", "jurisdiction": "US", "stepup_threshold": 700,
                  "summary": "Step-up verification below 700.",
                  "change_note": "Threshold lowered to 700."}},
        {"policy_id": "kyc-policy", "version": 15, "state": "DELIVERED",
         "effective_from": "2026-09-01", "effective_to": None,
         "body": {**common, "workflow": "kyc_onboarding", "jurisdiction": "US", "stepup_threshold": 640,
                  "summary": "Step-up verification below 640.",
                  "change_note": "Delivered by compliance 2026-08-24: removes step-up verification for applicants "
                                 "scoring 640 or above. Sign-off pending: the retrieval index still serves v14. "
                                 "This is the Section 7.1 stale-policy window."}},
        {"policy_id": "kyc-policy-eu", "version": 4, "state": "APPROVED",
         "effective_from": "2026-02-01", "effective_to": None,
         "body": {**common, "workflow": "kyc_onboarding", "jurisdiction": "EU", "stepup_threshold": 690,
                  "summary": "EU onboarding: step-up below 690, Art. 22 human-review route mandatory.",
                  "change_note": "Aligned to the EU AI Act Art. 14 oversight requirement."}},
    ]


REASONS = {
    "identity_document_mismatch":
        "Unable to verify identity: information on the identification document did not match the application.",
    "employment_stable":
        "(model-stated factor with no policy-grounded basis recorded)",
}

SCHEMA = {
    # Fields the workflow needs. Everything else in the application record is dropped at extraction.
    "fields": ["full_name", "dob", "ssn", "email", "phone", "address_line", "city", "state",
               "postal_code", "country_of_residence", "nationality", "id_document_type",
               "id_document_number", "occupation", "employer_name", "stated_income_band",
               "source_of_funds", "account_purpose", "product", "notes"],
    # Tokenized before the payload may cross the inference boundary.
    "pii_fields": ["full_name", "dob", "ssn", "email", "phone", "address_line", "postal_code",
                   "id_document_number"],
    # Removed entirely: free text is where injected instructions and stray PII live.
    "free_text_fields": ["notes"],
}


def _roles(applicants: list[dict[str, Any]]) -> dict[str, str]:
    """Stable handles onto the generated population.

    Resolved here, stored in the dataset, and read by both engines, so "the borderline applicant"
    means the same person in the Python demo, the browser prototype and the test suite. Borderline
    is the one worth defaulting to: its score sits between the v14 and v15 thresholds, so it is the
    applicant a policy change moves and the one an injected "APPROVE" actually steers.
    """
    def first(pred):
        return next(a["id"] for a in applicants if pred(a["fixture"]))
    return {
        "clean": first(lambda f: f["id_match"] and f["score"] >= 760 and f["channels"] >= 2),
        "borderline": first(lambda f: f["id_match"] and f["channels"] >= 2 and 640 <= f["score"] < 700),
        "mismatch": first(lambda f: not f["id_match"] and f["channels"] >= 2),
        "single-channel": first(lambda f: f["id_match"] and f["channels"] == 1),
    }


def build(seed: int = SEED, n: int = N_APPLICANTS) -> dict[str, Any]:
    rng = random.Random(seed)
    applicants = [_applicant(rng, i + 1) for i in range(n)]
    roles = _roles(applicants)
    return {
        "meta": {
            "generator": "demo/kyc/generate.py", "seed": seed, "n": n, "today": TODAY,
            "synthetic": True,
            "default_applicant": roles["borderline"],
            "notice": "Synthetic. Every value is fabricated and every parameter is illustrative, except "
                      "the single-channel share, which follows Section 7.3. SSNs use never-issued 900-999 "
                      "area numbers, telephone numbers the 555-01XX fictional exchange, and email the "
                      "reserved .test TLD.",
        },
        "schema": SCHEMA,
        "roles": roles,
        "applicants": applicants,
        "policies": _policies(),
        "reasons": REASONS,
    }


def funnel(data: dict[str, Any], threshold: int = 700) -> dict[str, Any]:
    """The outcome mix the population produces under one step-up threshold.

    Section 7.3: single-channel applicants are excluded at intake and never become cases, so the
    outcome shares are over admitted applicants only.
    """
    counts = {"PASS": 0, "REFER": 0, "REJECT": 0}
    excluded = 0
    for a in data["applicants"]:
        f = a["fixture"]
        if f["channels"] < 2:
            excluded += 1
        elif not f["id_match"]:
            counts["REJECT"] += 1
        elif f["score"] < threshold:
            counts["REFER"] += 1
        else:
            counts["PASS"] += 1
    n = len(data["applicants"])
    admitted = n - excluded
    return {"applicants": n, "excluded_at_intake": excluded, "admitted": admitted, **counts,
            "excluded_pct": round(100 * excluded / n, 1),
            "straight_through_pct": round(100 * counts["PASS"] / max(admitted, 1), 1),
            "referral_pct": round(100 * counts["REFER"] / max(admitted, 1), 1)}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="casebound-generate")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--n", type=int, default=N_APPLICANTS)
    ap.add_argument("--report", action="store_true", help="print the funnel instead of writing")
    a = ap.parse_args(argv)
    data = build(a.seed, a.n)
    if a.report:
        for thr in (740, 720, 700, 640):
            print(f"threshold {thr}: {funnel(data, thr)}")
        return
    DATASET.write_text(json.dumps(data, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {DATASET} · {len(data['applicants'])} applicants · {len(data['policies'])} policy versions")
    print(f"funnel under kyc-policy@v14 (threshold 700): {funnel(data)}")


if __name__ == "__main__":
    main()
