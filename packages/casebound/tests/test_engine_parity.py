"""The browser engine and the Python core must agree.

demo.html carries a second implementation of Algorithms 1-5 so the prototype runs from a single
file with no server. A second implementation is a liability the moment it drifts -- v0.1's had
already put the plan-coverage check on line 3 instead of line 8, and had dropped C4 from line 9.
This test removes the liability: it runs demo/engine.js and demo/harness.js in Node against the
same generated dataset, over the same fault matrix, and fails if any verdict, invariant vector or
failing check number disagrees with src/casebound.

Skipped, not failed, when Node is unavailable, so the Python suite still runs anywhere.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from demo.kyc.data import ROLES
from demo.kyc.run import run_scenario

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

#: Python scenario name -> (JS fault flags, effective-dating fix)
MATRIX = {
    "happy": ({}, False),
    "stale-policy": ({"stale": True}, False),
    "stale-policy-fixed": ({"stale": True}, True),
    "bypass": ({"bypass": True}, False),
    "pii-leak": ({"pii": True}, False),
    "pii-in-field": ({"piiField": True}, False),
    "over-privileged": ({"overpriv": True}, False),
    "entitlement-revoked": ({"revoke": True}, False),
    "crash": ({"crash": True}, False),
    "tampered-ledger": ({"tamper": True}, False),
    "injection": ({"inject": True}, False),
    "zero-tool": ({"zero": True}, False),
}

DRIVER = r"""
const path = require('path');
const CB = require(path.join(process.argv[2], 'demo/engine.js'));
const KYC = require(path.join(process.argv[2], 'demo/harness.js'));
const DATA = JSON.parse(require('fs').readFileSync(path.join(process.argv[2], 'demo/kyc/dataset.json'), 'utf8'));
const jobs = JSON.parse(process.argv[3]);
const out = {};
for (const job of jobs) {
  const ref = { current: CB.makeAuthorizer(KYC.ALLOWED) };
  const store = KYC.buildStore(DATA, !!job.faults.stale);
  const L = new CB.Ledger(DATA.meta.today + 'T14:00:00Z', 0);
  const applicant = DATA.applicants.find(a => a.id === job.applicant);
  const r = KYC.runCase({
    ledger: L, data: DATA, applicant, faults: job.faults, fix: job.fix,
    paperLiteral: job.paperLiteral, authorizerRef: ref, store,
  });
  const v = CB.reconstruct(L, r.case_id, ref.current, store, KYC.makeComparator(DATA),
                           { paperLiteral: job.paperLiteral });
  out[job.key] = {
    outcome: r.outcome, status: v.status, invariants: v.invariants,
    failing_lines: v.checks.filter(c => !c.passed).map(c => c.line),
    divergent: !!v.divergence,
    finding_kinds: v.findings.map(f => f.kind).sort(),
    untagged: L.untagged().length,
  };
}
console.log(JSON.stringify(out));
"""


def _run_js(jobs: list[dict]) -> dict:
    driver = ROOT / "tests" / "_parity_driver.js"
    driver.write_text(DRIVER, encoding="utf-8")
    try:
        proc = subprocess.run([NODE, str(driver), str(ROOT), json.dumps(jobs)],
                              capture_output=True, text=True, timeout=120)
    finally:
        driver.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise AssertionError(f"node driver failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_browser_engine_matches_the_python_core():
    applicant = ROLES["borderline"]
    jobs, expected = [], {}
    for scenario, (faults, fix) in MATRIX.items():
        for literal in (False, True):
            key = f"{scenario}|{int(literal)}"
            jobs.append({"key": key, "applicant": applicant, "faults": faults,
                         "fix": fix, "paperLiteral": literal})
            outcome, v, _ = run_scenario(scenario, applicant, paper_literal=literal)
            expected[key] = {
                "outcome": outcome.outcome if outcome else "CRASHED",
                "status": v.status,
                "invariants": v.invariants,
                "failing_lines": [c.line for c in v.checks if not c.passed],
                "divergent": bool(v.divergence),
            }

    got = _run_js(jobs)
    mismatches = []
    for key, want in expected.items():
        have = got[key]
        for attr in ("outcome", "status", "invariants", "failing_lines", "divergent"):
            if have[attr] != want[attr]:
                mismatches.append(f"{key}.{attr}: python={want[attr]!r} js={have[attr]!r}")
    assert not mismatches, "browser engine has drifted from the Python core:\n  " + "\n  ".join(mismatches)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_bypass_leaves_an_untagged_record_in_both_engines():
    got = _run_js([{"key": "bypass", "applicant": ROLES["borderline"], "faults": {"bypass": True},
                    "fix": False, "paperLiteral": False}])
    assert got["bypass"]["untagged"] == 1
    assert "plan_step_unevidenced" not in got["bypass"]["finding_kinds"]   # extended mode catches it in the status
