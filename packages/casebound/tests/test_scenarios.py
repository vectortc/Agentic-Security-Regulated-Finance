"""Every scenario in the matrix must produce the status the paper predicts, in both readings."""
import pytest

from casebound import COMPLETE, InMemoryLedger, SQLiteLedger
from demo.kyc.data import POPULATION, ExcludedAtIntake, admitted
from demo.kyc.run import batch, run_scenario
from demo.kyc.scenarios import SCENARIOS


@pytest.mark.parametrize("scenario", list(SCENARIOS))
@pytest.mark.parametrize("ledger_cls", [InMemoryLedger, SQLiteLedger])
@pytest.mark.parametrize("paper_literal", [False, True], ids=["extended", "paper-literal"])
def test_scenario_status(scenario, ledger_cls, paper_literal):
    outcome, v, expected = run_scenario(scenario, "borderline", ledger_cls(), paper_literal=paper_literal)
    if expected == "EXCEPTION":
        assert outcome.outcome == "HUMAN_REVIEW" and "Error" in outcome.reason
        assert v.status != COMPLETE
    else:
        assert v.status == expected, [c for c in v.checks if not c.passed]
    # Theorem 1 on every scenario, in whichever reading is active: COMPLETE <=> all invariants hold
    assert (v.status == COMPLETE) == all(v.invariants.values())


def test_injection_is_detected_not_prevented():
    outcome, v, _ = run_scenario("injection", "borderline")
    assert v.status == COMPLETE and outcome.outcome == "PASS"
    assert v.divergence and v.divergence["policy_grounded"]["decision"] == "REFER"


def test_bypass_leaves_untagged_event():
    ledger = InMemoryLedger()
    run_scenario("bypass", "borderline", ledger)
    assert len(ledger.untagged()) == 1


def test_stale_fix_routes_before_any_tool_runs():
    ledger = InMemoryLedger()
    outcome, v, _ = run_scenario("stale-policy-fixed", "borderline", ledger)
    assert outcome.outcome == "HUMAN_REVIEW" and not v.tools


def test_audit_cost_is_case_indexed():
    ledger = SQLiteLedger()
    cases = [a for a in POPULATION if admitted(a)][:50]
    for a in cases:
        run_scenario("happy", a["id"], ledger)
    outcome, v, _ = run_scenario("happy", cases[0]["id"], ledger)
    assert ledger.count() > 500
    assert len(v.events) < 20                       # O(E_case), independent of E_total


def test_single_channel_applicants_are_excluded_at_intake_and_never_become_cases():
    """Section 7.3: applicants with one contact channel are filtered out at intake and never enter
    the pipeline. Every admitted applicant becomes a case, and the gate certifies all of them on the
    honest path. The outcome shares themselves are illustrative and deliberately not asserted."""
    r = batch(140)
    excluded = [a for a in POPULATION[:140] if not admitted(a)]
    assert excluded and r["excluded_at_intake"] == len(excluded)
    assert r["n"] == 140 - len(excluded) == sum(r["outcomes"].values())
    assert r["verdicts"] == {COMPLETE: r["n"]}
    ledger = InMemoryLedger()
    with pytest.raises(ExcludedAtIntake):
        run_scenario("happy", excluded[0]["id"], ledger)
    assert ledger.count() == 0                      # no case was opened
