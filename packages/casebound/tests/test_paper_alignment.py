"""Tests that pin the implementation to the manuscript's text, including both settings of the
two switchable readings.

Each test names the manuscript clause it encodes, so a change to the paper has one obvious
place to land in the code.
"""
import pytest

from casebound import (COMPLETE, FAILED, INCOMPLETE, EventType, GatedModelAdapter, InMemoryLedger,
                       record_review_decision, scan_payload_pii)
from demo.kyc.run import run_scenario


# --- Algorithm 5, line 6: Some_Inference_Payload_Unredacted --------------------------------
def test_line6_fails_when_redaction_ran_but_the_payload_still_leaked():
    """SPE line 6: `if Inference_Used and (not chain.has_redaction or
    Some_Inference_Payload_Unredacted) then return FAILED`.

    v0.1 checked only the first leg, so this chain -- which has a REDACTION_COMPLETED event and a
    valid redaction reference on every inference -- passed the gate.
    """
    _, v, _ = run_scenario("pii-in-field", "borderline")
    inferences = [e for e in v.events if e.type == EventType.INFERENCE]
    assert inferences and all(e.data["redaction_ev"] for e in inferences), "first leg must be satisfied"
    assert any(e.data["payload_pii"] for e in inferences), "second leg must be what fails"
    assert v.status == FAILED and v.invariants["C4"] is False
    line6 = next(c for c in v.checks if c.line == 6)
    assert not line6.passed and "still carried PII" in line6.note


def test_line6_first_leg_still_fires_when_redaction_is_skipped_entirely():
    _, v, _ = run_scenario("pii-leak", "borderline")
    assert v.status == FAILED and v.invariants["C4"] is False


def test_scan_payload_pii_is_the_audit_grade_detector():
    assert scan_payload_pii({"employer_name": "Acme, contact hr@example.test"}) == ["employer_name"]
    assert scan_payload_pii({"employer_name": "Acme", "id": "TOK_ab12"}) == []


# --- inference-mediation: the gated model adapter is the only path to the model -------------
def test_every_model_call_emits_one_inference_event():
    """SPE Assumption A1: "every model call must traverse the redaction path of Algorithm 4 and
    emit an INFERENCE event". The adapter, not Algorithm 1, is what guarantees the pairing."""
    _, v, _ = run_scenario("happy", "clean")
    inf = [e for e in v.events if e.type == EventType.INFERENCE]
    assert [e.data["purpose"] for e in inf] == ["plan", "decide"]
    assert all(e.data["redaction_ev"] and e.data["payload_digest"] for e in inf)


def test_adapter_records_the_payload_it_actually_sent():
    ledger = InMemoryLedger()
    ledger.append("c-1", EventType.CASE_OPENED, {})

    class Planner:
        def plan(self, workflow, policy, redacted):
            from casebound import Plan
            return Plan(())

    adapter = GatedModelAdapter(ledger, Planner(), None, model_id="unit-test")
    adapter.plan("c-1", "w", None, {"ssn": "900-12-3456", "product": "x"}, None)
    inf = ledger.fetch_by_case("c-1")[-1]
    assert inf.data["payload_pii"] == ["ssn"]
    assert inf.data["payload_fields"] == ["product", "ssn"]
    assert inf.data["model"] == "unit-test"


# --- the two switchable readings (casebound.reconstruct module docstring) -------------------
def test_paper_literal_mode_reproduces_the_manuscripts_own_bypass_outcome():
    """SPE A1: under a gate bypass "the ledger does not observe it, Lemma 1 fails, and Algorithm 5
    may return COMPLETE for a case whose true execution violates an invariant." Read literally,
    that is what happens -- and it is why the plan-commitment clause exists."""
    _, literal, _ = run_scenario("bypass", "borderline", paper_literal=True)
    _, extended, _ = run_scenario("bypass", "borderline", paper_literal=False)
    assert literal.status == COMPLETE and extended.status == INCOMPLETE
    assert any(f["kind"] == "plan_step_unevidenced" for f in literal.findings), \
        "the literal reading must still surface the bypass as a finding, even though the status is COMPLETE"


def test_line9_status_is_switchable():
    """The manuscript's line 9 returns INCOMPLETE; its status-semantics paragraph calls a violated
    invariant FAILED. The code follows the paragraph and the flag restores the pseudocode."""
    _, default, _ = run_scenario("stale-policy", "borderline")
    _, literal, _ = run_scenario("stale-policy", "borderline", paper_literal=True)
    assert default.status == FAILED and literal.status == INCOMPLETE
    assert default.invariants["C3"] is False and literal.invariants["C3"] is False


# --- extensions beyond the paper -------------------------------------------------------------
def test_entitlement_drift_is_reported_not_hidden():
    """Eq. (2) has no time index, so drift is reported as a finding."""
    _, v, _ = run_scenario("entitlement-revoked", "borderline")
    drift = [f for f in v.findings if f["kind"] == "entitlement_drift"]
    assert drift and drift[0]["severity"] == "warn"
    assert drift[0]["recorded"] != [drift[0]["current"]]


def test_retry_is_distinguishable_from_a_duplicate_invocation():
    """Traversability is defined over idempotency keys, so attempt 2
    completing does not silently satisfy attempt 1's unmatched invocation."""
    _, v, _ = run_scenario("happy", "clean")
    invoked = [e for e in v.events if e.type == EventType.TOOL_INVOKED]
    completed = [e for e in v.events if e.type == EventType.TOOL_COMPLETED]
    assert all(e.data["attempt"] == 1 and e.data["idempotency_key"] for e in invoked)
    assert {e.data["idempotency_key"] for e in invoked} == {e.data["idempotency_key"] for e in completed}


def test_human_review_closure_is_recorded_without_making_the_case_complete():
    """A reviewer's disposition is evidence, not absolution: it joins the
    chain but does not retroactively satisfy an invariant the execution violated."""
    from casebound import reconstruct
    from demo.kyc.scenarios import build
    from casebound.workflow import execute_regulated_workflow

    s = build("zero-tool", "borderline")
    outcome = execute_regulated_workflow(s.ctx, s.request)
    record_review_decision(s.ctx.ledger, outcome.case_id, "reviewer:ana", "APPROVED_AFTER_REVIEW",
                           "manual document check passed")
    v = reconstruct(s.ctx.ledger, outcome.case_id, s.ctx.authorizer, s.store)
    assert v.status == INCOMPLETE
    assert v.review is not None and v.review.data["reviewer"] == "reviewer:ana"
    assert any(f["kind"] == "human_review_closed" for f in v.findings)
    assert v.review.case_id == outcome.case_id and v.review.verify()


def test_tampering_breaks_the_chain():
    """Assumption A5. The ledger being append-only is assumed, not established, by the paper."""
    _, v, _ = run_scenario("tampered-ledger", "borderline")
    assert v.status == FAILED and v.invariants["C1"] is False
    assert "hash mismatch" in next(c for c in v.checks if c.line == 3).note


@pytest.mark.parametrize("scenario", ["happy", "injection"])
def test_response_digests_are_always_recorded(scenario):
    """The response payload is a storage decision, the digest is not."""
    _, v, _ = run_scenario(scenario, "clean")
    assert all(t.data["response_digest"] for t in v.tools)
