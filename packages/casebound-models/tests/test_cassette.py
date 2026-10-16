"""Record once, replay exactly; a changed request never reuses an old answer."""
import pytest

from casebound import EventType, ModelRequest, ModelResponse
from casebound_models import RecordingClient, ReplayClient


class Echo:
    def __init__(self):
        self.n = 0

    def complete(self, request):
        self.n += 1
        steps = request.payload["policy"]["body"].get("required_checks", []) if request.purpose == "plan" else None
        out = {"steps": steps, "rationale": "r"} if request.purpose == "plan" else \
            {"decision": "REFER", "factors": ["score_below_stepup_threshold"]}
        return ModelResponse(out, "echo", "echo-1", "echo-1", f"req_{self.n}", {}, {"input_tokens": 1})


def test_a_recorded_run_replays_to_the_same_chain(tmp_path):
    from demo.kyc.run import run_scenario
    cassette = tmp_path / "run.jsonl"
    o1, v1, _, l1 = run_scenario("happy", return_ledger=True, model_client=RecordingClient(Echo(), cassette))
    o2, v2, _, l2 = run_scenario("happy", return_ledger=True, model_client=ReplayClient(cassette))
    assert (o1.outcome, v1.status) == (o2.outcome, v2.status)
    # Payload digests differ between the runs, correctly: each case salts its own redaction tokens.
    # What the model answered, and which recorded call answered it, must be identical.
    inf = lambda L, c: [(e.data["output_digest"], e.data["request_id"])
                        for e in L.fetch_by_case(c) if e.type == EventType.INFERENCE]
    assert inf(l1, o1.case_id) == inf(l2, o2.case_id)


def test_replay_refuses_a_request_it_has_not_seen(tmp_path):
    cassette = tmp_path / "one.jsonl"
    req = ModelRequest("plan", "i", {"policy": {"body": {}}}, {})
    RecordingClient(Echo(), cassette).complete(req)
    ReplayClient(cassette).complete(req)
    with pytest.raises(LookupError, match="changed since the cassette was recorded"):
        ReplayClient(cassette).complete(ModelRequest("plan", "i (edited)", {"policy": {"body": {}}}, {}))


def test_a_real_gemini_recording_still_replays_to_a_complete_case():
    """tests/cassettes/gemini-2.5-pro-happy.jsonl is a real Gemini 2.5 Pro run on Vertex AI
    (re-recorded 15 Oct 2026 for the three-tool pipeline, synthetic applicant). If a change to the prompts, schemas or payload shape stops
    it from replaying, this fails, which is the signal to re-record against the live model."""
    from pathlib import Path

    from demo.kyc.run import run_scenario
    cassette = Path(__file__).with_name("cassettes") / "gemini-2.5-pro-happy.jsonl"
    outcome, v, _, ledger = run_scenario("happy", return_ledger=True, model_client=ReplayClient(cassette))
    assert (outcome.outcome, v.status) == ("REFER", "COMPLETE")
    inf = [e for e in ledger.fetch_by_case(outcome.case_id) if e.type == EventType.INFERENCE]
    assert {e.data["model"] for e in inf} == {"gemini-2.5-pro"} and all(e.data["provider"] == "google-vertex" for e in inf)
