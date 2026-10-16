"""Google Vertex AI clients (Application Default Credentials) against fake SDK objects:
Gemini via google-genai, and Claude via AnthropicVertex."""
import json
import os
from types import SimpleNamespace as NS

import pytest

from casebound import ModelOutputError, ModelRequest
from casebound_models import AnthropicModelClient, GeminiModelClient

REQ = ModelRequest("plan", "You plan.", {"b": [1], "a": "x"},
                   {"type": "object", "properties": {"steps": {"type": "array", "items": {"type": "string"}}},
                    "required": ["steps"], "additionalProperties": False})


def _resp(text='{"steps": ["doc_verify"]}', finish="STOP", block=None, model_version="gemini-2.5-pro-001"):
    return NS(text=text, model_version=model_version, response_id="resp_9",
              prompt_feedback=NS(block_reason=block) if block else None,
              candidates=[NS(finish_reason=NS(name=finish))],
              usage_metadata=NS(prompt_token_count=200, candidates_token_count=12, thoughts_token_count=30))


class FakeGenAI:
    def __init__(self, resp):
        self.calls = []
        self.models = NS(generate_content=lambda **kw: (self.calls.append(kw), resp)[1])


def test_gemini_builds_one_structured_output_call():
    sdk = FakeGenAI(_resp())
    GeminiModelClient(client=sdk, location="us-central1").complete(REQ)
    kw = sdk.calls[0]
    assert kw["model"] == "gemini-2.5-pro"
    assert kw["contents"] == json.dumps(REQ.payload, sort_keys=True)
    cfg = kw["config"]
    assert cfg.system_instruction == "You plan." and cfg.response_mime_type == "application/json"
    assert cfg.response_json_schema == REQ.output_schema
    assert cfg.automatic_function_calling.disable is True      # tools run only through the gate


def test_gemini_reports_who_served_it_and_where():
    r = GeminiModelClient(client=FakeGenAI(_resp()), location="europe-west4").complete(REQ)
    assert r.output == {"steps": ["doc_verify"]} and r.provider == "google-vertex"
    assert r.requested_model == "gemini-2.5-pro" and r.served_model == "gemini-2.5-pro-001"
    assert r.request_id == "resp_9" and r.usage["location"] == "europe-west4" and r.params["location"] == "europe-west4"
    assert (r.usage["input_tokens"], r.usage["output_tokens"], r.usage["thoughts_tokens"]) == (200, 12, 30)


@pytest.mark.parametrize("resp, why", [
    (_resp(block=NS(name="SAFETY")), "prompt blocked"),
    (_resp(finish="SPII"), "declined"),
    (_resp(finish="SAFETY"), "declined"),
    (_resp(finish="MAX_TOKENS"), "truncated"),
    (_resp(text="nope"), "not valid JSON"),
    (NS(text="", prompt_feedback=None, candidates=[], usage_metadata=None), "no candidates"),
])
def test_gemini_unusable_replies_raise_model_output_error(resp, why):
    with pytest.raises(ModelOutputError, match=why):
        GeminiModelClient(client=FakeGenAI(resp)).complete(REQ)


def test_gemini_needs_a_project(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with pytest.raises(ValueError, match="GOOGLE_CLOUD_PROJECT"):
        GeminiModelClient()


def test_claude_on_vertex_uses_adc_and_turns_off_what_vertex_lacks(monkeypatch):
    import anthropic
    made = {}

    class FakeVertex:
        def __init__(self, project_id, region):
            made.update(project_id=project_id, region=region)
            msg = NS(id="msg_v", _request_id="req_v", model="claude-opus-5", stop_reason="end_turn", stop_details=None,
                     content=[NS(type="text", text='{"steps": []}')],
                     usage=NS(input_tokens=5, output_tokens=2, cache_read_input_tokens=0, inference_geo=None))
            self.calls = []
            self.messages = NS(create=lambda **kw: (self.calls.append(kw), msg)[1])

    monkeypatch.setattr(anthropic, "AnthropicVertex", FakeVertex)
    c = AnthropicModelClient.on_vertex("my-proj", "us-east5")
    r = c.complete(REQ)
    assert made == {"project_id": "my-proj", "region": "us-east5"}
    kw = c._client.calls[0]
    assert "fallbacks" not in kw and "inference_geo" not in kw and kw["model"] == "claude-opus-5"
    assert r.provider == "anthropic-vertex" and r.usage["location"] == "us-east5" and r.params["fallbacks"] is None


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CASEBOUND_LIVE_VERTEX_TESTS") != "1",
                    reason="set CASEBOUND_LIVE_VERTEX_TESTS=1 and GOOGLE_CLOUD_PROJECT (after gcloud ADC login)")
def test_live_kyc_case_through_gemini_on_vertex():
    from casebound import EventType
    from demo.kyc.run import run_scenario
    outcome, v, _, ledger = run_scenario("happy", return_ledger=True,
                                         model_client=GeminiModelClient(location=os.environ.get("GCP_LOCATION", "global")))
    inf = [e for e in ledger.fetch_by_case(outcome.case_id) if e.type == EventType.INFERENCE]
    assert inf and all(e.data["provider"] == "google-vertex" and e.data["model"] for e in inf)
    assert outcome.outcome in {"PASS", "REFER", "REJECT", "HUMAN_REVIEW"}
