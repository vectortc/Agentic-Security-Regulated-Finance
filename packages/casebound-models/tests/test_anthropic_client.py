"""AnthropicModelClient against a fake SDK object: the request it builds and how it reads the reply."""
import json
import os
from types import SimpleNamespace as NS

import pytest

from casebound import ModelOutputError, ModelRequest
from casebound_models import AnthropicModelClient

REQ = ModelRequest("decide", "You decide.", {"b": 2, "a": {"z": 1, "y": "x"}},
                   {"type": "object", "properties": {"decision": {"type": "string"}}, "required": ["decision"],
                    "additionalProperties": False})


def _message(text='{"decision": "PASS"}', stop="end_turn", model="claude-opus-5", geo="us", details=None):
    return NS(id="msg_1", _request_id="req_abc", model=model, stop_reason=stop, stop_details=details,
              content=[NS(type="thinking", thinking=""), NS(type="text", text=text)],
              usage=NS(input_tokens=120, output_tokens=8, cache_read_input_tokens=0, inference_geo=geo))


class FakeSDK:
    def __init__(self, message):
        self.calls = []
        self.messages = NS(create=lambda **kw: self._record("stable", kw, message))
        self.beta = NS(messages=NS(create=lambda **kw: self._record("beta", kw, message)))

    def _record(self, path, kw, message):
        self.calls.append((path, kw))
        return message


def test_builds_one_structured_output_call_from_the_request():
    sdk = FakeSDK(_message())
    AnthropicModelClient(client=sdk, inference_geo="us", effort="high").complete(REQ)
    path, kw = sdk.calls[0]
    assert path == "beta" and kw["betas"] == ["server-side-fallback-2026-07-01"] and kw["fallbacks"] == "default"
    assert kw["model"] == "claude-opus-5" and kw["system"] == "You decide." and kw["inference_geo"] == "us"
    assert kw["output_config"] == {"format": {"type": "json_schema", "schema": REQ.output_schema}, "effort": "high"}
    assert kw["messages"] == [{"role": "user", "content": json.dumps(REQ.payload, sort_keys=True)}]


def test_without_fallbacks_uses_the_stable_endpoint():
    sdk = FakeSDK(_message())
    AnthropicModelClient(client=sdk, fallbacks=None).complete(REQ)
    path, kw = sdk.calls[0]
    assert path == "stable" and "fallbacks" not in kw and "betas" not in kw and "inference_geo" not in kw


def test_reports_who_served_the_call_and_where():
    r = AnthropicModelClient(client=FakeSDK(_message(model="claude-opus-4-8", geo="eu"))).complete(REQ)
    assert r.output == {"decision": "PASS"} and r.provider == "anthropic"
    assert r.requested_model == "claude-opus-5" and r.served_model == "claude-opus-4-8"   # a fallback is visible
    assert r.request_id == "req_abc" and r.usage["inference_geo"] == "eu" and r.usage["input_tokens"] == 120
    assert r.params["fallbacks"] == "default"


@pytest.mark.parametrize("message, why", [
    (_message(stop="refusal", details=NS(category="cyber")), "declined"),
    (_message(stop="max_tokens"), "truncated"),
    (_message(text="not json"), "not valid JSON"),
    (_message(text="[1, 2]"), "not a JSON object"),
])
def test_unusable_replies_raise_model_output_error(message, why):
    with pytest.raises(ModelOutputError, match=why):
        AnthropicModelClient(client=FakeSDK(message)).complete(REQ)


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CASEBOUND_LIVE_MODEL_TESTS") != "1", reason="set CASEBOUND_LIVE_MODEL_TESTS=1")
def test_live_kyc_case_through_claude():
    """One real case end to end. Whatever Claude decides, the chain must say who decided it."""
    from casebound import EventType
    from demo.kyc.run import run_scenario
    outcome, v, _, ledger = run_scenario("happy", return_ledger=True, model_client=AnthropicModelClient())
    inf = [e for e in ledger.fetch_by_case(outcome.case_id) if e.type == EventType.INFERENCE]
    assert inf and all(e.data["provider"] == "anthropic" and e.data["model"] for e in inf)
    assert outcome.outcome in {"PASS", "REFER", "REJECT", "HUMAN_REVIEW"}
