"""ModelClient for Claude via the official Anthropic SDK.

Sends one `ModelRequest` as a single Messages API call with structured output
(`output_config.format` = the request's JSON Schema), and reports back what an auditor needs
on the INFERENCE event: the model that actually served the call, the request id, the
parameters, token usage, and where inference ran (`usage.inference_geo`).

Credentials resolve the SDK's usual way (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or an
`ant auth login` profile). Nothing here is called except through casebound.GatedModelAdapter.
"""
from __future__ import annotations

import json
from typing import Any

import anthropic

from casebound import ModelOutputError, ModelRequest, ModelResponse

DEFAULT_MODEL = "claude-opus-5"
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicModelClient:
    """Claude behind the `casebound.ModelClient` port.

    - `inference_geo` pins where inference runs ("us", "eu", ...). For a regulated deployment
      this is the data-residency control of Section 3.5 applied at the provider, and the
      region that actually served the call is recorded on every INFERENCE event.
    - `fallbacks="default"` lets the API re-run a refused request on a fallback model inside
      the same call. The served model is recorded, so a substitution is visible in the chain;
      pass `fallbacks=None` if your model inventory allows only the requested model.
    - A refusal, a truncated response or unparsable JSON raises `ModelOutputError`, which
      Algorithm 1 routes to human review.
    """

    def __init__(self, model: str = DEFAULT_MODEL, *, max_tokens: int = 16000, effort: str | None = None,
                 inference_geo: str | None = None, fallbacks: str | None = "default",
                 client: Any | None = None, provider: str = "anthropic", location: str | None = None) -> None:
        self.model, self.max_tokens, self.effort = model, max_tokens, effort
        self.inference_geo, self.fallbacks = inference_geo, fallbacks
        self.provider, self.location = provider, location
        self._client = client if client is not None else anthropic.Anthropic()

    @classmethod
    def on_vertex(cls, project_id: str | None = None, region: str = "global", model: str = DEFAULT_MODEL,
                  **kwargs: Any) -> "AnthropicModelClient":
        """Claude on Google Cloud Vertex AI, authenticated with Application Default Credentials.

        The model must be enabled in the project's Model Garden. Vertex does not support
        `inference_geo` or server-side `fallbacks`, so both are off; residency comes from
        `region` instead ("global", a multi-region such as "us"/"eu", or a specific region),
        and the region is recorded on every INFERENCE event.
        """
        import os
        project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project_id:
            raise ValueError("Claude on Vertex needs a GCP project: pass project_id= or set GOOGLE_CLOUD_PROJECT")
        client = anthropic.AnthropicVertex(project_id=project_id, region=region)   # pip install "anthropic[vertex]"
        return cls(model, client=client, provider="anthropic-vertex", location=region,
                   inference_geo=None, fallbacks=None, **kwargs)

    def _params(self) -> dict[str, Any]:
        return {"max_tokens": self.max_tokens, "effort": self.effort, "inference_geo": self.inference_geo,
                "fallbacks": self.fallbacks, "location": self.location}

    def complete(self, request: ModelRequest) -> ModelResponse:
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": request.output_schema}}
        if self.effort:
            output_config["effort"] = self.effort
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": request.instructions,
            # sort_keys: identical cases produce identical bytes, which keeps the payload digest
            # on the INFERENCE event reproducible and the prompt cache effective.
            "messages": [{"role": "user", "content": json.dumps(request.payload, sort_keys=True, default=str)}],
            "output_config": output_config,
        }
        if self.inference_geo:
            kwargs["inference_geo"] = self.inference_geo
        if self.fallbacks:
            message = self._client.beta.messages.create(betas=[_FALLBACK_BETA], fallbacks=self.fallbacks, **kwargs)
        else:
            message = self._client.messages.create(**kwargs)

        if message.stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            raise ModelOutputError(f"model declined the {request.purpose} request "
                                   f"(category: {getattr(details, 'category', None)})")
        if message.stop_reason == "max_tokens":
            raise ModelOutputError(f"{request.purpose} output truncated at max_tokens={self.max_tokens}")
        text = next((b.text for b in message.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise ModelOutputError(f"{request.purpose} response has no text block")
        try:
            output = json.loads(text)
        except json.JSONDecodeError as e:
            raise ModelOutputError(f"{request.purpose} output is not valid JSON: {e}") from e
        if not isinstance(output, dict):
            raise ModelOutputError(f"{request.purpose} output is not a JSON object")

        u = message.usage
        usage = {"input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
                 "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", None),
                 "inference_geo": getattr(u, "inference_geo", None), "location": self.location}
        return ModelResponse(output=output, provider=self.provider, requested_model=self.model,
                             served_model=message.model, request_id=getattr(message, "_request_id", None) or message.id,
                             params=self._params(), usage=usage)
