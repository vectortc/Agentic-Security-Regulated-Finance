"""ModelClient for Gemini on Vertex AI, via the google-genai SDK and Application Default Credentials.

Authenticate once with `gcloud auth application-default login` (or a service account); pass the
GCP project, or set GOOGLE_CLOUD_PROJECT. One `ModelRequest` becomes one `generate_content`
call with structured output (`response_json_schema` = the request's JSON Schema).

Residency: Vertex serves the call from `location`. "global" lets Google route it anywhere; a
regional location (e.g. "us-central1", "europe-west4") is the data-residency control of
Section 3.5 at the provider, and it is recorded on every INFERENCE event. Newer Gemini models may
be available only on "global" or only in preview; list what your project can use with
`casebound-demo --model gemini --list-models`.
"""
from __future__ import annotations

import json
import os
from typing import Any

from casebound import ModelOutputError, ModelRequest, ModelResponse

#: A generally-available model ID. Pass another with `model=` (e.g. a newer preview model).
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

_DECLINED = {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "RECITATION", "IMAGE_SAFETY"}


def vertex_genai_client(project: str | None = None, location: str = "global") -> Any:
    from google import genai               # optional dependency: pip install "casebound-models[vertex]"
    project = project or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise ValueError("Gemini on Vertex needs a GCP project: pass project= or set GOOGLE_CLOUD_PROJECT")
    return genai.Client(vertexai=True, project=project, location=location)


class GeminiModelClient:
    """Gemini behind the `casebound.ModelClient` port.

    A blocked prompt, a safety-type finish reason (SAFETY, SPII, ...), truncation or unparsable
    JSON raises `ModelOutputError`, which Algorithm 1 routes to human review.
    """

    provider = "google-vertex"

    def __init__(self, model: str = DEFAULT_GEMINI_MODEL, *, project: str | None = None, location: str = "global",
                 max_output_tokens: int = 16000, client: Any | None = None) -> None:
        self.model, self.location, self.max_output_tokens = model, location, max_output_tokens
        self._client = client if client is not None else vertex_genai_client(project, location)

    def complete(self, request: ModelRequest) -> ModelResponse:
        from google.genai import types
        config = types.GenerateContentConfig(
            system_instruction=request.instructions,
            response_mime_type="application/json",
            response_json_schema=request.output_schema,
            max_output_tokens=self.max_output_tokens,
            # No SDK-side function calling: tools run only through Algorithm 2's gate, never
            # because a model response asked the client library to call something.
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        resp = self._client.models.generate_content(
            model=self.model,
            # sort_keys keeps identical cases byte-identical (reproducible payload digests)
            contents=json.dumps(request.payload, sort_keys=True, default=str),
            config=config,
        )
        feedback = getattr(resp, "prompt_feedback", None)
        if feedback is not None and getattr(feedback, "block_reason", None):
            raise ModelOutputError(f"{request.purpose} prompt blocked ({_name(feedback.block_reason)})")
        candidates = getattr(resp, "candidates", None) or []
        if not candidates:
            raise ModelOutputError(f"{request.purpose} response has no candidates")
        reason = _name(getattr(candidates[0], "finish_reason", None))
        if reason in _DECLINED:
            raise ModelOutputError(f"model declined the {request.purpose} request (finish reason {reason})")
        if reason == "MAX_TOKENS":
            raise ModelOutputError(f"{request.purpose} output truncated at max_output_tokens={self.max_output_tokens}")
        try:
            output = json.loads(resp.text or "")
        except json.JSONDecodeError as e:
            raise ModelOutputError(f"{request.purpose} output is not valid JSON: {e}") from e
        if not isinstance(output, dict):
            raise ModelOutputError(f"{request.purpose} output is not a JSON object")

        um = getattr(resp, "usage_metadata", None)
        usage = {"input_tokens": getattr(um, "prompt_token_count", None),
                 "output_tokens": getattr(um, "candidates_token_count", None),
                 "thoughts_tokens": getattr(um, "thoughts_token_count", None),
                 "location": self.location}
        return ModelResponse(output=output, provider=self.provider, requested_model=self.model,
                             served_model=getattr(resp, "model_version", None) or self.model,
                             request_id=getattr(resp, "response_id", None),
                             params={"max_output_tokens": self.max_output_tokens, "location": self.location},
                             usage=usage)


def _name(v: Any) -> str | None:
    return None if v is None else getattr(v, "name", str(v))
