"""Model clients for casebound's gated model adapter.

Kept out of the stdlib-only core: this is where provider SDKs live.

- AnthropicModelClient: Claude on the Anthropic API, or on Vertex AI via `.on_vertex()` (Google ADC)
- GeminiModelClient: Gemini on Vertex AI (Google ADC); needs the `vertex` extra
- RecordingClient / ReplayClient: record real calls to a cassette and replay them without network
"""
from .anthropic_client import DEFAULT_MODEL, AnthropicModelClient
from .cassette import RecordingClient, ReplayClient, request_key
from .gemini_client import DEFAULT_GEMINI_MODEL, GeminiModelClient, vertex_genai_client

__all__ = ["AnthropicModelClient", "DEFAULT_GEMINI_MODEL", "DEFAULT_MODEL", "GeminiModelClient",
           "RecordingClient", "ReplayClient", "request_key", "vertex_genai_client"]
