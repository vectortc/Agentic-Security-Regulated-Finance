# casebound-models

Model clients for casebound's gated model adapter. The core (`packages/casebound`) is stdlib-only;
provider SDKs live here.

| Client | What it does |
|---|---|
| `AnthropicModelClient` | Claude via the official Anthropic SDK: one Messages API call per request, structured output constrained to the request's JSON Schema, optional `inference_geo` pinning, server-side refusal fallbacks (on by default; the served model is recorded). |
| `AnthropicModelClient.on_vertex()` | Claude on Google Vertex AI with Application Default Credentials. The model must be enabled in Model Garden. `inference_geo` and fallbacks are off (Vertex lacks them); the region is the residency control and is recorded. |
| `GeminiModelClient` | Gemini on Vertex AI via `google-genai` and ADC, with structured output via `response_json_schema`. Needs the `vertex` extra. |
| `RecordingClient` | Wraps any client and appends each call to a JSON-lines cassette. |
| `ReplayClient` | Serves recorded responses matched by a digest of the request; fails loudly on any request it has not seen. |

## How it fits

```
LLMPlanner / LLMDecider  --build ModelRequest-->  GatedModelAdapter  --complete()-->  ModelClient
      (casebound.llm)       <--parse response--   scans the full payload,            (this package)
                                                   records model, params, usage,
                                                   request id, inference region
```

Model-backed components never hold a client: `GatedModelAdapter` is the only caller of
`complete()`, which is what makes a deployment inference-mediated (the paper's Assumption A1).

## Use

```bash
pip install -e packages/casebound -e "packages/casebound-models[vertex]"
cd packages/casebound

# Google Vertex AI with Application Default Credentials (no Anthropic API key needed)
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=my-project
casebound-demo --model gemini --list-models                       # what this project can call
casebound-demo --model gemini --scenario happy                    # default gemini-2.5-pro, location global
casebound-demo --model gemini --model-id gemini-3.1-pro-preview --scenario happy
casebound-demo --model gemini --gcp-location us-central1 --batch 20   # regional = data residency
casebound-demo --model claude-vertex --gcp-location us-east5 --scenario happy   # Claude via Model Garden

# Anthropic API
casebound-demo --model anthropic --scenario happy                 # needs Anthropic credentials
casebound-demo --model anthropic --record runs/claude.jsonl --batch 20
casebound-demo --replay runs/claude.jsonl --batch 20              # same run, no network
```

Credentials resolve the SDK's usual way: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or an
`ant auth login` profile.

## Tests

`pytest` runs without network: the Anthropic client is tested against a fake SDK object, and the
end-to-end tests replay responses. Tests marked `live` call a real API and run only with
`CASEBOUND_LIVE_MODEL_TESTS=1` (Anthropic) or `CASEBOUND_LIVE_VERTEX_TESTS=1` plus
`GOOGLE_CLOUD_PROJECT` (Gemini on Vertex).
