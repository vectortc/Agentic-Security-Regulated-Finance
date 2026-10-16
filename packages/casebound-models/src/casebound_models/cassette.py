"""Record and replay model calls, so a run with a real model can be repeated exactly.

`RecordingClient` wraps any ModelClient and appends each request/response pair to a JSON-lines
cassette. `ReplayClient` serves those responses back, matched by a digest of the request, and
raises on a request it has not seen, so a changed prompt can never silently reuse an old answer.

Used for tests that must not call the network, and for evaluation runs (roadmap M8) whose
numbers have to be reproducible from the repository. Stdlib only.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from casebound import ModelClient, ModelRequest, ModelResponse, digest


_TOKEN = re.compile(r"TOK_[0-9a-f]{8}")


def request_key(request: ModelRequest) -> str:
    """Digest of the request with redaction tokens masked.

    Algorithm 4 salts each token with the case id, so the same applicant gets different, unlinkable
    tokens in every case. Tokens are opaque to the model by design, so masking them loses nothing
    the answer can depend on, and lets a rerun of the same applicant replay its recorded response.
    """
    payload = json.loads(_TOKEN.sub("TOK_*", json.dumps(request.payload, sort_keys=True, default=str)))
    return digest([request.purpose, request.instructions, payload, request.output_schema])


class RecordingClient:
    def __init__(self, inner: ModelClient, path: str | Path) -> None:
        self._inner, self._path = inner, Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def complete(self, request: ModelRequest) -> ModelResponse:
        response = self._inner.complete(request)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"key": request_key(request), "purpose": request.purpose,
                                "response": asdict(response)}, sort_keys=True) + "\n")
        return response


class ReplayClient:
    def __init__(self, path: str | Path) -> None:
        self._responses: dict[str, ModelResponse] = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                self._responses[row["key"]] = ModelResponse(**row["response"])

    def complete(self, request: ModelRequest) -> ModelResponse:
        key = request_key(request)
        if key not in self._responses:
            raise LookupError(f"no recorded response for this {request.purpose} request (key {key}); "
                              "the prompt, payload or schema changed since the cassette was recorded")
        return self._responses[key]
