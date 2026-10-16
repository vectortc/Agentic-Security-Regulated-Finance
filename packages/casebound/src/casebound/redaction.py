"""Algorithm 4: Redact_Before_Inference (invariant C4).

Structured extraction -> PII detection -> tokenize -> strip free text -> classify boundary.
The token->identity vault never leaves the caller's process; only its keys are logged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .events import EventType, digest
from .ledger import Ledger
from .ports import BoundaryEnforcer, InferenceBoundaryError, RedactionEvidence

PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    # Not inside a longer number, and not an ISO-8601 date: tool results carry dates (list
    # versions, effective dates) and a date misread as a phone would block a clean case (A3).
    "phone": re.compile(r"(?<![\d-])(?!\d{4}-\d{2}-\d{2}(?!\d))\+?\d[\d\s().-]{8,}\d"),
}


@dataclass(frozen=True)
class ExtractionSchema:
    """Which fields the workflow needs (everything else is dropped) and which are PII by name."""
    fields: tuple[str, ...]
    pii_fields: tuple[str, ...]
    free_text_fields: tuple[str, ...] = ()


def detect_pii(fields: dict[str, Any], schema: ExtractionSchema) -> list[str]:
    hits = [k for k in fields if k in schema.pii_fields]
    for k, v in fields.items():
        if k not in hits and isinstance(v, str) and any(p.search(v) for p in PII_PATTERNS.values()):
            hits.append(k)
    return hits


def scan_payload_pii(payload: dict[str, Any]) -> list[str]:
    """Field names in an outbound inference payload that still carry recognisable PII.

    This is the SPE `Some_Inference_Payload_Unredacted` oracle (Alg. 5, line 6). It runs on
    the payload the model actually receives, not on the pre-redaction record, so it catches
    PII that survived Algorithm 4 in a field the ExtractionSchema did not mark: the case the
    v0.1 "does an INFERENCE event reference a REDACTION_COMPLETED?" check passes and the SPE
    version fails. Detector quality is assumption A3 (oracle correctness); a regex detector
    is a demonstration, not a production one.
    """
    return sorted(k for k, v in payload.items()
                  if isinstance(v, str) and any(p.search(v) for p in PII_PATTERNS.values()))


def scan_payload_pii_deep(payload: Any, _path: str = "") -> list[str]:
    """`scan_payload_pii` over a whole nested request payload; returns dotted paths.

    A model-backed decider sends more than the redacted record: tool results and policy text
    ride along. C4 (Eq. 4) is a property of `payload(e)`, the whole thing the model received, so
    the gated adapter scans all of it. Paths look like `tool_results[1].response.contact`.
    """
    hits: list[str] = []
    if isinstance(payload, dict):
        for k in sorted(payload):
            hits += scan_payload_pii_deep(payload[k], f"{_path}.{k}" if _path else str(k))
    elif isinstance(payload, (list, tuple)):
        for i, v in enumerate(payload):
            hits += scan_payload_pii_deep(v, f"{_path}[{i}]")
    elif isinstance(payload, str) and any(p.search(payload) for p in PII_PATTERNS.values()):
        hits.append(_path)
    return hits


def classify_boundary(payload: dict[str, Any]) -> str:
    for v in payload.values():
        if isinstance(v, str) and any(p.search(v) for p in PII_PATTERNS.values()):
            return "raw-pii"
    return "redacted-structured"


def redact_before_inference(ledger: Ledger, case_id: str, raw_input: dict[str, Any], schema: ExtractionSchema,
                            boundary: BoundaryEnforcer,
                            classifier: Callable[[dict[str, Any]], str] | None = None,
                            detector: Callable[[dict[str, Any], "ExtractionSchema"], list[str]] | None = None,
                            ) -> tuple[dict[str, Any], RedactionEvidence, dict[str, Any]]:
    """`detector` overrides Detect_PII and `classifier` overrides Classify_Boundary.

    Both are injectable because Assumption A3 (oracle correctness) is about exactly these two
    components: "a redaction classifier false negative (C4) causes a guard to pass when it should
    fail." A deployment whose detector misses a PII category records REDACTION_COMPLETED over a
    payload that still leaks -- which the audit-time scan at Algorithm 5 line 6 catches, and the
    v0.1 "is there a redaction reference?" check did not.
    """
    fields = {k: raw_input[k] for k in schema.fields if k in raw_input}          # Structured_Extraction
    pii = (detector or detect_pii)(fields, schema)
    vault: dict[str, Any] = {}
    sanitized = dict(fields)
    for k in pii:                                                                # Redact_Or_Tokenize
        tok = "TOK_" + digest([case_id, k, fields[k]])[:8]
        vault[tok] = fields[k]
        sanitized[k] = tok
    for k in schema.free_text_fields:                                            # Remove_Free_Text
        sanitized.pop(k, None)
    bclass = (classifier or classify_boundary)(sanitized)
    if not boundary.allow(bclass):
        e = ledger.append(case_id, EventType.REDACTION_BOUNDARY_FAILED, {"boundary_class": bclass, "decision": "DENY"})
        raise InferenceBoundaryError(f"boundary class {bclass} denied (evidence {e.hash})")
    e = ledger.append(case_id, EventType.REDACTION_COMPLETED,
                      {"boundary_class": bclass, "decision": "ALLOW", "pii_fields": pii, "tokens": sorted(vault),
                       "payload_digest": digest(sanitized)})
    return sanitized, RedactionEvidence(e.hash, bclass, tuple(pii)), vault


class AllowRedactedOnly:
    def allow(self, boundary_class: str) -> bool:
        return boundary_class == "redacted-structured"
