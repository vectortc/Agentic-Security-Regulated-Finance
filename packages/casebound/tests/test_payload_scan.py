"""scan_payload_pii_deep: the whole outbound payload, nested, with dotted paths (C4, Eq. 4)."""
from casebound import scan_payload_pii_deep


def test_finds_pii_anywhere_in_a_nested_payload():
    payload = {"case": {"employer_name": "Acme"},
               "tool_results": [{"tool": "doc_verify", "response": {"ok": True}},
                                {"tool": "bureau_pull", "response": {"contact": "a@example.test", "score": 700}}]}
    assert scan_payload_pii_deep(payload) == ["tool_results[1].response.contact"]


def test_a_clean_payload_has_no_hits():
    assert scan_payload_pii_deep({"policy": {"ref": "p@v1", "body": {"effective": "2026-09-01"}}, "case": {"t": "TOK_ab12cd34"}}) == []
