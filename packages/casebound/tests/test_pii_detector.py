"""The regex PII detector behind Algorithm 4 and Algorithm 5 line 6 (Assumption A3: oracle correctness).

A false positive is not harmless: once tool results are scanned, a date misread as a phone number
fails or blocks a clean case. Both engines share the patterns; test_engine_parity keeps them equal.
"""
import pytest

from casebound import scan_payload_pii


@pytest.mark.parametrize("value, is_pii", [
    ("synthetic-list@2026-09-01", False),      # an ISO date is not a phone number (a dated version string)
    ("effective 2026-09-01", False),
    ("+1 555-0142-3301", True),
    ("(555) 014-2233", True),
    ("call 555 014 2233", True),
    ("hr.payroll@example.test", True),
    ("900-12-3456", True),
])
def test_the_detector_does_not_mistake_dates_for_phones(value, is_pii):
    assert bool(scan_payload_pii({"f": value})) == is_pii
