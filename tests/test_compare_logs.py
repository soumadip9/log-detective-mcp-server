"""Tests for Phase 4: compare_logs tool."""

import pytest
from log_detective.tools import compare_logs


def test_compare_logs_detects_added_and_missing_events():
    baseline = """2026-10-20T01:00:00Z [INFO] Service started req_111
2026-10-20T01:00:01Z [INFO] Processing item user 1111-2222-3333-4444
2026-10-20T01:00:02Z [INFO] Success confirmation sent
"""
    failing = """2026-10-20T01:05:00Z [INFO] Service started req_999
2026-10-20T01:05:01Z [INFO] Processing item user 5555-6666-7777-8888
2026-10-20T01:05:05Z [ERROR] Timeout contacting database 0x7ffd1234
"""
    result = compare_logs(baseline, failing)

    # Added events should capture the new ERROR
    assert len(result["added_events"]) >= 1
    added = result["added_events"][0]
    assert added["severity"] == "ERROR"
    assert "Timeout contacting database" in added["normalized_pattern"]

    # Missing events should capture the Success confirmation that didn't occur
    assert len(result["missing_events"]) >= 1
    missing = result["missing_events"][0]
    assert "Success confirmation sent" in missing["normalized_pattern"]

    # Must contain the non-causation disclaimer
    assert "disclaimer" in result
    assert "do not independently prove direct causation" in result["disclaimer"]


def test_compare_logs_frequency_differences():
    baseline = """[INFO] Query database
[INFO] Query database
"""
    failing = """[INFO] Query database
[INFO] Query database
[INFO] Query database
[INFO] Query database
[INFO] Query database
"""
    result = compare_logs(baseline, failing)
    assert len(result["frequency_changes"]) == 1
    fc = result["frequency_changes"][0]
    assert fc["count_in_baseline"] == 2
    assert fc["count_in_failing"] == 5


def test_compare_logs_identical_runs():
    log = """2026-10-20T01:00:00Z [INFO] Normal run event 1
2026-10-20T01:00:01Z [INFO] Normal run event 2
"""
    result = compare_logs(log, log)
    assert len(result["added_events"]) == 0
    assert len(result["missing_events"]) == 0
    assert len(result["frequency_changes"]) == 0
