"""Tests for Phase 2: find_errors tool."""

import json
import pytest

from log_detective.tools import find_errors
from log_detective.validators import MAX_LOG_SIZE_BYTES


def test_find_errors_plaintext():
    sample = """2026-10-20T00:01:00Z [INFO] System initialized
2026-10-20T00:01:05Z [WARN] Memory consumption at 75%
2026-10-20T00:01:10Z [ERROR] Database connection lost
2026-10-20T00:01:12Z [INFO] Attempting reconnect
2026-10-20T00:01:15Z [CRITICAL] Panic: out of memory
"""
    result = find_errors(sample, severity="ERROR")
    assert result["total_lines"] == 5
    # Default ERROR includes ERROR and CRITICAL
    assert result["matching_count"] == 2
    assert result["returned_count"] == 2
    assert result["errors"][0]["line"] == 3
    assert "Database connection lost" in result["errors"][0]["message"]
    assert result["errors"][1]["line"] == 5
    assert "Panic: out of memory" in result["errors"][1]["message"]


def test_find_errors_json_lines():
    sample = "\n".join([
        json.dumps({"timestamp": "2026-10-20T00:01:00Z", "level": "info", "message": "Starting worker"}),
        json.dumps({"timestamp": "2026-10-20T00:01:02Z", "level": "warn", "message": "Queue depth high"}),
        json.dumps({"timestamp": "2026-10-20T00:01:05Z", "level": "error", "message": "Worker crashed", "error": "NullPointer"}),
        json.dumps({"timestamp": "2026-10-20T00:01:06Z", "status": 500, "message": "HTTP 500 internal server error"}),
    ])
    result = find_errors(sample, severity="ERROR")
    assert result["matching_count"] == 2
    assert result["errors"][0]["line"] == 3
    assert result["errors"][0]["is_json"] is True
    assert result["errors"][1]["line"] == 4


def test_find_errors_with_stack_traces():
    sample = """2026-10-20T01:15:21Z [ERROR] PaymentGateway: Failed to authorize transaction
    at com.store.payment.StripeClient.executeRequest(StripeClient.java:142)
    at com.store.payment.StripeClient.authorize(StripeClient.java:88)
2026-10-20T01:15:22Z [INFO] Cleanup complete
"""
    result = find_errors(sample, severity="ERROR")
    assert result["matching_count"] == 1
    assert result["errors"][0]["line"] == 1
    assert "stack_trace" in result["errors"][0]
    assert len(result["errors"][0]["stack_trace"]) == 2


def test_find_errors_severity_filter():
    sample = """[DEBUG] Starting up
[INFO] Ready
[WARN] Deprecated API called
[ERROR] Failed to save
[CRITICAL] Server on fire
"""
    warn_result = find_errors(sample, severity="WARN")
    assert warn_result["matching_count"] == 1
    assert warn_result["errors"][0]["line"] == 3

    all_result = find_errors(sample, severity="ALL")
    assert all_result["matching_count"] == 5


def test_find_errors_limit_and_truncation():
    lines = [f"[ERROR] Error occurrence {i}" for i in range(10)]
    sample = "\n".join(lines)
    result = find_errors(sample, severity="ERROR", limit=3)
    assert result["matching_count"] == 10
    assert result["returned_count"] == 3
    assert result["truncated"] is True


def test_find_errors_empty_input():
    result = find_errors("", severity="ERROR")
    assert result["total_lines"] == 0
    assert result["matching_count"] == 0
    assert result["errors"] == []


def test_find_errors_mixed_casing():
    sample = "2026-10-20 [error] lowercase error\n2026-10-20 [ErRoR] mixed case error\n"
    result = find_errors(sample, severity="error")
    assert result["matching_count"] == 2


def test_find_errors_malformed_json():
    # Should safely treat malformed JSON as plain-text rather than crashing
    sample = '{"level": "error", "unclosed": \n2026-10-20 [ERROR] Normal line\n'
    result = find_errors(sample, severity="ERROR")
    # Even if line 1 fails json parse, it has 'error' in plain text so it gets classified safely
    assert result["matching_count"] >= 1


def test_find_errors_oversized_input():
    # Simulate oversized input exceeding MAX_LOG_SIZE_BYTES
    oversized = "a" * (MAX_LOG_SIZE_BYTES + 10)
    with pytest.raises(ValueError) as exc:
        find_errors(oversized)
    assert "exceeds maximum allowed size" in str(exc.value)
