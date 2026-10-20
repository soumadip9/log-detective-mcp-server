"""Tests for list_log_sources, read_logs, and source-based analysis tools."""

from pathlib import Path
import pytest

from log_detective.sources.local_file import LocalFileLogSource
from log_detective.sources.registry import LogSourceRegistry
from log_detective.tools import (
    compare_logs,
    find_errors,
    get_log_context,
    list_log_sources,
    read_logs,
)


@pytest.fixture
def configured_registry(tmp_path: Path):
    reg = LogSourceRegistry()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    failing_file = log_dir / "failing.log"
    failing_file.write_text(
        "2026-10-20T01:00:00Z [INFO] Service started req_111\n"
        "2026-10-20T01:00:05Z [WARN] Retry 1/3\n"
        "2026-10-20T01:00:10Z [ERROR] Stripe payment gateway timeout\n"
        "    at com.store.Payment.charge(Payment.java:42)\n"
        "2026-10-20T01:00:15Z [ERROR] 504 Gateway Timeout returned to client\n",
        encoding="utf-8",
    )

    baseline_file = log_dir / "baseline.log"
    baseline_file.write_text(
        "2026-10-20T01:00:00Z [INFO] Service started req_999\n"
        "2026-10-20T01:00:05Z [INFO] Payment authorized txn_12345\n"
        "2026-10-20T01:00:10Z [INFO] Order confirmed\n",
        encoding="utf-8",
    )

    reg.register_source(
        LocalFileLogSource(
            source_id="failing-run",
            name="Failing Checkout",
            file_path=failing_file,
            allowed_root=log_dir,
            description="Run with timeout",
        )
    )
    reg.register_source(
        LocalFileLogSource(
            source_id="baseline-run",
            name="Healthy Checkout",
            file_path=baseline_file,
            allowed_root=log_dir,
            description="Run without error",
        )
    )
    return reg


def test_list_log_sources(configured_registry):
    res = list_log_sources(registry=configured_registry)
    assert res["count"] == 2
    source_ids = [s["source_id"] for s in res["sources"]]
    assert "failing-run" in source_ids
    assert "baseline-run" in source_ids
    # Sensitive paths are NOT in description
    for s in res["sources"]:
        assert "\\" not in s["description"]
        assert "/" not in s["description"] or ".log" in s["description"]


def test_read_logs_by_source_id(configured_registry):
    res = read_logs(source_id="failing-run", limit=10, registry=configured_registry)
    assert res["source_id"] == "failing-run"
    assert res["lines_returned"] == 4
    assert "Stripe payment gateway timeout" in res["raw_text"]


def test_find_errors_via_source_id(configured_registry):
    # Call find_errors directly using source_id without supplying log_text
    res = find_errors(source_id="failing-run", severity="ERROR", registry=configured_registry)
    assert res["source_id"] == "failing-run"
    assert res["matching_count"] == 2
    assert res["errors"][0]["line"] == 3
    assert "Stripe payment gateway timeout" in res["errors"][0]["message"]
    assert "stack_trace" in res["errors"][0]


def test_get_log_context_via_source_id(configured_registry):
    # Call get_log_context directly using source_id and line 3
    res = get_log_context(target_line=3, source_id="failing-run", context_size=2, registry=configured_registry)
    assert res["source_id"] == "failing-run"
    assert res["target_line"] == 3
    assert len(res["lines"]) == 5
    assert res["lines"][2]["is_target"] is True
    assert ">     3 | 2026-10-20T01:00:10Z [ERROR] Stripe payment gateway timeout" in res["formatted"]


def test_compare_logs_via_source_ids(configured_registry):
    # Compare baseline vs failing using source IDs directly
    res = compare_logs(
        baseline_source_id="baseline-run",
        failing_source_id="failing-run",
        registry=configured_registry,
    )
    assert len(res["added_events"]) >= 1
    assert any("Stripe payment gateway timeout" in e["normalized_pattern"] for e in res["added_events"])
    assert len(res["missing_events"]) >= 1
    assert any("Payment authorized" in e["normalized_pattern"] for e in res["missing_events"])


def test_invalid_source_id_raises_key_error(configured_registry):
    with pytest.raises(KeyError) as exc:
        read_logs(source_id="non-existent-source", registry=configured_registry)
    assert "not configured" in str(exc.value)
