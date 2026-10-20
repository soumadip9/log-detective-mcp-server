"""Tests for CapturedProcessLogSource."""

from pathlib import Path
import pytest

from log_detective.sources.process import CapturedProcessLogSource


def test_captured_process_read(tmp_path: Path):
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir()
    spool_file = spool_dir / "worker.out"
    spool_file.write_text(
        "2026-10-20T01:00:00Z [INFO] Worker started (PID 1234)\n"
        "2026-10-20T01:00:05Z [ERROR] Failed to connect to Redis queue\n",
        encoding="utf-8",
    )

    source = CapturedProcessLogSource(
        source_id="worker-proc",
        name="Worker Service",
        spool_file_path=spool_file,
        allowed_root=spool_dir,
        process_name="celery-worker",
    )

    meta = source.get_metadata()
    assert meta.is_available is True
    assert "celery-worker" in meta.description

    result = source.read_logs()
    assert result.lines_returned == 2
    assert "Failed to connect to Redis queue" in result.raw_text


def test_captured_process_missing_spool(tmp_path: Path):
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir()
    missing_file = spool_dir / "missing.out"

    source = CapturedProcessLogSource(
        source_id="worker-missing",
        name="Missing Worker",
        spool_file_path=missing_file,
        allowed_root=spool_dir,
    )

    with pytest.raises(FileNotFoundError):
        source.read_logs()
