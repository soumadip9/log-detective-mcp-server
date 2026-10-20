"""Tests for LocalFileLogSource connector, allowlisting, and security guards."""

from pathlib import Path
import pytest

from log_detective.sources.local_file import LocalFileLogSource


@pytest.fixture
def temp_log_dir(tmp_path: Path):
    """Fixture creating an authorized logs directory and files."""
    log_dir = tmp_path / "app_logs"
    log_dir.mkdir()
    sample_file = log_dir / "service.log"
    sample_file.write_text(
        "2026-10-20T01:00:00Z [INFO] System up\n"
        "2026-10-20T01:00:05Z [WARN] Cache miss\n"
        "2026-10-20T01:00:10Z [ERROR] Database deadlock detected\n"
        "2026-10-20T01:00:15Z [INFO] Retrying query\n",
        encoding="utf-8",
    )
    return log_dir, sample_file


def test_local_file_read_success(temp_log_dir):
    log_dir, sample_file = temp_log_dir
    source = LocalFileLogSource(
        source_id="test-log",
        name="Test Service",
        file_path=sample_file,
        allowed_root=log_dir,
    )

    result = source.read_logs(limit=10)
    assert result.source_id == "test-log"
    assert result.lines_returned == 4
    assert result.total_matched == 4
    assert not result.truncated
    assert "Database deadlock detected" in result.raw_text


def test_local_file_severity_filter(temp_log_dir):
    log_dir, sample_file = temp_log_dir
    source = LocalFileLogSource(
        source_id="test-log",
        name="Test Service",
        file_path=sample_file,
        allowed_root=log_dir,
    )

    result = source.read_logs(severity="ERROR")
    assert result.lines_returned == 1
    assert result.entries[0].severity == "ERROR"
    assert "Database deadlock detected" in result.entries[0].message


def test_local_file_search_filter(temp_log_dir):
    log_dir, sample_file = temp_log_dir
    source = LocalFileLogSource(
        source_id="test-log",
        name="Test Service",
        file_path=sample_file,
        allowed_root=log_dir,
    )

    result = source.read_logs(search_term="Cache miss")
    assert result.lines_returned == 1
    assert "Cache miss" in result.raw_text


def test_local_file_limit_bounding(temp_log_dir):
    log_dir, sample_file = temp_log_dir
    source = LocalFileLogSource(
        source_id="test-log",
        name="Test Service",
        file_path=sample_file,
        allowed_root=log_dir,
    )

    result = source.read_logs(limit=2)
    assert result.lines_returned == 2
    assert result.total_matched == 4
    assert result.truncated is True


def test_path_traversal_prevention(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    secret_file = secret_dir / "passwords.txt"
    secret_file.write_text("supersecret")

    # Attempt to access ../secret/passwords.txt through allowed_dir
    traversal_path = allowed_dir / ".." / "secret" / "passwords.txt"
    source = LocalFileLogSource(
        source_id="exploit",
        name="Exploit",
        file_path=traversal_path,
        allowed_root=allowed_dir,
    )

    with pytest.raises(ValueError) as exc:
        source.read_logs()
    assert "Path traversal detected" in str(exc.value)


def test_missing_file_handling(tmp_path: Path):
    allowed_dir = tmp_path / "logs"
    allowed_dir.mkdir()
    non_existent = allowed_dir / "does_not_exist.log"

    source = LocalFileLogSource(
        source_id="missing",
        name="Missing Log",
        file_path=non_existent,
        allowed_root=allowed_dir,
    )

    with pytest.raises(FileNotFoundError):
        source.read_logs()


def test_safe_metadata_never_leaks_full_path(temp_log_dir):
    log_dir, sample_file = temp_log_dir
    source = LocalFileLogSource(
        source_id="test-log",
        name="Test Service",
        file_path=sample_file,
        allowed_root=log_dir,
    )

    meta = source.get_metadata().to_dict()
    assert meta["source_id"] == "test-log"
    assert "service.log" in meta["description"]
    # Internal full path should NOT be exposed
    assert str(log_dir) not in meta["description"]
    assert meta["is_available"] is True
