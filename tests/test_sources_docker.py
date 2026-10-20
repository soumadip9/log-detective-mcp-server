"""Tests for DockerLogSource with mocking and allowlist security."""

from unittest.mock import MagicMock
import pytest

from log_detective.sources.docker import DockerLogSource


def test_docker_source_allowlist_enforcement():
    # Attempting to access non-allowlisted container raises PermissionError
    source = DockerLogSource(
        source_id="docker-test",
        name="Docker Test",
        container_name_or_id="malicious-container",
        allowlisted_containers=["web-api", "worker-queue"],
    )

    with pytest.raises(PermissionError) as exc:
        source.read_logs()
    assert "not in the permitted Docker allowlist" in str(exc.value)


def test_docker_source_successful_read():
    mock_container = MagicMock()
    mock_container.status = "running"
    mock_container.logs.return_value = (
        b"2026-10-20T01:00:00Z [INFO] Container boot complete\n"
        b"2026-10-20T01:00:05Z [ERROR] Failed to bind port 8080\n"
    )

    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container

    source = DockerLogSource(
        source_id="docker-api",
        name="API Gateway",
        container_name_or_id="api-gateway",
        allowlisted_containers=["api-gateway"],
        docker_client=mock_client,
    )

    meta = source.get_metadata()
    assert meta.is_available is True
    assert "api-gateway" in meta.description

    res = source.read_logs(severity="ERROR")
    assert res.lines_returned == 1
    assert "Failed to bind port 8080" in res.raw_text
    mock_container.logs.assert_called_once()


def test_docker_source_missing_container():
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = Exception("Container not found")

    source = DockerLogSource(
        source_id="docker-missing",
        name="Missing",
        container_name_or_id="db-container",
        allowlisted_containers=["db-container"],
        docker_client=mock_client,
    )

    with pytest.raises(FileNotFoundError):
        source.read_logs()
