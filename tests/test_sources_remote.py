"""Tests for RemoteApiLogSource, SSRF prevention, and headers."""

from unittest.mock import MagicMock
import httpx
import pytest

from log_detective.sources.remote import RemoteApiLogSource


def test_remote_source_ssrf_prevention():
    # Attempting to query an unauthorized domain should be rejected immediately
    source = RemoteApiLogSource(
        source_id="remote-bad",
        name="Bad Host",
        endpoint_url="http://169.254.169.254/latest/meta-data/",  # AWS metadata SSRF attempt
        allowed_domains=["internal.mycompany.com"],
    )

    with pytest.raises(PermissionError) as exc:
        source.read_logs()
    assert "not in the permitted domain allowlist" in str(exc.value)


def test_remote_source_successful_read():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = (
        "2026-10-20T01:00:00Z [INFO] API Gateway route /pay matched\n"
        "2026-10-20T01:00:02Z [ERROR] Upstream payment service returned 502\n"
    )

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    source = RemoteApiLogSource(
        source_id="remote-good",
        name="Good Host",
        endpoint_url="https://logs.internal.mycompany.com/query",
        allowed_domains=["internal.mycompany.com"],
        auth_token="secret-token-123",
        http_client=mock_client,
    )

    res = source.read_logs()
    assert res.lines_returned == 2
    assert "Upstream payment service returned 502" in res.raw_text

    # Verify authorization header was injected
    call_kwargs = mock_client.get.call_args[1]
    assert call_kwargs["headers"]["Authorization"] == "Bearer secret-token-123"


def test_remote_source_http_error():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.side_effect = httpx.HTTPStatusError("Server error", request=MagicMock(), response=mock_response)

    source = RemoteApiLogSource(
        source_id="remote-err",
        name="Err Host",
        endpoint_url="https://logs.internal.mycompany.com/query",
        allowed_domains=["internal.mycompany.com"],
        http_client=mock_client,
    )

    with pytest.raises(RuntimeError) as exc:
        source.read_logs()
    assert "Remote log API error 500" in str(exc.value)
