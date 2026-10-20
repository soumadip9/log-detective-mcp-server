"""Tests for MCP server tool registration, discovery, health, and security."""

import asyncio
import os
import pytest
from starlette.testclient import TestClient

from log_detective.server import create_app, server


def test_mcp_tool_discovery():
    """Verify that all five tools are registered and advertised by the MCP server."""
    tools = asyncio.run(server.list_tools())
    tool_names = [t.name for t in tools]

    assert "list_log_sources" in tool_names
    assert "read_logs" in tool_names
    assert "find_errors" in tool_names
    assert "get_log_context" in tool_names
    assert "compare_logs" in tool_names

    # Check that tool descriptions exist
    for t in tools:
        assert t.description and len(t.description) > 10


def test_mcp_tool_execution():
    """Verify that tools can be called directly via server.call_tool."""
    sample_log = "2026-10-20 [ERROR] Test error line"
    res = asyncio.run(server.call_tool("find_errors", {"log_text": sample_log}))
    assert not res.is_error
    assert len(res.content) > 0
    text = res.content[0].text
    assert "Test error line" in text

    # Test list_log_sources execution via MCP
    res_sources = asyncio.run(server.call_tool("list_log_sources", {}))
    assert not res_sources.is_error
    assert len(res_sources.content) > 0


def test_health_endpoint():
    """Verify that /health responds with 200 OK and valid health payload."""
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "log-detective-mcp"


def test_auth_middleware_enforcement():
    """Verify that when MCP_AUTH_TOKEN is set, unauthorized requests to /mcp are rejected with 401."""
    token = "test-secret-token-12345"
    old_env = os.environ.get("MCP_AUTH_TOKEN")
    try:
        os.environ["MCP_AUTH_TOKEN"] = token
        app = create_app()
        with TestClient(app) as client:
            # Health check remains open
            r_health = client.get("/health")
            assert r_health.status_code == 200

            # Request to /mcp without token is rejected
            r_unauth = client.post("/mcp", json={"jsonrpc": "2.0"})
            assert r_unauth.status_code == 401
            assert "Unauthorized" in r_unauth.json()["error"]

            # Request to /mcp with bad token is rejected
            r_bad = client.post(
                "/mcp",
                headers={"Authorization": "Bearer wrong-token"},
                json={"jsonrpc": "2.0"},
            )
            assert r_bad.status_code == 401

            # Request to /mcp with correct token passes through auth middleware
            r_auth = client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            # Should not be 401
            assert r_auth.status_code != 401
    finally:
        if old_env is not None:
            os.environ["MCP_AUTH_TOKEN"] = old_env
        else:
            os.environ.pop("MCP_AUTH_TOKEN", None)
