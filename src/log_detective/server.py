"""Hosted Log Detective MCP Server with Streamable HTTP transport and authentication."""

import logging
import os
import sys
from typing import Any, Dict, Optional

from mcp.server.mcpserver import MCPServer
from mcp.server.streamable_http import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import uvicorn

from log_detective.tools import compare_logs as tool_compare_logs
from log_detective.tools import find_errors as tool_find_errors
from log_detective.tools import get_log_context as tool_get_log_context

# Configure operational logging - Never log raw log text or credentials
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("log_detective.server")

# Initialize MCP Server instance
server = MCPServer(
    name="log-detective",
    instructions=(
        "Log Detective MCP Server provides tools to investigate application logs. "
        "AI clients should retrieve the relevant log text from authorized local or remote "
        "sources and pass it to these tools to find errors, view context, or compare runs."
    ),
)


@server.custom_route("/health", methods=["GET"])
async def health_check(request: Any) -> JSONResponse:
    """Operational health check endpoint for monitoring uptime (e.g. Render)."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "log-detective-mcp",
            "version": "1.0.0",
        }
    )


@server.custom_route("/", methods=["GET"])
async def root_info(request: Any) -> JSONResponse:
    """Root info endpoint providing basic server metadata."""
    return JSONResponse(
        {
            "service": "log-detective-mcp",
            "description": "Log Detective MCP Server for application log investigation",
            "health_endpoint": "/health",
            "mcp_endpoint": "/mcp",
            "docs": "https://github.com/prasa/log-detective-mcp",
        }
    )


@server.tool(
    name="find_errors",
    description=(
        "Scan log text (plain-text or JSON lines) for error events, stack traces, and failure indicators. "
        "Returns line numbers, extracted error messages, timestamps, and stack traces. "
        "Use this first when an incident or checkout/API failure is reported to locate all error events."
    ),
)
def find_errors(
    log_text: str,
    severity: str = "ERROR",
    limit: int = 50,
) -> Dict[str, Any]:
    """Find errors within supplied log text.

    Args:
        log_text: Raw log text to inspect.
        severity: Severity level to filter by (default 'ERROR'). Options: 'ERROR', 'WARN', 'CRITICAL', 'INFO', 'ALL'.
        limit: Maximum number of matching entries to return (default 50, maximum 200).
    """
    logger.info("Executing find_errors (severity=%s, limit=%s)", severity, limit)
    try:
        return tool_find_errors(log_text=log_text, severity=severity, limit=limit)
    except (ValueError, TypeError) as exc:
        logger.warning("find_errors validation error: %s", exc)
        return {
            "error": str(exc),
            "status": "invalid_argument",
        }


@server.tool(
    name="get_log_context",
    description=(
        "Retrieve surrounding lines of context before and after a specific line number in a log. "
        "Preserves timestamps, stack traces, and highlights the target line. "
        "Use this after find_errors to inspect what occurred immediately leading up to or following a specific failure."
    ),
)
def get_log_context(
    log_text: str,
    target_line: int,
    context_size: int = 5,
) -> Dict[str, Any]:
    """Retrieve lines surrounding a target line number.

    Args:
        log_text: Raw log text.
        target_line: 1-indexed target line number.
        context_size: Number of lines before and after to include (default 5, maximum 50).
    """
    logger.info("Executing get_log_context (target_line=%s, context_size=%s)", target_line, context_size)
    try:
        return tool_get_log_context(log_text=log_text, target_line=target_line, context_size=context_size)
    except (ValueError, TypeError) as exc:
        logger.warning("get_log_context validation error: %s", exc)
        return {
            "error": str(exc),
            "status": "invalid_argument",
        }


@server.tool(
    name="compare_logs",
    description=(
        "Compare a healthy baseline log run against a failing log run to identify newly added errors, "
        "missing expected events, and frequency differences. "
        "Normalizes timestamps and dynamic IDs across runs so underlying behavior can be compared directly. "
        "Note: Highlights empirical differences without claiming direct causation."
    ),
)
def compare_logs(
    baseline_log: str,
    failing_log: str,
) -> Dict[str, Any]:
    """Compare baseline log against failing log.

    Args:
        baseline_log: Log content from a successful/normal run.
        failing_log: Log content from the failing run.
    """
    logger.info("Executing compare_logs")
    try:
        return tool_compare_logs(baseline_log=baseline_log, failing_log=failing_log)
    except (ValueError, TypeError) as exc:
        logger.warning("compare_logs validation error: %s", exc)
        return {
            "error": str(exc),
            "status": "invalid_argument",
        }


class AuthMiddleware(BaseHTTPMiddleware):
    """Bearer token authentication middleware for remote production hosting."""

    async def dispatch(self, request: Any, call_next: Any) -> Any:
        # Public health and info endpoints do not require authentication
        if request.url.path in ("/health", "/"):
            return await call_next(request)

        # Check for configured token (MCP_AUTH_TOKEN or AUTH_TOKEN)
        expected_token = os.environ.get("MCP_AUTH_TOKEN") or os.environ.get("AUTH_TOKEN")
        if expected_token:
            auth_header = request.headers.get("Authorization", "")
            expected_header = f"Bearer {expected_token}"
            if auth_header != expected_header:
                logger.warning("Rejected unauthorized request to %s", request.url.path)
                return JSONResponse(
                    {
                        "error": "Unauthorized: missing or invalid Bearer token in Authorization header",
                        "status": "unauthorized",
                    },
                    status_code=401,
                )

        return await call_next(request)


def create_app() -> Any:
    """Create and configure the Starlette application with Streamable HTTP transport and middleware."""
    # Disable DNS rebinding protection so requests from Render and remote reverse proxies pass through
    transport_sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=transport_sec,
    )
    app.add_middleware(AuthMiddleware)
    return app


def main() -> None:
    """Entrypoint to run the server on the configured PORT and HOST."""
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    token_configured = bool(os.environ.get("MCP_AUTH_TOKEN") or os.environ.get("AUTH_TOKEN"))

    logger.info("Starting Log Detective MCP Server on %s:%d (auth_enabled=%s)", host, port, token_configured)
    logger.info("Endpoints: Health -> http://%s:%d/health | MCP -> http://%s:%d/mcp", host, port, host, port)

    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
