"""Hosted Log Detective MCP Server with Streamable HTTP transport, source discovery, and authentication."""

import logging
import os
import sys
from typing import Any, Dict, Optional

from mcp.server.mcpserver import MCPServer
from mcp.server.streamable_http import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import uvicorn

from log_detective.sources.registry import default_registry
from log_detective.tools import compare_logs as tool_compare_logs
from log_detective.tools import find_errors as tool_find_errors
from log_detective.tools import get_log_context as tool_get_log_context
from log_detective.tools import list_log_sources as tool_list_log_sources
from log_detective.tools import read_logs as tool_read_logs

# Configure operational logging - Never log raw log text or credentials
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("log_detective.server")

# Initialize MCP Server instance
server = MCPServer(
    name="log-detective",
    instructions=(
        "Log Detective MCP Server provides tools to discover, retrieve, and investigate application logs. "
        "AI clients can inspect authorized log sources with list_log_sources, read recent logs with read_logs, "
        "and find errors, examine context, or compare runs using find_errors, get_log_context, and compare_logs."
    ),
)


@server.custom_route("/health", methods=["GET"])
async def health_check(request: Any) -> JSONResponse:
    """Operational health check endpoint for monitoring uptime (e.g. Render)."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "log-detective-mcp",
            "version": "1.1.0",
        }
    )


@server.custom_route("/", methods=["GET"])
async def root_info(request: Any) -> JSONResponse:
    """Root info endpoint providing basic server metadata."""
    return JSONResponse(
        {
            "service": "log-detective-mcp",
            "description": "Log Detective MCP Server for multi-source application log investigation",
            "health_endpoint": "/health",
            "mcp_endpoint": "/mcp",
            "docs": "https://github.com/prasa/log-detective-mcp",
        }
    )


@server.tool(
    name="list_log_sources",
    description=(
        "Discover the configured log sources that this server is authorized to read. "
        "Returns safe metadata including source ID, name, source type (local_file, captured_process, "
        "docker, remote_api), description, capabilities, and availability status. "
        "Use this first to see what log sources are available for debugging."
    ),
)
def list_log_sources() -> Dict[str, Any]:
    """List all available log sources."""
    logger.info("Executing list_log_sources")
    try:
        return tool_list_log_sources()
    except Exception as exc:
        logger.warning("list_log_sources error: %s", exc)
        return {"error": str(exc), "status": "error"}


@server.tool(
    name="read_logs",
    description=(
        "Read recent logs from a configured log source with bounded limits and optional filters. "
        "Supports filtering by severity (e.g. ERROR, WARN), search term, and line limits. "
        "Returns normalized log entries, timestamps, components, stack traces, and raw previews."
    ),
)
def read_logs(
    source_id: str,
    limit: int = 100,
    severity: Optional[str] = None,
    search_term: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Dict[str, Any]:
    """Read logs from a configured source ID."""
    logger.info("Executing read_logs (source_id=%s, limit=%s, severity=%s)", source_id, limit, severity)
    try:
        return tool_read_logs(
            source_id=source_id,
            limit=limit,
            severity=severity,
            search_term=search_term,
            start_time=start_time,
            end_time=end_time,
        )
    except (KeyError, FileNotFoundError) as exc:
        logger.warning("read_logs resource not found: %s", exc)
        return {"error": str(exc), "status": "not_found"}
    except PermissionError as exc:
        logger.warning("read_logs permission denied: %s", exc)
        return {"error": str(exc), "status": "permission_denied"}
    except (ValueError, TypeError) as exc:
        logger.warning("read_logs validation error: %s", exc)
        return {"error": str(exc), "status": "invalid_argument"}
    except Exception as exc:
        logger.error("read_logs execution failure: %s", exc)
        return {"error": str(exc), "status": "execution_failed"}


@server.tool(
    name="find_errors",
    description=(
        "Scan log text or a configured log source for error events, stack traces, and failure indicators. "
        "Returns line numbers, extracted error messages, timestamps, components, and stack traces. "
        "Accepts either 'source_id' to read from a configured source or direct 'log_text'."
    ),
)
def find_errors(
    log_text: Optional[str] = None,
    source_id: Optional[str] = None,
    severity: str = "ERROR",
    limit: int = 50,
) -> Dict[str, Any]:
    """Find errors within log text or from a configured log source."""
    logger.info("Executing find_errors (source_id=%s, severity=%s, limit=%s)", source_id, severity, limit)
    try:
        return tool_find_errors(log_text=log_text, source_id=source_id, severity=severity, limit=limit)
    except (KeyError, FileNotFoundError) as exc:
        logger.warning("find_errors resource not found: %s", exc)
        return {"error": str(exc), "status": "not_found"}
    except PermissionError as exc:
        logger.warning("find_errors permission denied: %s", exc)
        return {"error": str(exc), "status": "permission_denied"}
    except (ValueError, TypeError) as exc:
        logger.warning("find_errors validation error: %s", exc)
        return {"error": str(exc), "status": "invalid_argument"}
    except Exception as exc:
        logger.error("find_errors failure: %s", exc)
        return {"error": str(exc), "status": "execution_failed"}


@server.tool(
    name="get_log_context",
    description=(
        "Retrieve surrounding lines of context before and after a specific line number in a log. "
        "Preserves timestamps, stack traces, and highlights the target line. "
        "Accepts either 'source_id' to read from a configured source or direct 'log_text'."
    ),
)
def get_log_context(
    target_line: int,
    log_text: Optional[str] = None,
    source_id: Optional[str] = None,
    context_size: int = 5,
) -> Dict[str, Any]:
    """Retrieve lines surrounding a target line number."""
    logger.info("Executing get_log_context (source_id=%s, target_line=%s, context_size=%s)", source_id, target_line, context_size)
    try:
        return tool_get_log_context(target_line=target_line, log_text=log_text, source_id=source_id, context_size=context_size)
    except (KeyError, FileNotFoundError) as exc:
        logger.warning("get_log_context resource not found: %s", exc)
        return {"error": str(exc), "status": "not_found"}
    except PermissionError as exc:
        logger.warning("get_log_context permission denied: %s", exc)
        return {"error": str(exc), "status": "permission_denied"}
    except (ValueError, TypeError) as exc:
        logger.warning("get_log_context validation error: %s", exc)
        return {"error": str(exc), "status": "invalid_argument"}
    except Exception as exc:
        logger.error("get_log_context failure: %s", exc)
        return {"error": str(exc), "status": "execution_failed"}


@server.tool(
    name="compare_logs",
    description=(
        "Compare a healthy baseline log run against a failing log run to identify newly added errors, "
        "missing expected events, and frequency differences. "
        "Accepts direct log text or source IDs ('baseline_source_id', 'failing_source_id')."
    ),
)
def compare_logs(
    baseline_log: Optional[str] = None,
    failing_log: Optional[str] = None,
    baseline_source_id: Optional[str] = None,
    failing_source_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Compare baseline log against failing log."""
    logger.info("Executing compare_logs (baseline_source=%s, failing_source=%s)", baseline_source_id, failing_source_id)
    try:
        return tool_compare_logs(
            baseline_log=baseline_log,
            failing_log=failing_log,
            baseline_source_id=baseline_source_id,
            failing_source_id=failing_source_id,
        )
    except (KeyError, FileNotFoundError) as exc:
        logger.warning("compare_logs resource not found: %s", exc)
        return {"error": str(exc), "status": "not_found"}
    except PermissionError as exc:
        logger.warning("compare_logs permission denied: %s", exc)
        return {"error": str(exc), "status": "permission_denied"}
    except (ValueError, TypeError) as exc:
        logger.warning("compare_logs validation error: %s", exc)
        return {"error": str(exc), "status": "invalid_argument"}
    except Exception as exc:
        logger.error("compare_logs failure: %s", exc)
        return {"error": str(exc), "status": "execution_failed"}


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
    default_registry.load_from_environment()

    transport_sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=transport_sec,
    )
    app.add_middleware(AuthMiddleware)
    return app


def main() -> None:
    """Entrypoint to run the server on the configured PORT/HOST or stdio."""
    default_registry.load_from_environment()

    if "--stdio" in sys.argv:
        server.run(transport="stdio")
        return

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    token_configured = bool(os.environ.get("MCP_AUTH_TOKEN") or os.environ.get("AUTH_TOKEN"))

    logger.info("Starting Log Detective MCP Server on %s:%d (auth_enabled=%s)", host, port, token_configured)
    logger.info("Endpoints: Health -> http://%s:%d/health | MCP -> http://%s:%d/mcp", host, port, host, port)

    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
