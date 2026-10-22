# Log Detective MCP 🔍

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/protocol-MCP%20v2%20Streamable%20HTTP-green.svg)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/tests-50%20passed-brightgreen.svg)](tests/)

**Log Detective MCP** is a source-agnostic, multi-connector MCP server that lets AI clients like **Google Antigravity** discover, read, and investigate application logs from any authorized source — without you ever copying log text manually.

> **What changed in v1.1**: The server now exposes two new tools (`list_log_sources`, `read_logs`) and a modular source connector architecture so AI clients can retrieve and investigate logs directly using only a `source_id`.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                       Log Detective MCP Server                     │
│                                                                    │
│  Tools                 Source Connectors          Security         │
│  ──────                ─────────────────          ────────         │
│  list_log_sources  ──► LocalFileLogSource         Bearer Auth      │
│  read_logs         ──► CapturedProcessLogSource   Allowlists       │
│  find_errors       ──► DockerLogSource            Path Traversal   │
│  get_log_context   ──► RemoteApiLogSource         Secret Redact    │
│  compare_logs          LogSourceRegistry          Input Bounds     │
└──────────────────────────┬─────────────────────────────────────────┘
                           │ MCP over Streamable HTTP (TLS)
                           │ or stdio (local)
                    ┌──────┴──────┐
                    │  Antigravity │
                    │  AI Client   │
                    └─────────────┘
```

### Key Design Principles

- **Stateless analysis**: Tools work on log text in memory — no persistent database.
- **Source abstraction**: Connectors are registered per source ID; AI clients never supply raw file paths.
- **Fail-closed security**: Unauthorized paths, oversized inputs, and invalid source IDs are always rejected.
- **Evidence-only**: Log Detective retrieves and organizes evidence. It does not modify code, execute shell commands, or determine root cause autonomously.

---

## Five MCP Tools

| Tool | Purpose | Primary Inputs |
|------|---------|---------------|
| `list_log_sources` | Discover configured, authorized sources | — |
| `read_logs` | Fetch recent entries from a source | `source_id`, `limit`, `severity`, `search_term` |
| `find_errors` | Scan for errors and stack traces | `source_id` **or** `log_text`, `severity`, `limit` |
| `get_log_context` | View context around a line number | `target_line`, `source_id` **or** `log_text` |
| `compare_logs` | Diff baseline vs. failing run | `baseline_source_id` + `failing_source_id` **or** text |

All existing text-based workflows remain backward-compatible.

---

## Source Connector Types

| Type | Class | When to use |
|------|-------|-------------|
| `local_file` | `LocalFileLogSource` | App writes to a file; full path traversal protection |
| `captured_process` | `CapturedProcessLogSource` | App stdout/stderr redirected to a spool file |
| `docker` | `DockerLogSource` | Container logs via Docker SDK (container allowlisted) |
| `remote_api` | `RemoteApiLogSource` | Internal HTTPS log API (domain allowlisted, no SSRF) |

---

## Project Structure

```
log-detective-mcp/
├── src/
│   └── log_detective/
│       ├── __init__.py
│       ├── server.py          # MCPServer, Streamable HTTP, auth, tool registration
│       ├── tools.py           # All 5 tool implementations
│       ├── parsers.py         # Multi-language log parsing & normalization
│       ├── validators.py      # Input bounds & argument validation
│       ├── security.py        # Secret redaction, path traversal validation
│       └── sources/
│           ├── __init__.py
│           ├── base.py        # BaseLogSource abstract interface
│           ├── registry.py    # LogSourceRegistry — register/discover sources
│           ├── local_file.py  # Local file connector (path-traversal-safe)
│           ├── process.py     # Captured process spool connector
│           ├── docker.py      # Docker SDK connector (allowlisted only)
│           └── remote.py      # Remote HTTP API connector (SSRF-safe)
├── tests/
│   ├── test_compare_logs.py
│   ├── test_find_errors.py
│   ├── test_log_context.py
│   ├── test_server.py
│   ├── test_parsers_multilang.py   # Python, Node.js, Java, Go parsing
│   ├── test_security_redaction.py  # Secret/credential redaction
│   ├── test_sources_local.py       # Path traversal, permission errors
│   ├── test_sources_process.py
│   ├── test_sources_docker.py      # Mocked Docker SDK
│   ├── test_sources_remote.py      # SSRF prevention, mocked HTTP
│   └── test_tools_discovery_retrieval.py
├── examples/
│   ├── successful.log
│   └── failing.log
├── sources.json              # Active source configuration
├── sources.example.json      # Documented example configuration
├── .env.example              # Environment variable reference
├── requirements.txt
└── pyproject.toml
```

---

## Quickstart: Local Development

### 1. Install

```bash
git clone https://github.com/prasa/log-detective-mcp.git
cd log-detective-mcp
pip install -r requirements.txt
pip install -e .
```

### 2. Configure Sources

Copy and edit the example configuration:

```bash
cp sources.example.json sources.json
```

Edit `sources.json` to point to your actual log files:

```json
{
  "sources": [
    {
      "type": "local_file",
      "source_id": "my-app",
      "name": "My Application Log",
      "path": "logs/app.log",
      "allowed_root": "logs/",
      "description": "FastAPI backend application log"
    }
  ]
}
```

> **Security**: Only files inside `allowed_root` are accessible. Path traversal attempts (`../etc/passwd`) are always rejected.

### 3. Run Locally

```bash
# Optional auth token for remote deployments
export MCP_AUTH_TOKEN=my-secret-token

python -m log_detective.server
```

Server starts at `http://0.0.0.0:8000`:
- **Health**: `GET /health`
- **MCP**: `POST /mcp` (Streamable HTTP)

### 4. Test

```bash
pytest -v  # 50 tests, all passing
```

---

## Connecting Antigravity (Local stdio)

Edit `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "log-detective": {
      "command": "python",
      "args": ["-m", "log_detective.server", "--stdio"],
      "cwd": "C:\\path\\to\\log-detective-mcp"
    }
  }
}
```

Restart Antigravity — it will discover all 5 tools automatically.

---

## Connecting Antigravity (Remote / Render)

After deploying to Render (see below):

```json
{
  "mcpServers": {
    "log-detective": {
      "serverUrl": "https://YOUR-SERVICE.onrender.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```

---

## Registering a New Log Source

### Option A: `sources.json` file (recommended)

```json
{
  "sources": [
    {
      "type": "local_file",
      "source_id": "backend-api",
      "name": "Backend API",
      "path": "/var/log/myapp/api.log",
      "allowed_root": "/var/log/myapp/",
      "description": "Production FastAPI log"
    },
    {
      "type": "docker",
      "source_id": "redis-cache",
      "name": "Redis Container",
      "container": "redis-prod",
      "allowlisted_containers": ["redis-prod"]
    }
  ]
}
```

### Option B: Single file via environment variable

```bash
export LOG_DETECTIVE_LOG_FILE=/var/log/myapp/app.log
python -m log_detective.server
```

This auto-registers a source with `source_id="app-log"`.

### Option C: Programmatically

```python
from log_detective.sources.local_file import LocalFileLogSource
from log_detective.sources.registry import default_registry

default_registry.register_source(
    LocalFileLogSource(
        source_id="my-api",
        name="My API Logs",
        file_path="/var/log/api/app.log",
        allowed_root="/var/log/api/",
    )
)
```

---

## Example Workflows in Antigravity

### Workflow 1: Discover and investigate

> *"List available log sources, then find all errors in the checkout service."*

Antigravity calls:
1. `list_log_sources()` → sees `checkout-failing`, `checkout-baseline`
2. `find_errors(source_id="checkout-failing")` → 2 errors, line numbers, stack traces
3. `get_log_context(target_line=9, source_id="checkout-failing")` → 5-line window

### Workflow 2: Compare runs

> *"Compare the baseline and failing checkout logs and explain what changed."*

```
compare_logs(
  baseline_source_id="checkout-baseline",
  failing_source_id="checkout-failing"
)
```

Returns: added events (timeouts, 504 errors), missing events (payment auth, order confirmed), frequency divergences.

### Workflow 3: Search for a specific error

> *"Search the backend logs for any Redis connection errors."*

```
read_logs(source_id="backend-api", search_term="Redis", severity="ERROR")
```

---

## Deployment on Render

1. Push to GitHub.
2. Create **Render Web Service** from your repository.
3. Configure:
   - **Build**: `pip install -r requirements.txt && pip install -e .`
   - **Start**: `python -m log_detective.server`
   - **Health Check Path**: `/health`
4. Set **Environment Variables**:
   - `MCP_AUTH_TOKEN`: A strong random secret (`openssl rand -hex 24`)
   - `PORT`: Set automatically by Render
   - `LOG_DETECTIVE_SOURCES_CONFIG`: Path to your `sources.json`

MCP endpoint: `https://YOUR-SERVICE.onrender.com/mcp`

---

## Security Limitations

- **Redaction is best-effort**: Secret patterns are detected heuristically. Do not rely on redaction alone — use access controls and least-privilege permissions.
- **Local files only serve allowlisted paths**: Any path outside `allowed_root` is rejected with a path traversal error regardless of caller-supplied path.
- **Docker allowlists are required**: The Docker connector rejects any container not in `allowlisted_containers`.
- **Remote API domain allowlists prevent SSRF**: Only explicitly configured domains (including subdomains) are permitted.
- **No arbitrary shell execution**: The server never runs shell commands, terminates processes, or modifies files.
- **DNS rebinding protection**: Disabled for reverse-proxy compatibility on Render. On local networks, consider re-enabling `TransportSecuritySettings(enable_dns_rebinding_protection=True)`.

---

## Optional Connector: Docker

Docker support requires the `docker` Python SDK:

```bash
pip install docker
```

Then add a Docker source to `sources.json`:

```json
{
  "type": "docker",
  "source_id": "web-api",
  "name": "Web API Container",
  "container": "web-api-prod",
  "allowlisted_containers": ["web-api-prod"]
}
```

The server works without Docker installed (local file mode is unaffected).

---

## Optional Connector: Remote API

Add a remote source with an explicitly allowed domain:

```json
{
  "type": "remote_api",
  "source_id": "central-logs",
  "name": "Internal Log Service",
  "endpoint_url": "https://logs.internal.mycompany.com/v1/query",
  "allowed_domains": ["internal.mycompany.com"],
  "auth_token": "your-token-here"
}
```

Only `https://` URLs whose hostname matches an allowed domain are contacted. Requests to cloud metadata services, internal network IPs, or unapproved hostnames are rejected with a `PermissionError`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `source_id 'X' is not configured` | Source missing from `sources.json` | Add it and restart server |
| `Path traversal detected` | File path escapes `allowed_root` | Ensure `path` is inside `allowed_root` |
| `Permission denied` | File permissions | Check OS-level read access |
| `401 Unauthorized` | Wrong/missing Bearer token | Set `Authorization: Bearer <token>` header |
| Tools not showing in Antigravity | Stale MCP server cache | Refresh MCP servers in Antigravity settings |
| Docker source unavailable | `docker` package not installed | `pip install docker` |

---

## Acceptance Checklist (v1.1 Complete)

| Requirement | Status |
|-------------|--------|
| All 5 tools work | ✅ |
| Source ID → direct log retrieval | ✅ |
| Local file connector with path traversal protection | ✅ |
| Captured process connector | ✅ |
| Docker connector (mocked, allowlisted) | ✅ |
| Remote API connector (SSRF-safe) | ✅ |
| Secret redaction for tokens, passwords, API keys | ✅ |
| Multi-language parsing (Python, Node.js, Java, Go) | ✅ |
| Antigravity connected via stdio locally | ✅ |
| Bearer auth for remote deployments | ✅ |
| 50 tests passing | ✅ |
| README with full instructions | ✅ |
