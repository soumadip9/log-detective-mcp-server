# Log Detective MCP 🔍

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/protocol-MCP%20Streamable%20HTTP-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Log Detective MCP** is a hosted Model Context Protocol (MCP) server that provides structured, safe, and stateless access to application logs. Connected AI clients like **Google Antigravity** can use Log Detective's debugging tools to discover errors, inspect surrounding execution context, and compare baseline vs. failing runs without mixing tenant data or requiring persistent storage.

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Tool Specifications](#-tool-specifications)
- [Project Structure](#-project-structure)
- [Quickstart & Local Development](#-quickstart--local-development)
- [Running the Test Suite](#-running-the-test-suite)
- [Deployment on Render](#-deployment-on-render)
- [Connecting Antigravity](#-connecting-antigravity)
- [Example Debugging Workflow](#-example-debugging-workflow)
- [Security & Privacy Principles](#-security--privacy-principles)
- [Acceptance Checklist](#-acceptance-checklist)

---

## 🏛️ Overview & Architecture

When diagnosing failures, AI assistants need relevant log evidence rather than entire gigabyte dump files. Log Detective exposes three focused tools designed specifically for incident diagnosis:

```
+--------------------------+          +----------------------------------+
|  Developer Application   |          |      Hosted Log Detective        |
|  (Node, Python, Go, Java)|          |      Render (Streamable HTTP)    |
|                          |          |                                  |
|  Produces application    |          |  [find_errors]                   |
|  logs (text or JSON)     |          |  [get_log_context]               |
+------------+-------------+          |  [compare_logs]                  |
             |                        +-----------------+----------------+
             | Logs                                     ^
             v                                          | MCP over Streamable HTTP
+--------------------------+                            | (Bearer Auth + TLS)
|    Antigravity / AI      |----------------------------+
|    Client                |
|                          |
|  - Reads workspace logs  |
|  - Invokes MCP tools     |
|  - Explains root cause   |
+--------------------------+
```

### Key Product Boundaries
- **Stateless by Design**: Tools accept log text as direct arguments and return structured results immediately. No database, S3 bucket, or persistent log store is required for MVP.
- **Evidence Retrieval Only**: Log Detective retrieves and organizes empirical evidence (line numbers, stack traces, diffs). It does not edit source code, execute arbitrary shell commands, or make subjective assumptions regarding causation.

---

## 🛠️ Tool Specifications

### 1. `find_errors`
Scans raw log text (plain-text or JSON lines) for error events, stack traces, and failure indicators.
- **Inputs**:
  - `log_text` *(string, required)*: Raw log content to inspect.
  - `severity` *(string, optional, default: `"ERROR"`)*: Severity filter (`"ERROR"`, `"WARN"`, `"CRITICAL"`, `"INFO"`, `"ALL"`).
  - `limit` *(integer, optional, default: `50`, max: `200`)*: Maximum results returned.
- **Returns**: Total lines, matching count, line numbers, timestamps, messages, and grouped multiline stack traces.

### 2. `get_log_context`
Retrieves surrounding lines of context before and after a specific target line.
- **Inputs**:
  - `log_text` *(string, required)*: Raw log content.
  - `target_line` *(integer, required)*: 1-indexed line number to center the window on.
  - `context_size` *(integer, optional, default: `5`, max: `50`)*: Number of lines before and after.
- **Returns**: Bounded context window, target indicator (`is_target: true`), and formatted text block with `>` marker.

### 3. `compare_logs`
Compares a known healthy baseline log run against a failing log run to identify behavioral divergences.
- **Inputs**:
  - `baseline_log` *(string, required)*: Healthy execution log.
  - `failing_log` *(string, required)*: Failing execution log.
- **Returns**: Added events (new errors/warnings), missing events (expected steps that didn't complete), frequency changes (retry loops), and an explicit non-causation disclaimer.

---

## 📁 Project Structure

```
log-detective-mcp/
├── src/
│   └── log_detective/
│       ├── __init__.py      # Package initialization
│       ├── server.py        # MCPServer instance, Starlette app, HTTP transport & auth
│       ├── tools.py         # The 3 MCP tools implementation
│       ├── parsers.py       # Plaintext and JSON line parsers, normalizer
│       └── validators.py    # Input validation, bounds & security guards
├── tests/
│   ├── test_find_errors.py  # Phase 2 test suite
│   ├── test_log_context.py  # Phase 3 test suite
│   ├── test_compare_logs.py # Phase 4 test suite
│   └── test_server.py       # Phase 5 & 6 server, discovery, health & auth tests
├── examples/
│   ├── successful.log       # Reproducible baseline checkout log
│   └── failing.log          # Reproducible failing checkout log (timeouts & retries)
├── requirements.txt         # Pinned production & development dependencies
├── pyproject.toml           # Standard Python packaging configuration
├── .gitignore
└── README.md
```

---

## 🚀 Quickstart & Local Development

### 1. Prerequisites
- Python 3.11 or higher
- Git

### 2. Install Dependencies
```bash
git clone https://github.com/prasa/log-detective-mcp.git
cd log-detective-mcp

# Install dependencies in editable mode
pip install -r requirements.txt
pip install -e .
```

### 3. Run the Server Locally
```bash
# Optional: Set a local auth token
export MCP_AUTH_TOKEN="my-secret-token"

# Start server
python -m log_detective.server
```
The server will start listening on `http://0.0.0.0:8000`:
- **Health check**: `http://localhost:8000/health`
- **MCP Streamable HTTP Endpoint**: `http://localhost:8000/mcp`

### 4. Test with the Official MCP Inspector
You can test tool discovery and execution locally using the MCP Inspector:
```bash
npx @modelcontextprotocol/inspector
```
Connect via transport: `Streamable HTTP` with URL `http://localhost:8000/mcp` (and header `Authorization: Bearer my-secret-token` if configured).

---

## 🧪 Running the Test Suite

Log Detective includes a comprehensive pytest suite covering all input validations, parser edge cases, stack traces, and security limits:

```bash
pytest -v
```

Expected result:
```
============================= 21 passed in 2.06s ==============================
```

---

## ☁️ Deployment on Render

Deploy Log Detective as a **Render Web Service** for a public HTTPS endpoint.

### Step 1: Push Repository to GitHub
```bash
git add .
git commit -m "Initial release of Log Detective MCP v1.0.0"
git remote add origin https://github.com/YOUR_USERNAME/log-detective-mcp.git
git push -u origin master
```

### Step 2: Create a Web Service on Render
1. Open the [Render Dashboard](https://dashboard.render.com/) and click **New +** → **Web Service**.
2. Select your `log-detective-mcp` GitHub repository.
3. Configure the service settings:
   - **Name**: `log-detective-mcp`
   - **Region**: Select your preferred region (e.g., Oregon, Frankfurt)
   - **Branch**: `master` (or `main`)
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt && pip install -e .`
   - **Start Command**: `python -m log_detective.server`
   - **Instance Type**: `Free` or `Starter`
4. Add **Environment Variables**:
   - `MCP_AUTH_TOKEN`: Generate a strong random token (e.g. `openssl rand -hex 24`).
   - *(Note: Render automatically supplies `PORT`, which our server automatically binds to).*
5. Set Health Check Path:
   - **Health Check Path**: `/health`
6. Click **Create Web Service**.

Once deployed, your public MCP endpoint will be:
```
https://log-detective-mcp.onrender.com/mcp
```

---

## 🤖 Connecting Antigravity

Add your hosted server to your Antigravity MCP configuration (`settings.json` or project MCP configuration):

```json
{
  "mcpServers": {
    "log-detective": {
      "serverUrl": "https://log-detective-mcp.onrender.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```

> **Security Note**: Never commit actual authentication tokens to public version control.

Once added, restart or refresh Antigravity's MCP server panel. Antigravity will discover the three tools:
- `find_errors`
- `get_log_context`
- `compare_logs`

---

## 💡 Example Debugging Workflow

With Log Detective connected, you can prompt Antigravity:

> *"Investigate why my checkout API is failing. Read the workspace log at `examples/failing.log` and use Log Detective to examine the evidence."*

### Step-by-Step AI Execution
1. **Fetch Log Content**: Antigravity reads `examples/failing.log` from the workspace.
2. **Find Errors**:
   ```json
   find_errors({
     "log_text": "...",
     "severity": "ERROR"
   })
   ```
   *Result*: Discovers `PaymentGateway: Failed to authorize transaction after 3 retries: GatewayTimeoutException` on Line 9.
3. **Inspect Context**:
   ```json
   get_log_context({
     "log_text": "...",
     "target_line": 9,
     "context_size": 4
   })
   ```
   *Result*: Reveals lines 5–8 showing 3 repeated 5000ms timeouts contacting Stripe before the error was thrown.
4. **Compare with Baseline**:
   ```json
   compare_logs({
     "baseline_log": "<content of examples/successful.log>",
     "failing_log": "<content of examples/failing.log>"
   })
   ```
   *Result*: Highlights that `txn_9918237461` and order database write are missing, replaced by Stripe read timeout and inventory rollback.
5. **AI Synthesis**: The AI explains to the developer that Stripe API timeouts caused 3 failed retries leading to the 504 Gateway Timeout, and provides actionable remediation steps.

---

## 🔒 Security & Privacy Principles

- **Zero-Storage Privacy**: No customer logs are written to database or persistent disk. Logs exist only in transient memory during tool execution.
- **Safe Parsing (Untrusted Input)**: Log entries are treated as untrusted text strings. Malformed lines, injection strings, or instructional prompt injection embedded inside logs are never evaluated as code or system commands.
- **Bounded Resources**:
  - Maximum log payload: 5 MB (`MAX_LOG_SIZE_BYTES`)
  - Maximum context window: 50 lines (`MAX_CONTEXT_SIZE`)
  - Maximum error limit: 200 items (`MAX_FIND_ERRORS_LIMIT`)
- **Sanitized Operational Logs**: The server logs operational metrics (request count, tool names, timing) but explicitly suppresses raw log bodies and Bearer tokens.
- **Non-Causation Disclaimer**: All comparative diffs clearly state that differences indicate correlation and empirical evidence, not proven causation.

---

## ✅ Acceptance Checklist

| Requirement | Status | Verification |
|---|:---:|---|
| **All three tools work** | ✅ | Unit tested across JSON, plaintext & stack traces |
| **Inputs are bounded** | ✅ | Guards for oversized logs, invalid line numbers & context size |
| **MCP Inspector succeeds** | ✅ | Discovers and executes tools over Streamable HTTP |
| **Remote deployment ready** | ✅ | Binds to `0.0.0.0` and `$PORT`, handles reverse proxies |
| **Antigravity connects** | ✅ | Configured via `serverUrl` and Bearer token headers |
| **Evidence is useful** | ✅ | Line numbers, context window markers, stack traces |
| **Security checks pass** | ✅ | 401 on missing/bad token, no logs/secrets in stdout |
| **README complete** | ✅ | Full deployment & configuration instructions |

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
