"""Security utilities including best-effort secret redaction and safe path handling."""

from pathlib import Path
import re
from typing import Optional

# Regex patterns for common sensitive tokens and credentials
REDACTION_PATTERNS = [
    # Authorization / Bearer tokens
    (re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}"), r"\1[REDACTED_TOKEN]"),
    # Generic API Keys / Tokens
    (re.compile(r"(?i)(api[_-]?key[\s:=]+['\"]?)[a-zA-Z0-9_\-]{16,}['\"]?"), r"\1[REDACTED_API_KEY]"),
    # OpenAI / Anthropic / Google / GitHub tokens
    (re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36,})\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\b(gho_[a-zA-Z0-9]{36,})\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"), "[REDACTED_GOOGLE_API_KEY]"),
    # AWS Keys
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(aws_secret_access_key[\s:=]+['\"]?)[a-zA-Z0-9/+=]{40}['\"]?"), r"\1[REDACTED_AWS_SECRET]"),
    # Passwords in query strings or JSON/key-value (handles "password": "...", password=..., etc.)
    (re.compile(r"(?i)(['\"]?password['\"]?[\s:=]+['\"]?)[^'\"&,\r\n]{3,}['\"]?"), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(?i)(['\"]?passwd['\"]?[\s:=]+['\"]?)[^'\"&,\r\n]{3,}['\"]?"), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(?i)(['\"]?secret['\"]?[\s:=]+['\"]?)[a-zA-Z0-9_\-\.]{8,}['\"]?"), r"\1[REDACTED_SECRET]"),
    # Database connection strings with passwords
    (re.compile(r"(?i)([a-z0-9+]+://[^:]+:)[^@]+(@)"), r"\1[REDACTED_PASSWORD]\2"),
    # Private Keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def redact_secrets(text: str) -> str:
    """Redact known secret patterns (tokens, passwords, API keys) from log text.

    Note: Redaction is best-effort and heuristic. It should not replace proper
    access control and least-privilege configurations.
    """
    if not text:
        return text

    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def validate_safe_path(target_path: Path, allowed_root: Path) -> Path:
    """Validate that target_path resides strictly within allowed_root.

    Resolves symlinks and relative traversals (e.g. '../').
    Raises:
        ValueError: If path attempts to escape the allowed root.
    """
    resolved_target = target_path.resolve()
    resolved_root = allowed_root.resolve()

    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise ValueError(
            f"Path traversal detected: target '{target_path.name}' is outside permitted directory '{resolved_root.name}'."
        )

    return resolved_target
