"""Input validation and boundedness checks for Log Detective MCP."""

from typing import Optional

# Maximum limits to protect server resources
MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_LOG_LINES = 100_000
MAX_FIND_ERRORS_LIMIT = 200
DEFAULT_FIND_ERRORS_LIMIT = 50
MAX_CONTEXT_SIZE = 50
DEFAULT_CONTEXT_SIZE = 5

VALID_SEVERITIES = {
    "DEBUG",
    "INFO",
    "NOTICE",
    "WARN",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "FATAL",
    "EXCEPTION",
    "SEVERE",
    "ALERT",
    "EMERGENCY",
    "ALL",
    "ANY",
}


def validate_log_text(log_text: str, field_name: str = "log_text") -> str:
    """Validate that the log text is a string within acceptable size boundaries.

    Raises:
        TypeError: If log_text is not a string.
        ValueError: If log_text is empty or exceeds the maximum allowed size.
    """
    if not isinstance(log_text, str):
        raise TypeError(f"'{field_name}' must be a string, got {type(log_text).__name__}.")

    byte_len = len(log_text.encode("utf-8"))
    if byte_len > MAX_LOG_SIZE_BYTES:
        raise ValueError(
            f"'{field_name}' exceeds maximum allowed size of {MAX_LOG_SIZE_BYTES // (1024 * 1024)} MB "
            f"(received {byte_len / (1024 * 1024):.2f} MB)."
        )

    return log_text


def validate_limit(limit: Optional[int], default: int = DEFAULT_FIND_ERRORS_LIMIT, max_limit: int = MAX_FIND_ERRORS_LIMIT) -> int:
    """Validate limit argument for bounded responses."""
    if limit is None:
        return default

    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError(f"'limit' must be an integer, got {type(limit).__name__}.")

    if limit <= 0:
        raise ValueError(f"'limit' must be a positive integer greater than 0, got {limit}.")

    return min(limit, max_limit)


def validate_severity(severity: Optional[str]) -> str:
    """Validate severity filter."""
    if severity is None:
        return "ERROR"

    if not isinstance(severity, str):
        raise TypeError(f"'severity' must be a string, got {type(severity).__name__}.")

    cleaned = severity.strip().upper()
    if not cleaned:
        return "ERROR"

    return cleaned


def validate_target_line(target_line: int, total_lines: int) -> int:
    """Validate that target_line is a 1-based line number within bounds.

    Raises:
        TypeError: If target_line is not an int.
        ValueError: If target_line is out of range [1, total_lines].
    """
    if not isinstance(target_line, int) or isinstance(target_line, bool):
        raise TypeError(f"'target_line' must be an integer, got {type(target_line).__name__}.")

    if total_lines == 0:
        raise ValueError("Log content is empty; cannot retrieve context for any line.")

    if target_line < 1 or target_line > total_lines:
        raise ValueError(
            f"'target_line' {target_line} is out of bounds. Log contains {total_lines} lines (valid range: 1-{total_lines})."
        )

    return target_line


def validate_context_size(context_size: Optional[int], default: int = DEFAULT_CONTEXT_SIZE, max_context: int = MAX_CONTEXT_SIZE) -> int:
    """Validate context_size argument."""
    if context_size is None:
        return default

    if not isinstance(context_size, int) or isinstance(context_size, bool):
        raise TypeError(f"'context_size' must be an integer, got {type(context_size).__name__}.")

    if context_size < 0:
        raise ValueError(f"'context_size' cannot be negative, got {context_size}.")

    return min(context_size, max_context)
