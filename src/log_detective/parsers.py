"""Log parsing, normalization, and classification utilities."""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Tuple

# Regex patterns for plain-text log parsing
TIMESTAMP_PATTERN = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)

UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{4,}(?:-[0-9a-fA-F]{4,})+\b")
HEX_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")
REQUEST_ID_PATTERN = re.compile(r"\b(?:req_|req-|trace_|span_)[0-9a-zA-Z\-_]+\b", re.IGNORECASE)
EPHEMERAL_NUM_PATTERN = re.compile(r"\b\d{6,}\b")

# Plain text severity regex matching markers like [ERROR], ERROR:, level=error, etc.
SEVERITY_PATTERN = re.compile(
    r"(?:\[|\b)(CRITICAL|FATAL|SEVERE|EMERGENCY|ERROR|EXCEPTION|WARNING|WARN|ALERT|NOTICE|INFO|DEBUG|TRACE)(?:\]|:|\b)",
    re.IGNORECASE,
)

STACK_TRACE_LINE_PATTERN = re.compile(
    r"^(?:\s+at\s+.*|\s+File\s+\".*|Traceback \(most recent call last\):|\s+.*Error:.*|Caused by:.*|\s+\.\.\.\s+\d+\s+more)",
    re.IGNORECASE,
)

SEVERITY_HIERARCHY = {
    "FATAL": 50,
    "CRITICAL": 50,
    "EMERGENCY": 50,
    "SEVERE": 40,
    "ERROR": 40,
    "EXCEPTION": 40,
    "WARNING": 30,
    "WARN": 30,
    "ALERT": 30,
    "NOTICE": 20,
    "INFO": 20,
    "DEBUG": 10,
    "TRACE": 5,
}


@dataclass
class LogEntry:
    """Represents a parsed line from an application log."""

    line_number: int
    raw_content: str
    is_json: bool = False
    severity: Optional[str] = None
    message: str = ""
    timestamp: Optional[str] = None
    stack_trace: List[str] = field(default_factory=list)
    parsed_json: Optional[Dict[str, Any]] = None

    def normalized_message(self) -> str:
        """Return a normalized version of the message for comparison across runs."""
        msg = self.message if self.message else self.raw_content
        return normalize_log_line(msg)


def normalize_log_line(text: str) -> str:
    """Normalize dynamic log tokens (timestamps, UUIDs, hex addresses, request IDs)."""
    norm = TIMESTAMP_PATTERN.sub("<TIMESTAMP>", text)
    norm = UUID_PATTERN.sub("<UUID>", norm)
    norm = HEX_PATTERN.sub("<HEX>", norm)
    norm = REQUEST_ID_PATTERN.sub("<REQ_ID>", norm)
    norm = EPHEMERAL_NUM_PATTERN.sub("<NUM>", norm)
    # Collapse multiple whitespace
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


def parse_json_log_line(line: str) -> Optional[Tuple[Optional[str], str, Optional[str], Dict[str, Any]]]:
    """Attempt to parse a line as JSON and extract severity, message, timestamp, and json dict.

    Returns:
        (severity, message, timestamp, parsed_dict) or None if not JSON.
    """
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None

    try:
        data = json.loads(stripped)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None

    # Severity lookup
    severity: Optional[str] = None
    for key in ("level", "severity", "log_level", "logLevel", "lvl"):
        if key in data and isinstance(data[key], (str, int)):
            val = str(data[key]).upper()
            if val in SEVERITY_HIERARCHY:
                severity = val
                break
            # Handle numeric syslog levels if any
            if val in ("E", "ERR"):
                severity = "ERROR"
                break
            if val in ("W", "WRN"):
                severity = "WARN"
                break
            severity = val
            break

    # If no explicit level key, check HTTP status code
    if not severity:
        status = data.get("status") or data.get("status_code") or data.get("statusCode")
        if isinstance(status, int):
            if status >= 500:
                severity = "ERROR"
            elif status >= 400:
                severity = "WARN"

    # Message lookup
    message: str = ""
    for key in ("message", "msg", "error", "err", "description", "event", "detail"):
        if key in data and data[key]:
            message = str(data[key])
            break

    if not message:
        # Fallback to entire json representation
        message = stripped

    # Timestamp lookup
    timestamp: Optional[str] = None
    for key in ("timestamp", "time", "ts", "@timestamp", "datetime", "date"):
        if key in data and data[key]:
            timestamp = str(data[key])
            break

    return severity, message, timestamp, data


def parse_plaintext_log_line(line: str) -> Tuple[Optional[str], str, Optional[str]]:
    """Parse a plain-text log line for severity, message, and timestamp."""
    # Timestamp extraction
    ts_match = TIMESTAMP_PATTERN.search(line)
    timestamp = ts_match.group(0) if ts_match else None

    # Severity extraction
    severity: Optional[str] = None
    sev_match = SEVERITY_PATTERN.search(line)
    if sev_match:
        severity = sev_match.group(1).upper()
        if severity == "WARNING":
            severity = "WARN"
        elif severity == "CRITICAL" or severity == "FATAL":
            severity = "CRITICAL"

    # Message is the line without leading timestamp
    message = line.strip()
    return severity, message, timestamp


def parse_log_text(log_text: str) -> List[LogEntry]:
    """Parse raw log text into a list of LogEntry items, with stack traces grouped into parents."""
    if not log_text:
        return []

    raw_lines = log_text.splitlines()
    entries: List[LogEntry] = []

    for idx, raw_line in enumerate(raw_lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        # Check if this line is a continuation / stack trace line for previous entry
        if entries and STACK_TRACE_LINE_PATTERN.match(raw_line):
            entries[-1].stack_trace.append(raw_line)
            continue

        # Check if line is structured JSON
        json_result = parse_json_log_line(raw_line)
        if json_result is not None:
            sev, msg, ts, data = json_result
            # Check for stack trace inside JSON
            stack: List[str] = []
            for stack_key in ("stack", "stack_trace", "stackTrace", "trace"):
                if stack_key in data and isinstance(data[stack_key], str):
                    stack = data[stack_key].splitlines()
                    break
                elif stack_key in data and isinstance(data[stack_key], list):
                    stack = [str(x) for x in data[stack_key]]
                    break

            entries.append(
                LogEntry(
                    line_number=idx,
                    raw_content=raw_line,
                    is_json=True,
                    severity=sev,
                    message=msg,
                    timestamp=ts,
                    stack_trace=stack,
                    parsed_json=data,
                )
            )
        else:
            # Plain-text line
            sev, msg, ts = parse_plaintext_log_line(raw_line)
            entries.append(
                LogEntry(
                    line_number=idx,
                    raw_content=raw_line,
                    is_json=False,
                    severity=sev,
                    message=msg,
                    timestamp=ts,
                    stack_trace=[],
                )
            )

    return entries


def matches_severity(entry_severity: Optional[str], target_severity: str) -> bool:
    """Check if entry severity matches the target severity.

    Supports 'ALL', 'ANY', exact match, or category matches (e.g. 'ERROR' includes CRITICAL/FATAL/ERROR).
    """
    target = target_severity.upper().strip()
    if target in ("ALL", "ANY"):
        return True

    if not entry_severity:
        return False

    entry_sev = entry_severity.upper().strip()
    if entry_sev == target:
        return True

    # Standard groupings:
    # If target is ERROR: matches ERROR, CRITICAL, FATAL, SEVERE, EXCEPTION
    if target == "ERROR" and entry_sev in {"ERROR", "CRITICAL", "FATAL", "SEVERE", "EXCEPTION"}:
        return True

    # If target is WARN / WARNING: matches WARN, WARNING
    if target in {"WARN", "WARNING"} and entry_sev in {"WARN", "WARNING"}:
        return True

    # If target is CRITICAL: matches CRITICAL, FATAL, EMERGENCY
    if target in {"CRITICAL", "FATAL"} and entry_sev in {"CRITICAL", "FATAL", "EMERGENCY"}:
        return True

    return False
