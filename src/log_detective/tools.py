"""Implementation of the three Log Detective MCP tools."""

from collections import Counter
from typing import Any, Dict, List, Optional

from log_detective.parsers import (
    LogEntry,
    matches_severity,
    normalize_log_line,
    parse_log_text,
)
from log_detective.validators import (
    validate_context_size,
    validate_limit,
    validate_log_text,
    validate_severity,
    validate_target_line,
)


def find_errors(
    log_text: str,
    severity: Optional[str] = "ERROR",
    limit: Optional[int] = 50,
) -> Dict[str, Any]:
    """Scan log text for error events and return their line numbers and details.

    Args:
        log_text: The raw log contents (plain-text or JSON lines).
        severity: Severity filter (default 'ERROR'). Options include:
                  'ERROR', 'WARN', 'CRITICAL', 'INFO', 'DEBUG', 'ALL'.
        limit: Maximum number of matching entries to return (default 50, capped at 200).

    Returns:
        Structured dictionary containing total lines, matching errors, line numbers,
        timestamps, and associated stack traces.
    """
    valid_text = validate_log_text(log_text, "log_text")
    valid_sev = validate_severity(severity)
    valid_limit = validate_limit(limit)

    raw_lines = valid_text.splitlines()
    total_lines = len(raw_lines)
    if total_lines == 0:
        return {
            "total_lines": 0,
            "matching_count": 0,
            "returned_count": 0,
            "truncated": False,
            "severity_filter": valid_sev,
            "errors": [],
        }

    entries = parse_log_text(valid_text)
    matching_entries: List[LogEntry] = []

    for entry in entries:
        if matches_severity(entry.severity, valid_sev):
            matching_entries.append(entry)

    matching_count = len(matching_entries)
    returned_entries = matching_entries[:valid_limit]
    truncated = matching_count > valid_limit

    results = []
    for entry in returned_entries:
        item: Dict[str, Any] = {
            "line": entry.line_number,
            "severity": entry.severity or "UNKNOWN",
            "message": entry.message,
            "timestamp": entry.timestamp,
            "raw": entry.raw_content,
        }
        if entry.stack_trace:
            item["stack_trace"] = entry.stack_trace
        if entry.is_json and entry.parsed_json:
            item["is_json"] = True
        results.append(item)

    return {
        "total_lines": total_lines,
        "matching_count": matching_count,
        "returned_count": len(results),
        "truncated": truncated,
        "severity_filter": valid_sev,
        "errors": results,
    }


def get_log_context(
    log_text: str,
    target_line: int,
    context_size: Optional[int] = 5,
) -> Dict[str, Any]:
    """Retrieve surrounding lines of context before and after a specified target line.

    Args:
        log_text: The raw log contents.
        target_line: 1-indexed target line number to center the context window on.
        context_size: Number of lines before and after target_line (default 5, capped at 50).

    Returns:
        Structured context including line numbers, line content, target marker,
        and a formatted text preview.
    """
    valid_text = validate_log_text(log_text, "log_text")
    raw_lines = valid_text.splitlines()
    total_lines = len(raw_lines)

    valid_line = validate_target_line(target_line, total_lines)
    valid_size = validate_context_size(context_size)

    # Calculate 1-based start and end line numbers
    start_line = max(1, valid_line - valid_size)
    end_line = min(total_lines, valid_line + valid_size)

    context_lines = []
    formatted_rows = []

    for idx in range(start_line, end_line + 1):
        line_content = raw_lines[idx - 1]
        is_target = idx == valid_line
        context_lines.append(
            {
                "line_number": idx,
                "content": line_content,
                "is_target": is_target,
            }
        )

        marker = ">" if is_target else " "
        formatted_rows.append(f"{marker} {idx:5d} | {line_content}")

    return {
        "target_line": valid_line,
        "context_size": valid_size,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "lines": context_lines,
        "formatted": "\n".join(formatted_rows),
    }


def compare_logs(
    baseline_log: str,
    failing_log: str,
) -> Dict[str, Any]:
    """Compare a known successful/baseline log against a failing run to highlight differences.

    Args:
        baseline_log: Log content from a healthy/baseline execution.
        failing_log: Log content from the failing execution.

    Returns:
        Structured report detailing added events, missing expected events, and frequency
        discrepancies, with an explicit non-causation disclaimer.
    """
    valid_baseline = validate_log_text(baseline_log, "baseline_log")
    valid_failing = validate_log_text(failing_log, "failing_log")

    baseline_lines = valid_baseline.splitlines()
    failing_lines = valid_failing.splitlines()

    baseline_entries = parse_log_text(valid_baseline)
    failing_entries = parse_log_text(valid_failing)

    # Count normalized event occurrences
    baseline_patterns: Counter = Counter()
    baseline_first_seen: Dict[str, LogEntry] = {}
    for entry in baseline_entries:
        norm = entry.normalized_message()
        baseline_patterns[norm] += 1
        if norm not in baseline_first_seen:
            baseline_first_seen[norm] = entry

    failing_patterns: Counter = Counter()
    failing_first_seen: Dict[str, LogEntry] = {}
    for entry in failing_entries:
        norm = entry.normalized_message()
        failing_patterns[norm] += 1
        if norm not in failing_first_seen:
            failing_first_seen[norm] = entry

    all_patterns = set(baseline_patterns.keys()) | set(failing_patterns.keys())

    added_events = []
    missing_events = []
    frequency_changes = []

    for pattern in sorted(all_patterns):
        base_count = baseline_patterns.get(pattern, 0)
        fail_count = failing_patterns.get(pattern, 0)

        if base_count == 0 and fail_count > 0:
            entry = failing_first_seen[pattern]
            added_events.append(
                {
                    "severity": entry.severity or "INFO",
                    "normalized_pattern": pattern,
                    "first_occurrence_line": entry.line_number,
                    "count_in_failing": fail_count,
                    "sample": entry.raw_content,
                }
            )
        elif base_count > 0 and fail_count == 0:
            entry = baseline_first_seen[pattern]
            missing_events.append(
                {
                    "severity": entry.severity or "INFO",
                    "normalized_pattern": pattern,
                    "count_in_baseline": base_count,
                    "sample": entry.raw_content,
                }
            )
        elif base_count != fail_count:
            # Significant frequency divergence
            frequency_changes.append(
                {
                    "normalized_pattern": pattern,
                    "count_in_baseline": base_count,
                    "count_in_failing": fail_count,
                    "sample": failing_first_seen[pattern].raw_content,
                }
            )

    # Sort added events to put ERROR / CRITICAL first
    def severity_rank(item: Dict[str, Any]) -> int:
        sev = str(item.get("severity", "")).upper()
        if sev in ("CRITICAL", "FATAL"):
            return 0
        if sev in ("ERROR", "EXCEPTION", "SEVERE"):
            return 1
        if sev in ("WARN", "WARNING"):
            return 2
        return 3

    added_events.sort(key=severity_rank)

    return {
        "summary": {
            "baseline_total_lines": len(baseline_lines),
            "failing_total_lines": len(failing_lines),
            "added_events_count": len(added_events),
            "missing_events_count": len(missing_events),
            "frequency_changes_count": len(frequency_changes),
        },
        "added_events": added_events,
        "missing_events": missing_events,
        "frequency_changes": frequency_changes,
        "disclaimer": (
            "These differences represent observed event discrepancies between the baseline and failing runs. "
            "Discrepancies provide empirical evidence for investigation and do not independently prove direct causation. "
            "Inspect surrounding context and source code to confirm the root cause."
        ),
    }
