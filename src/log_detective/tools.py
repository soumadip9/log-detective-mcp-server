"""Implementation of the Log Detective MCP tools (discovery, retrieval, and analysis)."""

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from log_detective.parsers import (
    LogEntry,
    matches_severity,
    normalize_log_line,
    parse_log_text,
)
from log_detective.sources.registry import LogSourceRegistry, default_registry
from log_detective.validators import (
    validate_context_size,
    validate_limit,
    validate_log_text,
    validate_severity,
    validate_target_line,
)


def _resolve_log_text(
    log_text: Optional[str],
    source_id: Optional[str],
    field_name: str = "log_text",
    registry: Optional[LogSourceRegistry] = None,
) -> Tuple[str, Optional[str]]:
    """Helper to obtain log text either from direct argument or configured source ID."""
    if isinstance(log_text, str) and len(log_text.strip()) > 0:
        return validate_log_text(log_text, field_name), None

    if source_id is not None and len(source_id.strip()) > 0:
        reg = registry or default_registry
        source = reg.get_source(source_id.strip())
        res = source.read_logs(limit=2000)
        return validate_log_text(res.raw_text, f"source:{source_id}"), source_id.strip()

    if log_text == "":
        return "", None

    raise ValueError(f"Either '{field_name}' or 'source_id' must be provided.")


def list_log_sources(registry: Optional[LogSourceRegistry] = None) -> Dict[str, Any]:
    """List all configured log sources available to the MCP client."""
    reg = registry or default_registry
    sources = reg.list_sources()
    return {
        "count": len(sources),
        "sources": [s.to_dict() for s in sources],
    }


def read_logs(
    source_id: str,
    limit: int = 100,
    severity: Optional[str] = None,
    search_term: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    registry: Optional[LogSourceRegistry] = None,
) -> Dict[str, Any]:
    """Read logs from a configured log source with bounded limits and optional filters."""
    if not source_id or not isinstance(source_id, str):
        raise TypeError("'source_id' must be a non-empty string.")

    valid_limit = validate_limit(limit, default=100, max_limit=200)
    valid_sev = validate_severity(severity) if severity else None

    reg = registry or default_registry
    source = reg.get_source(source_id.strip())

    result = source.read_logs(
        limit=valid_limit,
        severity=valid_sev,
        search_term=search_term,
        start_time=start_time,
        end_time=end_time,
    )

    return result.to_dict()


def find_errors(
    log_text: Optional[str] = None,
    source_id: Optional[str] = None,
    severity: Optional[str] = "ERROR",
    limit: Optional[int] = 50,
    registry: Optional[LogSourceRegistry] = None,
) -> Dict[str, Any]:
    """Scan log text or a configured log source for error events, line numbers, and stack traces."""
    valid_text, resolved_source = _resolve_log_text(log_text, source_id, "log_text", registry)
    valid_sev = validate_severity(severity)
    valid_limit = validate_limit(limit)

    raw_lines = valid_text.splitlines()
    total_lines = len(raw_lines)
    if total_lines == 0:
        return {
            "source_id": resolved_source,
            "total_lines": 0,
            "matching_count": 0,
            "returned_count": 0,
            "truncated": False,
            "severity_filter": valid_sev,
            "errors": [],
        }

    entries = parse_log_text(valid_text, source_id=resolved_source)
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
        if entry.component:
            item["component"] = entry.component
        if entry.request_id:
            item["request_id"] = entry.request_id
        if entry.stack_trace:
            item["stack_trace"] = entry.stack_trace
        if entry.is_json and entry.parsed_json:
            item["is_json"] = True
        results.append(item)

    resp: Dict[str, Any] = {
        "total_lines": total_lines,
        "matching_count": matching_count,
        "returned_count": len(results),
        "truncated": truncated,
        "severity_filter": valid_sev,
        "errors": results,
    }
    if resolved_source:
        resp["source_id"] = resolved_source
    return resp


def get_log_context(
    log_text: Optional[str | int] = None,
    target_line: Optional[int] = None,
    context_size: Optional[int] = 5,
    source_id: Optional[str] = None,
    registry: Optional[LogSourceRegistry] = None,
) -> Dict[str, Any]:
    """Retrieve surrounding lines of context before and after a specified target line.

    Supports both (log_text, target_line, context_size) and (target_line, source_id=...) signatures.
    """
    # Detect if target_line was passed as first positional parameter
    actual_log_text: Optional[str] = None
    actual_target_line: Optional[int] = target_line

    if isinstance(log_text, int) and target_line is None:
        actual_target_line = log_text
        actual_log_text = None
    elif isinstance(log_text, str):
        actual_log_text = log_text

    valid_text, resolved_source = _resolve_log_text(actual_log_text, source_id, "log_text", registry)
    raw_lines = valid_text.splitlines()
    total_lines = len(raw_lines)

    valid_line = validate_target_line(actual_target_line, total_lines)
    valid_size = validate_context_size(context_size)

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

    resp: Dict[str, Any] = {
        "target_line": valid_line,
        "context_size": valid_size,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "lines": context_lines,
        "formatted": "\n".join(formatted_rows),
    }
    if resolved_source:
        resp["source_id"] = resolved_source
    return resp


def compare_logs(
    baseline_log: Optional[str] = None,
    failing_log: Optional[str] = None,
    baseline_source_id: Optional[str] = None,
    failing_source_id: Optional[str] = None,
    registry: Optional[LogSourceRegistry] = None,
) -> Dict[str, Any]:
    """Compare a healthy/baseline execution against a failing execution."""
    valid_baseline, b_source = _resolve_log_text(baseline_log, baseline_source_id, "baseline_log", registry)
    valid_failing, f_source = _resolve_log_text(failing_log, failing_source_id, "failing_log", registry)

    baseline_lines = valid_baseline.splitlines()
    failing_lines = valid_failing.splitlines()

    baseline_entries = parse_log_text(valid_baseline, source_id=b_source)
    failing_entries = parse_log_text(valid_failing, source_id=f_source)

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
            frequency_changes.append(
                {
                    "normalized_pattern": pattern,
                    "count_in_baseline": base_count,
                    "count_in_failing": fail_count,
                    "sample": failing_first_seen[pattern].raw_content,
                }
            )

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

    summary: Dict[str, Any] = {
        "baseline_total_lines": len(baseline_lines),
        "failing_total_lines": len(failing_lines),
        "added_events_count": len(added_events),
        "missing_events_count": len(missing_events),
        "frequency_changes_count": len(frequency_changes),
    }
    if b_source or f_source:
        summary["baseline_source"] = b_source
        summary["failing_source"] = f_source

    return {
        "summary": summary,
        "added_events": added_events,
        "missing_events": missing_events,
        "frequency_changes": frequency_changes,
        "disclaimer": (
            "These differences represent observed event discrepancies between the baseline and failing runs. "
            "Discrepancies provide empirical evidence for investigation and do not independently prove direct causation. "
            "Inspect surrounding context and source code to confirm the root cause."
        ),
    }
