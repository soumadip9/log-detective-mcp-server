"""Captured process logs connector for stdout/stderr redirected to spool files."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from log_detective.parsers import LogEntry, matches_severity, parse_log_text
from log_detective.security import redact_secrets, validate_safe_path
from log_detective.sources.base import (
    BaseLogSource,
    LogSourceCapability,
    LogSourceMetadata,
    ReadLogsResult,
)
from log_detective.validators import MAX_LOG_SIZE_BYTES

logger = logging.getLogger("log_detective.sources.process")


class CapturedProcessLogSource(BaseLogSource):
    """Connector for reading stdout/stderr captured from external processes into a file/spool.

    Security & Architectural Design:
    - This connector explicitly does NOT execute arbitrary shell commands or attempt
      unsafe inspection of other OS terminal memory.
    - Application processes must redirect or pipe their output to a designated log spool
      file (e.g. `python app.py > /var/log/app.stdout.log 2>&1` or via process supervisor).
    """

    def __init__(
        self,
        source_id: str,
        name: str,
        spool_file_path: Path | str,
        process_name: Optional[str] = None,
        allowed_root: Optional[Path | str] = None,
        description: str = "Captured process stdout/stderr output",
    ):
        super().__init__(source_id, name, description)
        self.raw_path = Path(spool_file_path)
        self.process_name = process_name or name
        self.allowed_root = Path(allowed_root).resolve() if allowed_root else self.raw_path.parent.resolve()

    @property
    def source_type(self) -> str:
        return "captured_process"

    @property
    def capabilities(self) -> List[LogSourceCapability]:
        return [
            LogSourceCapability.FILTER_SEVERITY,
            LogSourceCapability.FILTER_LIMIT,
            LogSourceCapability.FILTER_SEARCH,
            LogSourceCapability.TAIL,
        ]

    def _resolve_validated_path(self) -> Path:
        return validate_safe_path(self.raw_path, self.allowed_root)

    def get_metadata(self) -> LogSourceMetadata:
        is_avail = False
        status_msg = None
        try:
            target = self._resolve_validated_path()
            if target.is_file():
                is_avail = True
            else:
                status_msg = f"Process output spool '{target.name}' not found."
        except Exception as exc:
            status_msg = f"Security/access check failed: {exc}"

        return LogSourceMetadata(
            source_id=self.source_id,
            name=self.name,
            source_type=self.source_type,
            description=f"{self.description} (process: {self.process_name})",
            capabilities=[cap.value for cap in self.capabilities],
            is_available=is_avail,
            status_message=status_msg,
        )

    def read_logs(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        search_term: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> ReadLogsResult:
        target_path = self._resolve_validated_path()
        if not target_path.exists():
            raise FileNotFoundError(f"Spool file for process source '{self.source_id}' does not exist.")

        try:
            with open(target_path, mode="r", encoding="utf-8", errors="replace") as f:
                content = f.read(MAX_LOG_SIZE_BYTES)
        except PermissionError:
            raise PermissionError(f"Permission denied reading spool for source '{self.source_id}'.")

        sanitized_content = redact_secrets(content)
        all_entries = parse_log_text(sanitized_content, source_id=self.source_id)

        filtered: List[LogEntry] = []
        search_lower = search_term.lower() if search_term else None

        for entry in all_entries:
            if severity and not matches_severity(entry.severity, severity):
                continue
            if search_lower:
                msg_match = search_lower in entry.message.lower()
                raw_match = search_lower in entry.raw_content.lower()
                if not (msg_match or raw_match):
                    continue
            filtered.append(entry)

        total_matched = len(filtered)
        bounded_entries = filtered[-limit:] if limit > 0 else filtered
        truncated = total_matched > len(bounded_entries)
        raw_text = "\n".join(e.raw_content for e in bounded_entries)

        return ReadLogsResult(
            source_id=self.source_id,
            lines_returned=len(bounded_entries),
            total_matched=total_matched,
            truncated=truncated,
            entries=bounded_entries,
            raw_text=raw_text,
            metadata={
                "process_name": self.process_name,
                "spool_file": target_path.name,
            },
        )
