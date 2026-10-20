"""Local file log source connector with path traversal and symlink guards."""

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

logger = logging.getLogger("log_detective.sources.local_file")


class LocalFileLogSource(BaseLogSource):
    """Log source connector for reading authorized local log files safely."""

    def __init__(
        self,
        source_id: str,
        name: str,
        file_path: Path | str,
        allowed_root: Optional[Path | str] = None,
        description: str = "Local application log file",
        encoding: str = "utf-8",
    ):
        super().__init__(source_id, name, description)
        self.raw_path = Path(file_path)
        self.allowed_root = Path(allowed_root).resolve() if allowed_root else self.raw_path.parent.resolve()
        self.encoding = encoding

    @property
    def source_type(self) -> str:
        return "local_file"

    @property
    def capabilities(self) -> List[LogSourceCapability]:
        return [
            LogSourceCapability.FILTER_SEVERITY,
            LogSourceCapability.FILTER_LIMIT,
            LogSourceCapability.FILTER_SEARCH,
            LogSourceCapability.TAIL,
        ]

    def _resolve_validated_path(self) -> Path:
        """Resolve the target path and ensure it does not escape allowed_root."""
        return validate_safe_path(self.raw_path, self.allowed_root)

    def get_metadata(self) -> LogSourceMetadata:
        """Return safe metadata without revealing the full internal system path."""
        safe_filename = self.raw_path.name
        is_avail = False
        status_msg = None

        try:
            target = self._resolve_validated_path()
            if target.is_file():
                is_avail = True
            else:
                status_msg = f"Log file '{safe_filename}' not found."
        except Exception as exc:
            status_msg = f"Security or access error: {exc}"

        return LogSourceMetadata(
            source_id=self.source_id,
            name=self.name,
            source_type=self.source_type,
            description=f"{self.description} ({safe_filename})",
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
        """Read and parse logs from the local file with bounded output and security checks."""
        target_path = self._resolve_validated_path()

        if not target_path.exists():
            raise FileNotFoundError(f"Log file for source '{self.source_id}' does not exist.")

        if not target_path.is_file():
            raise ValueError(f"Path for source '{self.source_id}' is not a regular file.")

        file_size = target_path.stat().st_size
        if file_size > MAX_LOG_SIZE_BYTES:
            logger.warning(
                "Source '%s' file size (%d bytes) exceeds safe limit (%d bytes). Reading bounded tail.",
                self.source_id,
                file_size,
                MAX_LOG_SIZE_BYTES,
            )

        try:
            with open(target_path, mode="r", encoding=self.encoding, errors="replace") as f:
                content = f.read(MAX_LOG_SIZE_BYTES)
        except PermissionError:
            raise PermissionError(f"Permission denied accessing log file for source '{self.source_id}'.")
        except Exception as exc:
            raise RuntimeError(f"Error reading log file for source '{self.source_id}': {exc}")

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
                stack_match = any(search_lower in s.lower() for s in entry.stack_trace)
                if not (msg_match or raw_match or stack_match):
                    continue

            filtered.append(entry)

        total_matched = len(filtered)
        bounded_entries = filtered[-limit:] if limit > 0 else filtered
        truncated = total_matched > len(bounded_entries)

        # Build raw text preserving full stack traces
        raw_lines: List[str] = []
        for e in bounded_entries:
            raw_lines.append(e.raw_content)
            raw_lines.extend(e.stack_trace)
        raw_text = "\n".join(raw_lines)

        metadata: Dict[str, Any] = {
            "file_name": target_path.name,
            "total_lines_read": len(all_entries),
            "file_size_bytes": file_size,
        }

        return ReadLogsResult(
            source_id=self.source_id,
            lines_returned=len(bounded_entries),
            total_matched=total_matched,
            truncated=truncated,
            entries=bounded_entries,
            raw_text=raw_text,
            metadata=metadata,
        )
