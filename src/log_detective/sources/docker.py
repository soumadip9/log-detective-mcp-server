"""Optional Docker container log connector with strict allowlisting and bounded retrieval."""

import logging
from typing import Any, Dict, List, Optional

from log_detective.parsers import LogEntry, matches_severity, parse_log_text
from log_detective.security import redact_secrets
from log_detective.sources.base import (
    BaseLogSource,
    LogSourceCapability,
    LogSourceMetadata,
    ReadLogsResult,
)

logger = logging.getLogger("log_detective.sources.docker")


class DockerLogSource(BaseLogSource):
    """Log source connector for reading logs from an explicitly allowlisted Docker container."""

    def __init__(
        self,
        source_id: str,
        name: str,
        container_name_or_id: str,
        allowlisted_containers: Optional[List[str]] = None,
        description: str = "Docker container logs",
        docker_client: Optional[Any] = None,
    ):
        super().__init__(source_id, name, description)
        self.container_identifier = container_name_or_id
        # Container must be in explicitly permitted allowlist
        self.allowlisted = set(allowlisted_containers) if allowlisted_containers else {container_name_or_id}
        self._custom_docker_client = docker_client

    @property
    def source_type(self) -> str:
        return "docker"

    @property
    def capabilities(self) -> List[LogSourceCapability]:
        return [
            LogSourceCapability.FILTER_SEVERITY,
            LogSourceCapability.FILTER_LIMIT,
            LogSourceCapability.FILTER_SEARCH,
            LogSourceCapability.FILTER_TIME_RANGE,
            LogSourceCapability.TAIL,
        ]

    def _get_docker_client(self) -> Any:
        """Lazily initialize the Docker SDK client or use injected mock."""
        if self._custom_docker_client is not None:
            return self._custom_docker_client

        try:
            import docker
            return docker.from_env()
        except ImportError:
            raise ImportError(
                "The 'docker' Python package is not installed. "
                "Install it with 'pip install docker' to enable Docker log sources."
            )

    def _verify_allowlisted(self) -> None:
        """Verify that the target container is present in the permitted allowlist."""
        if self.container_identifier not in self.allowlisted:
            raise PermissionError(
                f"Container '{self.container_identifier}' is not in the permitted Docker allowlist for source '{self.source_id}'."
            )

    def get_metadata(self) -> LogSourceMetadata:
        is_avail = False
        status_msg = None
        try:
            self._verify_allowlisted()
            client = self._get_docker_client()
            container = client.containers.get(self.container_identifier)
            is_avail = container.status in ("running", "restarting", "exited")
            status_msg = f"Container status: {container.status}"
        except ImportError as exc:
            status_msg = str(exc)
        except Exception as exc:
            status_msg = f"Docker unavailable or container not found: {exc}"

        return LogSourceMetadata(
            source_id=self.source_id,
            name=self.name,
            source_type=self.source_type,
            description=f"{self.description} (container: {self.container_identifier})",
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
        self._verify_allowlisted()
        client = self._get_docker_client()

        try:
            container = client.containers.get(self.container_identifier)
        except Exception as exc:
            raise FileNotFoundError(f"Container '{self.container_identifier}' not found: {exc}")

        # Fetch bounded logs via docker SDK
        kwargs: Dict[str, Any] = {
            "stdout": True,
            "stderr": True,
            "tail": max(limit * 2, 200),  # Fetch enough lines to filter
        }
        if start_time:
            kwargs["since"] = start_time
        if end_time:
            kwargs["until"] = end_time

        try:
            raw_bytes = container.logs(**kwargs)
            if isinstance(raw_bytes, bytes):
                raw_log = raw_bytes.decode("utf-8", errors="replace")
            else:
                raw_log = str(raw_bytes)
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch logs from Docker container '{self.container_identifier}': {exc}")

        sanitized_content = redact_secrets(raw_log)
        all_entries = parse_log_text(sanitized_content, source_id=self.source_id)

        filtered: List[LogEntry] = []
        search_lower = search_term.lower() if search_term else None

        for entry in all_entries:
            if severity and not matches_severity(entry.severity, severity):
                continue
            if search_lower:
                if not (search_lower in entry.message.lower() or search_lower in entry.raw_content.lower()):
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
            metadata={"container": self.container_identifier},
        )
