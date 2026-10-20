"""Remote log API connector with strict URL allowlisting and SSRF protection."""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from log_detective.parsers import LogEntry, matches_severity, parse_log_text
from log_detective.security import redact_secrets
from log_detective.sources.base import (
    BaseLogSource,
    LogSourceCapability,
    LogSourceMetadata,
    ReadLogsResult,
)
from log_detective.validators import MAX_LOG_SIZE_BYTES

logger = logging.getLogger("log_detective.sources.remote")


class RemoteApiLogSource(BaseLogSource):
    """Connector for fetching logs from an authorized, allowlisted internal/remote HTTP log API."""

    def __init__(
        self,
        source_id: str,
        name: str,
        endpoint_url: str,
        allowed_domains: List[str],
        auth_header: Optional[str] = None,
        auth_token: Optional[str] = None,
        description: str = "Remote HTTP Log API",
        timeout_seconds: float = 10.0,
        http_client: Optional[httpx.Client] = None,
    ):
        super().__init__(source_id, name, description)
        self.endpoint_url = endpoint_url
        self.allowed_domains = {d.lower() for d in allowed_domains}
        self.auth_header = auth_header or "Authorization"
        self.auth_token = auth_token
        self.timeout_seconds = timeout_seconds
        self._custom_http_client = http_client

    @property
    def source_type(self) -> str:
        return "remote_api"

    @property
    def capabilities(self) -> List[LogSourceCapability]:
        return [
            LogSourceCapability.FILTER_SEVERITY,
            LogSourceCapability.FILTER_LIMIT,
            LogSourceCapability.FILTER_SEARCH,
        ]

    def _verify_safe_endpoint(self) -> None:
        """Verify URL scheme and domain to strictly prevent SSRF attacks."""
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme '{parsed.scheme}'; only http and https are allowed.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ValueError(f"Endpoint URL '{self.endpoint_url}' has no valid hostname.")

        # Check against allowed domain allowlist
        domain_match = any(
            hostname == allowed or hostname.endswith("." + allowed)
            for allowed in self.allowed_domains
        )
        if not domain_match:
            raise PermissionError(
                f"Endpoint host '{hostname}' is not in the permitted domain allowlist: {sorted(self.allowed_domains)}"
            )

    def get_metadata(self) -> LogSourceMetadata:
        is_avail = False
        status_msg = None
        try:
            self._verify_safe_endpoint()
            is_avail = True
        except Exception as exc:
            status_msg = str(exc)

        # Do not expose auth headers or tokens
        parsed = urlparse(self.endpoint_url)
        safe_endpoint = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"

        return LogSourceMetadata(
            source_id=self.source_id,
            name=self.name,
            source_type=self.source_type,
            description=f"{self.description} ({safe_endpoint})",
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
        self._verify_safe_endpoint()

        headers: Dict[str, str] = {}
        if self.auth_token:
            if self.auth_header.lower() == "authorization" and not self.auth_token.lower().startswith("bearer "):
                headers["Authorization"] = f"Bearer {self.auth_token}"
            else:
                headers[self.auth_header] = self.auth_token

        params: Dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        if search_term:
            params["query"] = search_term

        client = self._custom_http_client or httpx.Client(timeout=self.timeout_seconds)
        try:
            response = client.get(self.endpoint_url, headers=headers, params=params)
            response.raise_for_status()
            text_content = response.text
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Remote log API error {exc.response.status_code}: {exc.response.text[:200]}")
        except httpx.RequestError as exc:
            raise RuntimeError(f"Failed to connect to remote log API: {exc}")
        finally:
            if self._custom_http_client is None:
                client.close()

        if len(text_content.encode("utf-8")) > MAX_LOG_SIZE_BYTES:
            text_content = text_content[:MAX_LOG_SIZE_BYTES]

        sanitized_content = redact_secrets(text_content)
        all_entries = parse_log_text(sanitized_content, source_id=self.source_id)

        bounded_entries = all_entries[-limit:] if limit > 0 else all_entries
        truncated = len(all_entries) > len(bounded_entries)
        raw_text = "\n".join(e.raw_content for e in bounded_entries)

        return ReadLogsResult(
            source_id=self.source_id,
            lines_returned=len(bounded_entries),
            total_matched=len(all_entries),
            truncated=truncated,
            entries=bounded_entries,
            raw_text=raw_text,
            metadata={"endpoint_host": urlparse(self.endpoint_url).hostname},
        )
