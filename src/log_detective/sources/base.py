"""Abstract base classes and data models for modular log sources."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from log_detective.parsers import LogEntry


class LogSourceCapability(str, Enum):
    """Capabilities supported by a log source."""

    FILTER_SEVERITY = "filter_severity"
    FILTER_LIMIT = "filter_limit"
    FILTER_SEARCH = "filter_search"
    FILTER_TIME_RANGE = "filter_time_range"
    TAIL = "tail"


@dataclass
class LogSourceMetadata:
    """Safe, non-sensitive metadata for describing a log source to MCP clients."""

    source_id: str
    name: str
    source_type: str  # "local_file", "captured_process", "docker", "remote_api"
    description: str
    capabilities: List[str]
    is_available: bool = True
    status_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to safe dictionary (never reveals private paths or credentials)."""
        data: Dict[str, Any] = {
            "source_id": self.source_id,
            "name": self.name,
            "type": self.source_type,
            "description": self.description,
            "capabilities": self.capabilities,
            "is_available": self.is_available,
        }
        if self.status_message:
            data["status_message"] = self.status_message
        return data


@dataclass
class ReadLogsResult:
    """Structured result returned from reading logs from any source."""

    source_id: str
    lines_returned: int
    total_matched: int
    truncated: bool
    entries: List[LogEntry]
    raw_text: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for MCP response."""
        return {
            "source_id": self.source_id,
            "lines_returned": self.lines_returned,
            "total_matched": self.total_matched,
            "truncated": self.truncated,
            "entries": [entry.to_dict() for entry in self.entries],
            "raw_text": self.raw_text,
            "metadata": self.metadata,
        }


class BaseLogSource(ABC):
    """Abstract interface that every log source connector must implement."""

    def __init__(self, source_id: str, name: str, description: str):
        self.source_id = source_id
        self.name = name
        self.description = description

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Return the source type identifier (e.g. 'local_file')."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> List[LogSourceCapability]:
        """Return the capabilities supported by this source."""
        pass

    @abstractmethod
    def get_metadata(self) -> LogSourceMetadata:
        """Return safe, non-sensitive metadata describing this source."""
        pass

    @abstractmethod
    def read_logs(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        search_term: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> ReadLogsResult:
        """Read logs from the source with bounded output and supported filters.

        Raises:
            FileNotFoundError: If the underlying source resource is missing.
            PermissionError: If access is denied by permission or allowlist.
            ValueError: If parameters are invalid or bounds are violated.
        """
        pass
