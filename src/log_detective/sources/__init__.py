"""Log sources package for modular discovery and retrieval."""

from log_detective.sources.base import (
    BaseLogSource,
    LogSourceCapability,
    LogSourceMetadata,
    ReadLogsResult,
)
from log_detective.sources.docker import DockerLogSource
from log_detective.sources.local_file import LocalFileLogSource
from log_detective.sources.process import CapturedProcessLogSource
from log_detective.sources.registry import LogSourceRegistry, default_registry
from log_detective.sources.remote import RemoteApiLogSource

__all__ = [
    "BaseLogSource",
    "LogSourceCapability",
    "LogSourceMetadata",
    "ReadLogsResult",
    "LocalFileLogSource",
    "CapturedProcessLogSource",
    "DockerLogSource",
    "RemoteApiLogSource",
    "LogSourceRegistry",
    "default_registry",
]
