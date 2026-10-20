"""Central registry for discovering, configuring, and accessing log sources."""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from log_detective.sources.base import BaseLogSource, LogSourceMetadata
from log_detective.sources.docker import DockerLogSource
from log_detective.sources.local_file import LocalFileLogSource
from log_detective.sources.process import CapturedProcessLogSource
from log_detective.sources.remote import RemoteApiLogSource

logger = logging.getLogger("log_detective.sources.registry")


class LogSourceRegistry:
    """Registry that manages configured log sources and enforces safe access."""

    def __init__(self) -> None:
        self._sources: Dict[str, BaseLogSource] = {}

    def register_source(self, source: BaseLogSource) -> None:
        """Register a new log source connector."""
        if not source.source_id:
            raise ValueError("Log source must have a non-empty source_id.")
        self._sources[source.source_id] = source
        logger.info("Registered log source '%s' (type: %s)", source.source_id, source.source_type)

    def unregister_source(self, source_id: str) -> None:
        """Unregister a log source."""
        self._sources.pop(source_id, None)

    def get_source(self, source_id: str) -> BaseLogSource:
        """Retrieve a registered log source by ID.

        Raises:
            KeyError: If source_id is not registered.
        """
        if source_id not in self._sources:
            available = list(self._sources.keys())
            raise KeyError(
                f"Log source '{source_id}' is not configured. Available sources: {available if available else 'None'}."
            )
        return self._sources[source_id]

    def list_sources(self) -> List[LogSourceMetadata]:
        """Return safe, non-sensitive metadata for all registered sources."""
        results: List[LogSourceMetadata] = []
        for source in self._sources.values():
            try:
                results.append(source.get_metadata())
            except Exception as exc:
                logger.warning("Error fetching metadata for source '%s': %s", source.source_id, exc)
                results.append(
                    LogSourceMetadata(
                        source_id=source.source_id,
                        name=source.name,
                        source_type=source.source_type,
                        description=source.description,
                        capabilities=[c.value for c in source.capabilities],
                        is_available=False,
                        status_message=f"Metadata error: {exc}",
                    )
                )
        return results

    def load_from_config(self, config_data: dict, base_dir: Optional[Path] = None) -> None:
        """Load sources from a structured dictionary.

        Format:
        {
          "sources": [
            {
              "type": "local_file",
              "source_id": "app-logs",
              "name": "App Logs",
              "path": "logs/app.log",
              "allowed_root": "logs/"
            }
          ]
        }
        """
        root_dir = (base_dir or Path.cwd()).resolve()
        sources_list = config_data.get("sources", [])

        for item in sources_list:
            source_type = item.get("type", "local_file")
            source_id = item.get("source_id")
            name = item.get("name", source_id)
            description = item.get("description", "")

            if not source_id:
                logger.warning("Skipping source definition without 'source_id': %s", item)
                continue

            try:
                if source_type == "local_file":
                    raw_path = Path(item["path"])
                    file_path = raw_path if raw_path.is_absolute() else (root_dir / raw_path).resolve()
                    allowed_root_raw = item.get("allowed_root")
                    if allowed_root_raw:
                        p = Path(allowed_root_raw)
                        allowed_root = p if p.is_absolute() else (root_dir / p).resolve()
                    else:
                        allowed_root = file_path.parent

                    source = LocalFileLogSource(
                        source_id=source_id,
                        name=name,
                        file_path=file_path,
                        allowed_root=allowed_root,
                        description=description or f"Local file log: {file_path.name}",
                    )
                    self.register_source(source)

                elif source_type == "captured_process":
                    raw_spool = Path(item["spool_file"])
                    spool_path = raw_spool if raw_spool.is_absolute() else (root_dir / raw_spool).resolve()
                    allowed_root = (root_dir / item.get("allowed_root", "")).resolve() if item.get("allowed_root") else spool_path.parent
                    source = CapturedProcessLogSource(
                        source_id=source_id,
                        name=name,
                        spool_file_path=spool_path,
                        process_name=item.get("process_name"),
                        allowed_root=allowed_root,
                        description=description or "Captured process log",
                    )
                    self.register_source(source)

                elif source_type == "docker":
                    source = DockerLogSource(
                        source_id=source_id,
                        name=name,
                        container_name_or_id=item["container"],
                        allowlisted_containers=item.get("allowlisted_containers"),
                        description=description or f"Docker logs: {item['container']}",
                    )
                    self.register_source(source)

                elif source_type == "remote_api":
                    source = RemoteApiLogSource(
                        source_id=source_id,
                        name=name,
                        endpoint_url=item["endpoint_url"],
                        allowed_domains=item.get("allowed_domains", []),
                        auth_header=item.get("auth_header"),
                        auth_token=item.get("auth_token"),
                        description=description or "Remote log API",
                    )
                    self.register_source(source)
                else:
                    logger.warning("Unknown source type '%s' for source '%s'", source_type, source_id)
            except Exception as exc:
                logger.error("Failed to initialize source '%s': %s", source_id, exc)

    def load_from_file(self, config_path: Path) -> bool:
        """Load source configurations from a JSON file."""
        if not config_path.exists():
            return False

        try:
            with open(config_path, mode="r", encoding="utf-8") as f:
                data = json.load(f)
            self.load_from_config(data, base_dir=config_path.parent)
            logger.info("Loaded log sources configuration from %s", config_path)
            return True
        except Exception as exc:
            logger.error("Failed reading source config file %s: %s", config_path, exc)
            return False

    def load_from_environment(self, workspace_root: Optional[Path] = None) -> None:
        """Load sources from environment variables or default locations."""
        root = (workspace_root or Path.cwd()).resolve()

        # 1. Custom JSON config path from environment
        env_config = os.environ.get("LOG_DETECTIVE_SOURCES_CONFIG")
        if env_config:
            p = Path(env_config)
            cfg_path = p if p.is_absolute() else (root / p).resolve()
            self.load_from_file(cfg_path)

        # 2. Default workspace sources.json if present
        default_file = root / "sources.json"
        if default_file.exists():
            self.load_from_file(default_file)

        # 3. Simple single-file log configuration via environment variable
        env_log_file = os.environ.get("LOG_DETECTIVE_LOG_FILE")
        if env_log_file:
            target = Path(env_log_file)
            f_path = target if target.is_absolute() else (root / target).resolve()
            source = LocalFileLogSource(
                source_id="app-log",
                name="Application Log",
                file_path=f_path,
                allowed_root=f_path.parent,
                description=f"Configured application log file ({f_path.name})",
            )
            self.register_source(source)


# Global default registry instance
default_registry = LogSourceRegistry()
