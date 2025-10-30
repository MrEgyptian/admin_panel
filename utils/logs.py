from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from utils.database import read_json, write_json

LogEntry = Dict[str, Any]


def load_logs(log_file: Path, logger: Optional[logging.Logger] = None) -> List[LogEntry]:
    data = read_json(log_file, default=[], logger=logger)
    if not isinstance(data, list):
        return []
    entries: List[LogEntry] = []
    for item in data:
        if isinstance(item, dict):
            entries.append(item)
    return entries


def save_logs(log_file: Path, entries: Iterable[LogEntry]) -> None:
    write_json(log_file, list(entries))


def append_log_entry(
    log_file: Path,
    *,
    username: Optional[str],
    exe_id: Optional[str],
    action: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
    priority: str = "info",
    source: str = "system",
    tag: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
) -> None:
    entry: LogEntry = {
        "id": uuid.uuid4().hex,
        "timestamp": datetime.utcnow().isoformat(),
        "username": username,
        "exe_id": exe_id,
        "action": action,
        "message": message,
        "metadata": metadata or {},
        "priority": priority,
        "source": source,
        "tag": tag,
    }

    entries = load_logs(log_file, logger=logger)
    entries.append(entry)
    save_logs(log_file, entries)


def filter_logs_by_username(entries: Iterable[LogEntry], username: str) -> List[LogEntry]:
    return [entry for entry in entries if entry.get("username") == username]


def filter_logs_by_exe(entries: Iterable[LogEntry], exe_id: str) -> List[LogEntry]:
    return [entry for entry in entries if entry.get("exe_id") == exe_id]
