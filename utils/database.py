import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from werkzeug.security import check_password_hash, generate_password_hash

from utils.roles import normalize_admin_record, normalize_role, resolve_permissions


def read_json(path: Path, default: Any, logger: Optional[logging.Logger] = None) -> Any:
    if not path.exists():
        return default
    raw_content = path.read_text(encoding="utf-8").strip()
    if not raw_content:
        return default
    try:
        return json.loads(raw_content)
    except json.JSONDecodeError:
        backup_path = path.with_suffix(".corrupt")
        backup_path.write_text(raw_content, encoding="utf-8")
        if logger:
            logger.error("Invalid JSON in %s; copied to %s", path.name, backup_path.name)
        return default


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def ensure_admin_store(
    admins_file: Path,
    default_username: str,
    default_password: str,
    logger: Optional[logging.Logger] = None,
) -> None:
    """Create admin credential JSON if it does not exist."""

    if admins_file.exists():
        return

    default_admin = {
        "username": default_username,
        "password_hash": generate_password_hash(default_password),
        "created_at": datetime.utcnow().isoformat(),
        "role": "god",
        "permissions": ["*"],
    }
    if logger:
        logger.info("Creating default admin credentials for %s", default_username)
    write_json(admins_file, {"admins": [default_admin]})


def load_admins(
    admins_file: Path,
    logger: Optional[logging.Logger] = None,
) -> List[Dict[str, Any]]:
    """Return admin credential entries."""

    payload = read_json(admins_file, default={"admins": []}, logger=logger)
    admins: Any
    if isinstance(payload, dict):
        admins = payload.get("admins", [])
    else:
        admins = payload

    if not isinstance(admins, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for entry in admins:
        if not isinstance(entry, dict):
            continue
        if not entry.get("username"):
            continue
        normalized.append(normalize_admin_record(entry))
    return normalized


def authenticate_admin(admins: List[Dict[str, Any]], username: str, password: str) -> Optional[Dict[str, Any]]:
    for admin in admins:
        if admin.get("username") != username:
            continue
        password_hash = admin.get("password_hash")
        if password_hash and check_password_hash(password_hash, password):
            return admin
        plain_password = admin.get("password")
        if plain_password and plain_password == password:
            return admin
    return None


def save_admins(admins_file: Path, admins: List[Dict[str, Any]]) -> None:
    """Persist the provided admin records to disk."""
    sanitized: List[Dict[str, Any]] = []
    for admin in admins:
        record: Dict[str, Any] = dict(admin)
        role = normalize_role(record.get("role"))
        record["role"] = role

        record.pop("resolved_permissions", None)

        if role == "custom":
            custom_permissions = record.get("permissions")
            if isinstance(custom_permissions, list):
                record["permissions"] = resolve_permissions("custom", custom_permissions)
            else:
                record["permissions"] = []
        else:
            record.pop("permissions", None)

        sanitized.append(record)

    write_json(admins_file, {"admins": sanitized})
