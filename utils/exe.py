import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.database import read_json, write_json
from utils.time import parse_iso_date


def generate_stub_executable(
	directory: Path,
	exe_id: str,
	name: str,
	exe_type: str,
	metadata: Dict[str, Optional[str]],
) -> str:
	file_path = directory / f"{exe_id}.exe"
	stub_content = (
		"Executable Stub File\n"
		f"Generated: {datetime.utcnow().isoformat()}Z\n"
		f"Name: {name}\n"
		f"Type: {exe_type}\n"
		f"ID: {exe_id}\n"
		f"Server URL: {metadata.get('server_url') or 'not set'}\n"
		f"Available From: {metadata.get('available_from') or 'immediately'}\n"
		f"Expires On: {metadata.get('expiry_date') or 'no expiry'}\n"
		f"Status: {metadata.get('status_label', 'unknown')}\n"
	)
	file_path.write_text(stub_content, encoding="utf-8")
	return file_path.name


def load_executables(
	data_file: Path,
	logger: Optional[logging.Logger] = None,
) -> List[Dict[str, Any]]:
	"""Return the executable metadata stored on disk."""

	data = read_json(data_file, default=[], logger=logger)
	if isinstance(data, list):
		return [item for item in data if isinstance(item, dict)]
	return []


def save_executables(data_file: Path, executables: List[Dict[str, Any]]) -> None:
	write_json(data_file, executables)


def compute_status(executable: Dict[str, Any]) -> Dict[str, Any]:
	today = datetime.utcnow().date()
	available_at = parse_iso_date(executable.get("available_from"))
	expires_at = parse_iso_date(executable.get("expiry_date"))

	status_label = "Active"
	if executable.get("revoked"):
		status_label = "Revoked"
	elif expires_at and expires_at < today:
		status_label = "Expired"
	elif available_at and available_at > today:
		status_label = "Scheduled"

	remaining_days: Optional[int] = None
	if expires_at:
		remaining_days = (expires_at - today).days

	ready_date = available_at.isoformat() if available_at else None

	return {
		**executable,
		"status_label": status_label,
		"days_remaining": remaining_days,
		"ready_date": ready_date,
	}

