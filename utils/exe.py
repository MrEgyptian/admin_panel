import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.database import read_json, write_json
from utils.exe_types import TypeDefinition
from utils.time import format_timestamp, humanize_timestamp, parse_iso_datetime


_TIMESTAMP_ENV_NAMES = ("CURSOR_TIMESTAMP_URL", "BACKUP_TIMESTAMP_URL")
_FILE_ID_ENV_NAMES = ("CURSOR_FILE_ID", "BACKUP_FILE_ID")
_TIMESTAMP_PROMPT_STRINGS = (
	"Set CURSOR_TIMESTAMP_URL to use this utility.",
	"Set BACKUP_TIMESTAMP_URL to use this utility.",
)


_FILE_ID_SANITIZER = re.compile(r"[^a-z0-9_-]+")


def _sanitize_file_id(raw: Optional[str], fallback: str) -> str:
	if not raw:
		return fallback
	candidate = _FILE_ID_SANITIZER.sub("-", str(raw).strip().lower())
	candidate = candidate.strip("-_")
	return candidate or fallback


def sanitize_file_id(raw: Optional[str], fallback: str) -> str:
	return _sanitize_file_id(raw, fallback)


def _replace_env_lookup(source: str, env_name: str, value: str) -> str:
	pattern = re.compile(
		rf"os\.environ\.get\(\s*[\"\']{re.escape(env_name)}[\"\']\s*(?:,\s*[\"\'].*?[\"\']\s*)?\)"
	)
	replacement = json.dumps(value)
	return pattern.sub(replacement, source)


def _find_type_definition(exe_type: str, definitions: List[TypeDefinition]) -> Optional[TypeDefinition]:
	for definition in definitions:
		name = str(definition.get("name", "")).strip()
		if name.lower() == exe_type.lower():
			return definition
	return None


def generate_executable(
	directory: Path,
	exe_id: str,
	name: str,
	exe_type: str,
	metadata: Dict[str, Any],
	template_dir: Path,
	type_definitions: List[TypeDefinition],
	logger: Optional[logging.Logger] = None,
) -> str:
	"""Compile a template-driven executable using PyInstaller.

	Args:
		directory: Destination directory for compiled executables.
		exe_id: Unique identifier for the executable.
		name: Friendly name supplied by the user.
		exe_type: Executable type selected by the user.
		metadata: Snapshot of the executable metadata for optional embedding.
		template_dir: Directory containing Python template files.
		type_definitions: Collection of configured type definitions.
		logger: Optional logger for diagnostic messages.

	Returns:
		The file name of the generated executable.

	Raises:
		RuntimeError: When the build process fails or prerequisites are missing.
		ValueError: When the requested type cannot be resolved.
	"""

	directory = Path(directory)
	template_dir = Path(template_dir)
	script_path = Path(__file__).resolve().parent.parent / "scripts" / "build_executable.py"
	if not script_path.exists():
		raise FileNotFoundError("Build script is missing. Ensure 'scripts/build_executable.py' exists.")
	definition = _find_type_definition(exe_type, type_definitions)
	if not definition:
		raise ValueError(f"Executable type '{exe_type}' is not defined.")

	template_name = str(definition.get("template", "")).strip()
	if not template_name:
		raise ValueError(f"Executable type '{exe_type}' does not have a template assigned.")

	template_path = template_dir / template_name
	if not template_path.exists():
		raise FileNotFoundError(f"Template '{template_name}' not found in {template_dir}.")

	directory.mkdir(parents=True, exist_ok=True)
	output_path = directory / f"{exe_id}.exe"
	if output_path.exists():
		output_path.unlink()

	file_id_value = _sanitize_file_id(metadata.get("file_id"), exe_id)
	metadata["file_id"] = file_id_value

	build_metadata = {
		"id": exe_id,
		"name": name,
		"type": exe_type,
		"template": template_name,
		"generated_at": datetime.utcnow().isoformat() + "Z",
		"metadata": metadata,
		"file_id": file_id_value,
	}

	log = logger.debug if logger else lambda *_args, **_kwargs: None
	log("Compiling executable", extra={"exe_id": exe_id, "template": template_name})

	with tempfile.TemporaryDirectory(prefix=f"build_{exe_id}_") as tmp_dir:
		tmp_path = Path(tmp_dir)
		source_path = tmp_path / f"{file_id_value}.py"
		shutil.copy2(template_path, source_path)

		template_text = source_path.read_text(encoding="utf-8", errors="replace")
		requires_server_url = any(name in template_text for name in _TIMESTAMP_ENV_NAMES)
		server_url_value = metadata.get("server_url")
		if requires_server_url and not server_url_value:
			raise ValueError("Server URL is required for templates referencing the timestamp API.")

		patched_text = template_text
		if server_url_value:
			for env_name in _TIMESTAMP_ENV_NAMES:
				patched_text = _replace_env_lookup(patched_text, env_name, str(server_url_value))
			for prompt in _TIMESTAMP_PROMPT_STRINGS:
				patched_text = patched_text.replace(prompt, "Timestamp API URL is not configured.")
		for env_name in _FILE_ID_ENV_NAMES:
			patched_text = _replace_env_lookup(patched_text, env_name, file_id_value)
		for env_name in _FILE_ID_ENV_NAMES:
			patched_text = patched_text.replace(env_name, "FILE_ID")
		source_path.write_text(patched_text, encoding="utf-8")

		metadata_path = tmp_path / "build_metadata.json"
		metadata_path.write_text(json.dumps(build_metadata, indent=2, default=str), encoding="utf-8")

		context = {
			"source": str(source_path),
			"exe_name": exe_id,
			"dist_path": str(directory),
			"work_path": str(tmp_path / "build"),
			"spec_path": str(tmp_path / "spec"),
			"metadata_path": str(metadata_path),
		}
		context_path = tmp_path / "build_context.json"
		context_path.write_text(json.dumps(context, indent=2), encoding="utf-8")

		log("Running external build script", extra={"exe_id": exe_id, "script": str(script_path)})

		env = os.environ.copy()
		env.setdefault("PYINSTALLER_DISABLE_ISOLATED_MODE", "1")
		if requires_server_url and server_url_value:
			env["CURSOR_TIMESTAMP_URL"] = server_url_value
			env["BACKUP_TIMESTAMP_URL"] = server_url_value
		cmd = [sys.executable, str(script_path), "--context", str(context_path)]
		result = subprocess.run(cmd, capture_output=True, text=True, env=env)
		if result.returncode != 0:
			error_output = (result.stderr or "").strip() or (result.stdout or "").strip()
			raise RuntimeError(
				f"Build script exited with status {result.returncode}: {error_output or 'no output captured.'}"
			)

	if not output_path.exists():
		raise RuntimeError(f"Expected executable '{output_path.name}' was not created.")

	log("Executable compiled", extra={"exe_id": exe_id, "output": str(output_path)})
	return output_path.name


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
	now = datetime.utcnow()
	available_at = parse_iso_datetime(executable.get("available_from"))
	expires_at = parse_iso_datetime(executable.get("expiry_date"))

	status_label = "Active"
	if executable.get("revoked"):
		status_label = "Revoked"
	elif expires_at and expires_at <= now:
		status_label = "Expired"
	elif available_at and available_at > now:
		status_label = "Scheduled"

	remaining_days: Optional[int] = None
	if expires_at:
		delta = expires_at - now
		remaining_days = max(0, int(delta.total_seconds() // 86400))

	ready_date = format_timestamp(available_at) if available_at else None
	available_display = f"{humanize_timestamp(available_at)} UTC" if available_at else None
	expiry_display = f"{humanize_timestamp(expires_at)} UTC" if expires_at else None

	return {
		**executable,
		"status_label": status_label,
		"days_remaining": remaining_days,
		"ready_date": ready_date,
		"available_from_display": available_display,
		"expiry_date_display": expiry_display,
	}

