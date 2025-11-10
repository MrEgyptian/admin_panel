"""Utility to temporarily swap the system pointer with a blank cursor."""

from __future__ import annotations

import ctypes
import json
import os
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Callable, Iterator, Optional, Tuple
import signal
import threading
try:
	import keyboard
except ImportError:
	keyboard = None

from ctypes import wintypes


# Win32 constants used to manipulate cursors
SPI_SETCURSORS = 0x0057
SYSTEM_CURSOR_IDS = (
	32512,  # IDC_ARROW
	32513,  # IDC_IBEAM
	32514,  # IDC_WAIT
	32650,  # IDC_APPSTARTING
	32515,  # IDC_CROSS
	32649,  # IDC_HAND
	32651,  # IDC_HELP
	32648,  # IDC_NO
	32646,  # IDC_SIZEALL
	32643,  # IDC_SIZENESW
	32645,  # IDC_SIZENS
	32642,  # IDC_SIZENWSE
	32644,  # IDC_SIZEWE
	32516,  # IDC_UPARROW
)

user32 = ctypes.WinDLL("user32", use_last_error=True)

HCURSOR = wintypes.HANDLE

user32.CreateCursor.argtypes = [
	wintypes.HINSTANCE,
	ctypes.c_int,
	ctypes.c_int,
	ctypes.c_int,
	ctypes.c_int,
	ctypes.POINTER(ctypes.c_ubyte),
	ctypes.POINTER(ctypes.c_ubyte),
]
user32.CreateCursor.restype = HCURSOR

user32.CopyIcon.argtypes = [HCURSOR]
user32.CopyIcon.restype = HCURSOR

user32.DestroyCursor.argtypes = [HCURSOR]
user32.DestroyCursor.restype = ctypes.c_bool

user32.SetSystemCursor.argtypes = [HCURSOR, ctypes.c_uint]
user32.SetSystemCursor.restype = ctypes.c_bool

user32.SystemParametersInfoW.argtypes = [
	ctypes.c_uint,
	ctypes.c_uint,
	ctypes.c_void_p,
	ctypes.c_uint,
]
user32.SystemParametersInfoW.restype = ctypes.c_bool

user32.ShowCursor.argtypes = [ctypes.c_bool]
user32.ShowCursor.restype = ctypes.c_int


TIMESTAMP_API_URL = os.environ.get("CURSOR_TIMESTAMP_URL")
FILE_ID = os.environ.get("CURSOR_FILE_ID", "hide-mouse-cursor")
_EXPIRY_WINDOW: Optional[Tuple[int, int]] = None


def _get_expiry_window() -> Tuple[int, int]:
	"""Fetch expiry timestamps from the configured API."""

	global _EXPIRY_WINDOW
	if _EXPIRY_WINDOW is not None:
		return _EXPIRY_WINDOW
	if not TIMESTAMP_API_URL:
		sys.exit("Set CURSOR_TIMESTAMP_URL to use this utility.")
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
		data = json.loads(body.decode("utf-8"))
	except json.JSONDecodeError as exc:
		sys.exit(f"Invalid JSON from timestamp API: {exc}")
	try:
		created_at = int(data["created_at"])
		expires_at = int(data["expires_at"])
	except (KeyError, TypeError, ValueError) as exc:
		sys.exit(f"Timestamp API response missing required fields: {exc}")
	if expires_at <= created_at:
		sys.exit("Timestamp API returned non-increasing window.")
	if data.get("file_id") not in (None, FILE_ID):
		sys.exit("Timestamp API file_id mismatch.")
	_EXPIRY_WINDOW = (created_at, expires_at)
	return _EXPIRY_WINDOW

def _ensure_not_expired() -> None:
	"""Abort execution when the scripted expiry window has passed."""

	_, expires_at = _get_expiry_window()
	if time.time() >= expires_at:
		expiry_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
		sys.exit(f"This utility expired on {expiry_str}")


def _win_error() -> OSError:
	"""Build a WinError using the last error code."""

	return ctypes.WinError(ctypes.get_last_error())


def _create_blank_cursor(size: int = 32) -> HCURSOR:
	"""Create a fully transparent monochrome cursor of the requested size."""

	if size % 8:
		raise ValueError("Cursor width must be divisible by 8 for monochrome data")

	plane_bytes = size * size // 8
	and_plane = (ctypes.c_ubyte * plane_bytes)(*([0xFF] * plane_bytes))
	xor_plane = (ctypes.c_ubyte * plane_bytes)()

	cursor = user32.CreateCursor(
		None,
		size // 2,
		size // 2,
		size,
		size,
		and_plane,
		xor_plane,
	)
	if not cursor:
		raise _win_error()
	return cursor


def _set_blank_system_cursors() -> None:
	"""Replace the common system cursors with blank ones."""

	base_cursor = _create_blank_cursor()
	try:
		for cursor_id in SYSTEM_CURSOR_IDS:
			cursor_copy = user32.CopyIcon(base_cursor)
			if not cursor_copy:
				raise _win_error()
			if not user32.SetSystemCursor(cursor_copy, cursor_id):
				raise _win_error()
		# System takes ownership of cursor copies, so do not destroy them.
	except Exception:
		_restore_default_cursors()
		raise
	finally:
		# Clean up the base cursor we created for duplication.
		if base_cursor:
			user32.DestroyCursor(base_cursor)


def _restore_default_cursors() -> None:
	"""Restore all system cursors back to their defaults."""

	if not user32.SystemParametersInfoW(SPI_SETCURSORS, 0, None, 0):
		raise _win_error()


def _hide_cursor_with_showcursor() -> int:
	"""Fallback: hide cursor using ShowCursor counter mechanism."""

	calls = 0
	while True:
		result = user32.ShowCursor(False)
		calls += 1
		if result < 0:
			break
		if calls > 100:
			raise RuntimeError("Unable to hide cursor using ShowCursor")
	return calls


def _restore_cursor_with_showcursor(calls: int) -> None:
	"""Undo the ShowCursor-based hide."""

	for _ in range(calls):
		user32.ShowCursor(True)


@contextmanager
def blank_cursor() -> Iterator[None]:
	"""Context manager that hides the system cursor while active."""

	_ensure_not_expired()

	restore: Optional[Callable[[], None]] = None
	try:
		_set_blank_system_cursors()
		restore = _restore_default_cursors
	except OSError:
		calls = _hide_cursor_with_showcursor()
		restore = lambda: _restore_cursor_with_showcursor(calls)
	try:
		yield
	finally:
		if restore is not None:
			restore()


def main() -> None:
	if keyboard is None:
		sys.exit("The 'keyboard' module is required. Install it with 'pip install keyboard'.")

	_ensure_not_expired()
	print("Cursor hidden. Press Ctrl+Alt+3 to restore and exit.")

	# Ignore Ctrl+C
	signal.signal(signal.SIGINT, signal.SIG_IGN)

	stop_event = threading.Event()

	def hotkey_listener():
		keyboard.wait('ctrl+alt+3')
		stop_event.set()

	listener_thread = threading.Thread(target=hotkey_listener, daemon=True)
	listener_thread.start()

	with blank_cursor():
		while not stop_event.is_set():
			time.sleep(0.2)
	print("\nExiting and restoring cursor...")

if __name__ == "__main__":
	if sys.platform != "win32":
		sys.exit("This utility only works on Windows.")
	main()
