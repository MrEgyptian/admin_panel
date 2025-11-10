import calendar
import re
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Optional

from flask import Blueprint, current_app, jsonify, request

from utils.exe import load_executables
from utils.time import parse_iso_datetime

api_bp = Blueprint("api", __name__)


_FILE_ID_NORMALIZER = re.compile(r"[^a-z0-9_-]+")
_DEFAULT_EXPIRY_DAYS = 365


def _normalize_file_id(raw: str) -> str:
    return _FILE_ID_NORMALIZER.sub("-", raw.strip().lower()).strip("-_")


def _candidate_ids(entry: Dict[str, Any]) -> Iterable[str]:
    explicit = entry.get("file_id")
    if explicit:
        yield explicit.strip().lower()
    name_based = _normalize_file_id(str(entry.get("name", "")))
    if name_based:
        yield name_based
    identifier = entry.get("id")
    if identifier:
        yield str(identifier).strip().lower()


def _find_entry(target: str, entries: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    target_normalized = _normalize_file_id(target)
    for entry in entries:
        for candidate in _candidate_ids(entry):
            if candidate == target_normalized:
                return entry
    return None


def _coerce_timestamp(value: Optional[str], fallback: Optional[datetime] = None) -> Optional[datetime]:
    if not value:
        return fallback
    parsed = parse_iso_datetime(value)
    return parsed or fallback


def _ensure_expiry(window_start: datetime, expires_at: Optional[datetime]) -> datetime:
    if expires_at:
        return expires_at
    return window_start + timedelta(days=_DEFAULT_EXPIRY_DAYS)


def _to_epoch_utc(moment: datetime) -> int:
    return int(calendar.timegm(moment.utctimetuple()))


@api_bp.route("/api/timestamp", methods=["POST"])
def timestamp_window():
    payload = request.get_json(silent=True) or {}
    file_id = str(payload.get("file_id") or "").strip()
    if not file_id:
        return jsonify({"error": "file_id_required"}), 400

    data_file = current_app.config["DATA_FILE"]
    entries = load_executables(data_file, logger=current_app.logger)
    entry = _find_entry(file_id, entries)
    if not entry:
        current_app.logger.info("Timestamp lookup failed", extra={"file_id": file_id})
        return jsonify({"error": "file_id_not_found"}), 404

    created_at = _coerce_timestamp(entry.get("created_at"), datetime.utcnow())
    available_from = _coerce_timestamp(entry.get("available_from"), created_at)
    window_start = available_from or created_at or datetime.utcnow()
    expires_at = _ensure_expiry(window_start, _coerce_timestamp(entry.get("expiry_date")))

    response = {
        "file_id": _normalize_file_id(entry.get("file_id") or file_id),
        "created_at": _to_epoch_utc(created_at if created_at else window_start),
        "available_from": _to_epoch_utc(window_start),
        "expires_at": _to_epoch_utc(expires_at),
        "revoked": bool(entry.get("revoked", False)),
    }

    if entry.get("revoked"):
        response["status"] = "revoked"
    elif datetime.utcnow() >= expires_at:
        response["status"] = "expired"
    elif window_start and datetime.utcnow() < window_start:
        response["status"] = "scheduled"
    else:
        response["status"] = "active"

    return jsonify(response)
