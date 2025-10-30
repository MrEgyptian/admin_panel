from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from flask import Blueprint, current_app, render_template, request

from routes.decorators import login_required, require_permission
from utils.exe import load_executables
from utils.logs import filter_logs_by_exe, filter_logs_by_username, load_logs

logs_bp = Blueprint("logs", __name__, url_prefix="/logs")


def _executables_map() -> Dict[str, Dict[str, Any]]:
    executables = load_executables(current_app.config["DATA_FILE"], logger=current_app.logger)
    lookup: Dict[str, Dict[str, Any]] = {}
    for item in executables:
        exe_id = item.get("id")
        if isinstance(exe_id, str):
            lookup[exe_id] = item
    return lookup


def _prepare_entries(entries: Iterable[Dict[str, Any]], exe_lookup: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    prepared: List[Dict[str, Any]] = []
    for entry in entries:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        exe_id = entry.get("exe_id") if isinstance(entry.get("exe_id"), str) else None
        username_value = entry.get("username") if isinstance(entry.get("username"), str) else None
        exe = exe_lookup.get(exe_id) if exe_id else None

        raw_timestamp = entry.get("timestamp") if isinstance(entry.get("timestamp"), str) else None
        timestamp_display = raw_timestamp or "Unknown"
        if raw_timestamp:
            try:
                parsed = datetime.fromisoformat(raw_timestamp)
                timestamp_display = parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
            except ValueError:
                timestamp_display = raw_timestamp

        prepared.append(
            {
                "id": entry.get("id"),
                "timestamp": raw_timestamp,
                "timestamp_display": timestamp_display,
                "username": username_value or "Unknown",
                "username_value": username_value,
                "exe_id": exe_id,
                "exe_name": (exe or {}).get("name") or metadata.get("exe_name") or exe_id or "Unknown",
                "action": entry.get("action") or "unknown",
                "message": entry.get("message") or "",
                "metadata": metadata,
                "priority": entry.get("priority") or "info",
                "source": entry.get("source") or "system",
                "tag": entry.get("tag") or None,
            }
        )
    return prepared


@logs_bp.route("/")
@login_required
@require_permission("view_logs")
def logs_index():
    entries_all = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    entries_all.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    selected_priority = (request.args.get("priority") or "").strip()
    selected_source = (request.args.get("source") or "").strip()
    selected_tag = (request.args.get("tag") or "").strip()
    search_query = (request.args.get("q") or "").strip()

    def _normalize(value: Optional[str]) -> Optional[str]:
        return value.lower() if isinstance(value, str) else None

    normalized_priority = _normalize(selected_priority)
    normalized_source = _normalize(selected_source)
    normalized_tag = _normalize(selected_tag)
    normalized_query = search_query.lower() if search_query else None

    filtered_entries = []
    for entry in entries_all:
        priority_value = entry.get("priority")
        source_value = entry.get("source")
        tag_value = entry.get("tag")

        if normalized_priority and _normalize(priority_value) != normalized_priority:
            continue
        if normalized_source and _normalize(source_value) != normalized_source:
            continue
        if normalized_tag and _normalize(tag_value) != normalized_tag:
            continue

        if normalized_query:
            haystack_parts: List[str] = []
            for key in ("message", "action", "username", "exe_id", "priority", "source", "tag"):
                value = entry.get(key)
                if isinstance(value, str):
                    haystack_parts.append(value)
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            for value in metadata.values():
                if isinstance(value, (str, int, float)):
                    haystack_parts.append(str(value))

            haystack = " ".join(haystack_parts).lower()
            if normalized_query not in haystack:
                continue

        filtered_entries.append(entry)

    exe_lookup = _executables_map()
    prepared_entries = _prepare_entries(filtered_entries[:200], exe_lookup)

    user_counter = Counter(entry.get("username") or "Unknown" for entry in filtered_entries)
    user_summary = [
        {"username": username, "count": count}
        for username, count in user_counter.most_common()
    ]

    exe_counter = Counter(entry.get("exe_id") or "Unknown" for entry in filtered_entries)
    exe_summary = []
    for exe_id, count in exe_counter.most_common():
        exe: Optional[Dict[str, Any]] = exe_lookup.get(exe_id) if exe_id != "Unknown" else None
        exe_summary.append(
            {
                "exe_id": exe_id if exe_id != "Unknown" else None,
                "exe_name": (exe or {}).get("name") or exe_id,
                "count": count,
            }
        )

    available_priorities = sorted({entry.get("priority") for entry in entries_all if entry.get("priority")})
    available_sources = sorted({entry.get("source") for entry in entries_all if entry.get("source")})
    available_tags = sorted({entry.get("tag") for entry in entries_all if entry.get("tag")})

    return render_template(
        "logs/index.html",
        entries=prepared_entries,
        user_summary=user_summary,
        exe_summary=exe_summary,
        priorities=available_priorities,
        sources=available_sources,
        tags=available_tags,
        selected_filters={
            "priority": selected_priority,
            "source": selected_source,
            "tag": selected_tag,
            "q": search_query,
        },
    )


@logs_bp.route("/users/<string:username>")
@login_required
@require_permission("view_logs")
def logs_for_user(username: str):
    entries = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    filtered = filter_logs_by_username(entries, username)
    filtered.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    exe_lookup = _executables_map()
    prepared_entries = _prepare_entries(filtered, exe_lookup)

    return render_template(
        "logs/user.html",
        username=username,
        entries=prepared_entries,
    )


@logs_bp.route("/executables/<string:exe_id>")
@login_required
@require_permission("view_logs")
def logs_for_executable(exe_id: str):
    entries = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    filtered = filter_logs_by_exe(entries, exe_id)
    filtered.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    exe_lookup = _executables_map()
    prepared_entries = _prepare_entries(filtered, exe_lookup)
    exe_record = exe_lookup.get(exe_id)

    exe_name = (exe_record or {}).get("name") or exe_id

    return render_template(
        "logs/executable.html",
        exe_id=exe_id,
        exe_name=exe_name,
        entries=prepared_entries,
    )
