from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from routes.decorators import login_required, require_permission
from utils.exe import load_executables
from utils.logs import (
    clear_all_logs,
    clear_logs_for_executable,
    clear_logs_for_user,
    delete_log_entry,
    filter_logs_by_exe,
    filter_logs_by_username,
    load_logs,
)

logs_bp = Blueprint("logs", __name__, url_prefix="/logs")

_NONE_SENTINEL = "__none__"
_FILTER_SUFFIXES = ("priority", "source", "tag", "q")


def _executables_map() -> Dict[str, Dict[str, Any]]:
    executables = load_executables(current_app.config["DATA_FILE"], logger=current_app.logger)
    lookup: Dict[str, Dict[str, Any]] = {}
    for item in executables:
        exe_id = item.get("id")
        if isinstance(exe_id, str):
            lookup[exe_id] = item
    return lookup


def _normalize_filter(value: Optional[str]) -> Optional[str]:
    if isinstance(value, str) and value:
        return value.lower()
    return None


def _filter_entries(
    entries: Iterable[Dict[str, Any]],
    *,
    priority: Optional[str] = None,
    source: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    normalized_priority = _normalize_filter(priority)
    normalized_source = _normalize_filter(source)
    normalized_tag = _normalize_filter(tag)
    normalized_query = search.lower() if isinstance(search, str) and search else None

    filtered: List[Dict[str, Any]] = []
    for entry in entries:
        if normalized_priority and _normalize_filter(entry.get("priority")) != normalized_priority:
            continue
        if normalized_source and _normalize_filter(entry.get("source")) != normalized_source:
            continue
        if normalized_tag and _normalize_filter(entry.get("tag")) != normalized_tag:
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

        filtered.append(entry)

    return filtered


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


def _collect_filters(prefix: str) -> Dict[str, str]:
    return {
        suffix: (request.args.get(f"{prefix}_{suffix}") or "").strip()
        for suffix in _FILTER_SUFFIXES
    }


@logs_bp.route("/", methods=["GET", "POST"])
@login_required
@require_permission("view_logs")
def logs_index():
    allowed_tabs = {"user", "exe", "event"}
    raw_tab = request.args.get("tab")
    if raw_tab is None:
        raw_tab = request.form.get("active_tab") or request.form.get("tab")
    requested_tab = (raw_tab or "user").strip().lower()
    active_tab = requested_tab if requested_tab in allowed_tabs else "user"

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        redirect_params: Dict[str, str] = {}
        for prefix in ("user", "exe", "event"):
            for suffix in _FILTER_SUFFIXES:
                value = (request.form.get(f"{prefix}_{suffix}") or "").strip()
                if value:
                    redirect_params[f"{prefix}_{suffix}"] = value

        form_tab = (request.form.get("active_tab") or request.form.get("tab") or "").strip().lower()
        if form_tab in allowed_tabs:
            active_tab = form_tab

        if action == "clear_user":
            username_raw = (request.form.get("username") or "").strip()
            if not username_raw:
                flash("No user specified for clearing.", "error")
            else:
                username_value: Optional[str]
                if username_raw == _NONE_SENTINEL:
                    username_value = None
                    label = "unknown users"
                else:
                    username_value = username_raw
                    label = f"'{username_value}'"

                removed = clear_logs_for_user(
                    current_app.config["LOGS_FILE"],
                    username_value,
                    logger=current_app.logger,
                )
                if removed:
                    flash(f"Cleared {removed} log entries for {label}.", "success")
                else:
                    flash("No matching log entries found for that user.", "info")

        elif action == "clear_executable":
            exe_id = (request.form.get("exe_id") or "").strip()
            if not exe_id:
                flash("No executable specified for clearing.", "error")
            else:
                removed = clear_logs_for_executable(
                    current_app.config["LOGS_FILE"],
                    exe_id,
                    logger=current_app.logger,
                )
                if removed:
                    flash(f"Cleared {removed} log entries for executable '{exe_id}'.", "success")
                else:
                    flash("No matching log entries found for that executable.", "info")

        elif action == "clear_all":
            removed = clear_all_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
            if removed:
                flash(f"Cleared {removed} log entries.", "success")
            else:
                flash("No log entries to clear.", "info")
        else:
            flash("Unknown log action requested.", "error")

        if active_tab:
            redirect_params["tab"] = active_tab
    
        return redirect(url_for("logs.logs_index", **redirect_params))

    entries_all = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    entries_all.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    exe_lookup = _executables_map()

    available_priorities = sorted({entry.get("priority") for entry in entries_all if entry.get("priority")})
    available_sources = sorted({entry.get("source") for entry in entries_all if entry.get("source")})
    available_tags = sorted({entry.get("tag") for entry in entries_all if entry.get("tag")})

    user_filters = _collect_filters("user")
    exe_filters = _collect_filters("exe")
    event_filters = _collect_filters("event")

    user_filtered = _filter_entries(
        entries_all,
        priority=user_filters["priority"],
        source=user_filters["source"],
        tag=user_filters["tag"],
        search=user_filters["q"],
    )
    user_counter = Counter(entry.get("username") for entry in user_filtered)
    user_summary = []
    for username_value, count in user_counter.most_common():
        display_name = username_value or "Unknown"
        value_token = _NONE_SENTINEL if username_value is None else username_value
        user_summary.append(
            {
                "username": username_value,
                "value": value_token,
                "display": display_name,
                "count": count,
            }
        )

    exe_filtered = _filter_entries(
        entries_all,
        priority=exe_filters["priority"],
        source=exe_filters["source"],
        tag=exe_filters["tag"],
        search=exe_filters["q"],
    )
    exe_counter = Counter(entry.get("exe_id") for entry in exe_filtered)
    exe_summary = []
    for exe_id, count in exe_counter.most_common():
        exe_record: Optional[Dict[str, Any]] = exe_lookup.get(exe_id) if exe_id else None
        exe_summary.append(
            {
                "exe_id": exe_id,
                "exe_name": (exe_record or {}).get("name") or (exe_id or "System"),
                "count": count,
                "can_clear": bool(exe_id),
            }
        )

    event_filtered = _filter_entries(
        entries_all,
        priority=event_filters["priority"],
        source=event_filters["source"],
        tag=event_filters["tag"],
        search=event_filters["q"],
    )
    event_entries = _prepare_entries(event_filtered[:200], exe_lookup)

    def _prefixed(prefix: str, values: Dict[str, str]) -> Dict[str, str]:
        return {
            f"{prefix}_{key}": value
            for key, value in values.items()
            if value
        }

    user_query = _prefixed("user", user_filters)
    exe_query = _prefixed("exe", exe_filters)
    event_query = _prefixed("event", event_filters)

    preserve_for_user = {**exe_query, **event_query}
    preserve_for_exe = {**user_query, **event_query}
    preserve_for_event = {**user_query, **exe_query}
    all_filters = {**user_query, **exe_query, **event_query}

    reset_user_url = url_for("logs.logs_index", tab="user", **preserve_for_user)
    reset_exe_url = url_for("logs.logs_index", tab="exe", **preserve_for_exe)
    reset_event_url = url_for("logs.logs_index", tab="event", **preserve_for_event)

    tab_links = {
        "user": url_for("logs.logs_index", tab="user", **all_filters),
        "exe": url_for("logs.logs_index", tab="exe", **all_filters),
        "event": url_for("logs.logs_index", tab="event", **all_filters),
    }

    return render_template(
        "logs/index.html",
        user_summary=user_summary,
        exe_summary=exe_summary,
        event_entries=event_entries,
        priorities=available_priorities,
        sources=available_sources,
        tags=available_tags,
        user_filters=user_filters,
        exe_filters=exe_filters,
        event_filters=event_filters,
        user_total=sum(item["count"] for item in user_summary),
        exe_total=sum(item["count"] for item in exe_summary),
        event_total=len(event_filtered),
        preserve_for_user=preserve_for_user,
        preserve_for_exe=preserve_for_exe,
        preserve_for_event=preserve_for_event,
        all_filters=all_filters,
        reset_user_url=reset_user_url,
        reset_exe_url=reset_exe_url,
        reset_event_url=reset_event_url,
        active_tab=active_tab,
        tab_links=tab_links,
    )


def _collect_plain_filters() -> Dict[str, str]:
    return {
        suffix: (request.args.get(suffix) or "").strip()
        for suffix in _FILTER_SUFFIXES
    }


@logs_bp.route("/users/<string:username>", methods=["GET", "POST"])
@login_required
@require_permission("view_logs")
def logs_for_user(username: str):
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        redirect_params = {
            key: value
            for key in _FILTER_SUFFIXES
            if (value := (request.form.get(key) or "").strip())
        }

        if action == "clear_user":
            removed = clear_logs_for_user(
                current_app.config["LOGS_FILE"],
                username,
                logger=current_app.logger,
            )
            if removed:
                flash(f"Cleared {removed} log entries for '{username}'.", "success")
            else:
                flash("No log entries to clear for this user.", "info")
        else:
            flash("Unknown log action requested.", "error")

        return redirect(url_for("logs.logs_for_user", username=username, **redirect_params))

    entries = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    user_entries = filter_logs_by_username(entries, username)
    user_entries.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    filters = _collect_plain_filters()

    filtered = _filter_entries(
        user_entries,
        priority=filters["priority"],
        source=filters["source"],
        tag=filters["tag"],
        search=filters["q"],
    )

    exe_lookup = _executables_map()
    prepared_entries = _prepare_entries(filtered, exe_lookup)

    available_priorities = sorted({entry.get("priority") for entry in user_entries if entry.get("priority")})
    available_sources = sorted({entry.get("source") for entry in user_entries if entry.get("source")})
    available_tags = sorted({entry.get("tag") for entry in user_entries if entry.get("tag")})

    reset_url = url_for("logs.logs_for_user", username=username)

    return render_template(
        "logs/user.html",
        username=username,
        entries=prepared_entries,
        filters=filters,
        priorities=available_priorities,
        sources=available_sources,
        tags=available_tags,
        total=len(filtered),
        reset_url=reset_url,
        has_entries=bool(user_entries),
    )


@logs_bp.route("/executables/<string:exe_id>", methods=["GET", "POST"])
@login_required
@require_permission("view_logs")
def logs_for_executable(exe_id: str):
    filter_keys = ("priority", "source", "tag", "q")

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        redirect_params: Dict[str, str] = {}
        for key in filter_keys:
            value = (request.form.get(key) or "").strip()
            if value:
                redirect_params[key] = value

        if action == "delete_entry":
            entry_id = (request.form.get("entry_id") or "").strip()
            if entry_id and delete_log_entry(current_app.config["LOGS_FILE"], entry_id, logger=current_app.logger):
                flash("Log entry deleted.", "success")
            else:
                flash("Log entry could not be found.", "error")
        elif action == "clear_executable":
            removed = clear_logs_for_executable(current_app.config["LOGS_FILE"], exe_id, logger=current_app.logger)
            if removed:
                flash(f"Cleared {removed} log entries for this executable.", "success")
            else:
                flash("No log entries to clear for this executable.", "info")
        else:
            flash("Unknown log action requested.", "error")

        return redirect(url_for("logs.logs_for_executable", exe_id=exe_id, **redirect_params))

    selected_priority = (request.args.get("priority") or "").strip()
    selected_source = (request.args.get("source") or "").strip()
    selected_tag = (request.args.get("tag") or "").strip()
    search_query = (request.args.get("q") or "").strip()

    entries_all = load_logs(current_app.config["LOGS_FILE"], logger=current_app.logger)
    entries_for_exe = filter_logs_by_exe(entries_all, exe_id)
    entries_for_exe.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

    filtered_entries = _filter_entries(
        entries_for_exe,
        priority=selected_priority,
        source=selected_source,
        tag=selected_tag,
        search=search_query,
    )

    exe_lookup = _executables_map()
    prepared_entries = _prepare_entries(filtered_entries, exe_lookup)
    exe_record = exe_lookup.get(exe_id)

    exe_name = (exe_record or {}).get("name") or exe_id

    available_priorities = sorted({entry.get("priority") for entry in entries_for_exe if entry.get("priority")})
    available_sources = sorted({entry.get("source") for entry in entries_for_exe if entry.get("source")})
    available_tags = sorted({entry.get("tag") for entry in entries_for_exe if entry.get("tag")})

    return render_template(
        "logs/executable.html",
        exe_id=exe_id,
        exe_name=exe_name,
        entries=prepared_entries,
        priorities=available_priorities,
        sources=available_sources,
        tags=available_tags,
        selected_filters={
            "priority": selected_priority,
            "source": selected_source,
            "tag": selected_tag,
            "q": search_query,
        },
        has_entries=bool(entries_for_exe),
    )
