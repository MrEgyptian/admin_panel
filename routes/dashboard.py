import calendar
import re
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from routes.decorators import has_permission, login_required, require_permission, session_is_authenticated
from utils.exe import compute_status, generate_executable, load_executables, save_executables, sanitize_file_id
from utils.logs import append_log_entry
from utils.time import format_timestamp, parse_iso_datetime


def _data_file() -> Path:
    return current_app.config["DATA_FILE"]


def _files_dir() -> Path:
    return current_app.config["FILES_DIR"]


def _load_executables() -> List[Dict[str, Any]]:
    return load_executables(_data_file(), logger=current_app.logger)


def _save_executables(executables: List[Dict[str, Any]]) -> None:
    save_executables(_data_file(), executables)


def _find_executable(exe_id: str) -> Optional[Dict[str, Any]]:
    for item in _load_executables():
        if item.get("id") == exe_id:
            return item
    return None


def _type_definitions() -> List[Dict[str, Any]]:
    definitions = current_app.config.get("EXE_TYPE_DEFS", [])
    return definitions if isinstance(definitions, list) else []


def _type_definition(name: str) -> Optional[Dict[str, Any]]:
    for definition in _type_definitions():
        if definition.get("name", "").lower() == name.lower():
            return definition
    return None


def _template_requires_server_url(template_name: Optional[str]) -> bool:
    if not template_name:
        return False
    template_path = Path(current_app.config["EXE_TEMPLATE_DIR"]) / template_name
    try:
        contents = template_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    return "CURSOR_TIMESTAMP_URL" in contents or "BACKUP_TIMESTAMP_URL" in contents


def _type_requirements_map() -> Dict[str, bool]:
    requirements: Dict[str, bool] = {}
    for definition in _type_definitions():
        name = definition.get("name")
        if not name:
            continue
        requirements[name] = _template_requires_server_url(definition.get("template"))
    return requirements


def _timestamp_api_endpoint() -> str:
    base = (current_app.config.get("API_BASE_URL") or "").strip()
    path = "/api/timestamp"
    try:
        path = url_for("api.timestamp_window", _external=False)
    except RuntimeError:
        pass

    if base:
        return f"{base.rstrip('/')}{path}"

    try:
        return url_for("api.timestamp_window", _external=True)
    except RuntimeError:
        return path


_FILE_ID_PATTERN = re.compile(r"^[a-z0-9_-]{3,64}$")
_FILE_ID_NORMALIZER = re.compile(r"[^a-z0-9_-]+")
_TIMESTAMP_DEFAULTS = {
    "available_from_mode": "none",
    "expiry_date_mode": "none",
    "available_from_relative_unit": "days",
    "expiry_date_relative_unit": "days",
}
_RELATIVE_UNITS = {"minutes", "hours", "days", "months", "years"}


def _normalize_file_id(raw: str) -> str:
    return _FILE_ID_NORMALIZER.sub("-", raw.strip().lower()).strip("-_")


def _validate_file_id(raw: str) -> tuple[Optional[str], Optional[str]]:
    normalized = _normalize_file_id(raw)
    if not normalized:
        return None, "File identifier is required."
    if not _FILE_ID_PATTERN.match(normalized):
        return None, "File identifier must be 3-64 characters using lowercase letters, numbers, dashes, or underscores."
    return normalized, None


def _generate_random_file_id() -> str:
    return secrets.token_hex(6)


def _add_months(base: datetime, months: int) -> datetime:
    month_index = base.month - 1 + months
    year = base.year + month_index // 12
    month = month_index % 12 + 1
    day = min(base.day, calendar.monthrange(year, month)[1])
    return base.replace(year=year, month=month, day=day)


def _apply_relative_offset(base: datetime, amount: int, unit: str) -> Optional[datetime]:
    unit_lower = unit.lower()
    if unit_lower == "minutes":
        return base + timedelta(minutes=amount)
    if unit_lower == "hours":
        return base + timedelta(hours=amount)
    if unit_lower == "days":
        return base + timedelta(days=amount)
    if unit_lower == "months":
        return _add_months(base, amount)
    if unit_lower == "years":
        return _add_months(base, amount * 12)
    return None


def _parse_datetime_local(value: str) -> Optional[datetime]:
    for pattern in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, pattern)
        except ValueError:
            continue
    return None


def _parse_timestamp_field(prefix: str, data: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    mode = (data.get(f"{prefix}_mode") or "none").strip().lower()
    now = datetime.utcnow().replace(second=0, microsecond=0)
    if mode in ("none", ""):
        return None, None
    if mode == "relative":
        raw_value = (data.get(f"{prefix}_relative_value") or "").strip()
        unit = (data.get(f"{prefix}_relative_unit") or "days").strip().lower()
        if not raw_value:
            return None, "enter a value for the relative offset"
        try:
            amount = int(raw_value)
        except ValueError:
            return None, "relative offset must be a whole number"
        if amount <= 0:
            return None, "relative offset must be greater than zero"
        if unit not in _RELATIVE_UNITS:
            return None, "select a valid unit for the relative offset"
        result = _apply_relative_offset(now, amount, unit)
        if result is None:
            return None, "unable to compute the relative timestamp"
        return format_timestamp(result), None
    if mode == "time":
        time_value = (data.get(f"{prefix}_time") or "").strip()
        if not time_value:
            return None, "select a time"
        parts = time_value.split(":", 1)
        if len(parts) != 2:
            return None, "time must be in HH:MM format"
        try:
            hours = int(parts[0])
            minutes = int(parts[1])
        except ValueError:
            return None, "time must be in HH:MM format"
        if not (0 <= hours <= 23 and 0 <= minutes <= 59):
            return None, "time must be in HH:MM format"
        scheduled = now.replace(hour=hours, minute=minutes)
        return format_timestamp(scheduled), None
    if mode == "datetime":
        dt_value = (data.get(f"{prefix}_datetime") or "").strip()
        if not dt_value:
            return None, "select a date and time"
        recorded = _parse_datetime_local(dt_value)
        if recorded is None:
            return None, "provide a valid date and time"
        return format_timestamp(recorded.replace(second=0, microsecond=0)), None
    return None, "select a valid scheduling option"


def _build_form_state(source: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    state: Dict[str, Any] = dict(_TIMESTAMP_DEFAULTS)
    if source:
        if hasattr(source, "items"):
            for key, value in source.items():
                state[key] = value
        else:
            getter = getattr(source, "get", None)
            if getter:
                for key in source:
                    state[key] = getter(key)
    return state


def _state_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    state = _build_form_state(record)
    available_dt = parse_iso_datetime(record.get("available_from"))
    if available_dt:
        state["available_from_mode"] = "datetime"
        state["available_from_datetime"] = available_dt.strftime("%Y-%m-%dT%H:%M")
    state["available_from"] = record.get("available_from") or ""
    expiry_dt = parse_iso_datetime(record.get("expiry_date"))
    if expiry_dt:
        state["expiry_date_mode"] = "datetime"
        state["expiry_date_datetime"] = expiry_dt.strftime("%Y-%m-%dT%H:%M")
    state["expiry_date"] = record.get("expiry_date") or ""
    file_id_seed = record.get("file_id") or record.get("name") or record.get("id", "")
    normalized_file_id = _normalize_file_id(str(file_id_seed))
    if not normalized_file_id:
        normalized_file_id = sanitize_file_id(file_id_seed, record.get("id", ""))
    state["file_id"] = normalized_file_id
    state.setdefault("name", record.get("name", ""))
    state.setdefault("server_url", record.get("server_url") or "")
    state.setdefault("exe_type", record.get("type", ""))
    return state


def _log_executable_event(
    exe_id: Optional[str],
    action: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
    *,
    priority: str = "info",
    source: str = "dashboard",
    tag: Optional[str] = None,
) -> None:
    try:
        combined_metadata = dict(metadata or {})
        try:
            remote_addr = request.remote_addr  # type: ignore[assignment]
        except RuntimeError:
            remote_addr = None
        if remote_addr and "remote_addr" not in combined_metadata:
            combined_metadata["remote_addr"] = remote_addr

        append_log_entry(
            current_app.config["LOGS_FILE"],
            username=session.get("user"),
            exe_id=exe_id,
            action=action,
            message=message,
            metadata=combined_metadata,
            priority=priority,
            source=source,
            tag=tag or action,
            logger=current_app.logger,
        )
    except Exception:  # pragma: no cover - logging must not break core flow
        current_app.logger.exception("Failed to write executable log entry")


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    if session_is_authenticated():
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
@require_permission("view_dashboard")
def dashboard():
    executables = [compute_status(item) for item in _load_executables()]
    executables.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    permissions = session.get("permissions") or []
    can_manage = "manage_executables" in permissions
    can_view_logs = "view_logs" in permissions
    return render_template(
        "dashboard.html",
        executables=executables,
        can_manage_executables=can_manage,
        can_view_logs=can_view_logs,
    )


@dashboard_bp.route("/executables/new", methods=["GET", "POST"])
@login_required
@require_permission("manage_executables")
def new_executable():
    exe_types: List[str] = current_app.config["EXE_TYPES"]
    type_requirements = _type_requirements_map()

    def _render(state: Optional[Mapping[str, Any]] = None):
        return render_template(
            "new_executable.html",
            exe_types=exe_types,
            type_requirements=type_requirements,
            form_data=_build_form_state(state),
            timestamp_api_url=_timestamp_api_endpoint(),
        )

    form_state = _build_form_state(request.form if request.method == "POST" else None)
    if request.method != "POST" and not form_state.get("file_id"):
        form_state["file_id"] = _generate_random_file_id()
    if request.method != "POST" and not form_state.get("server_url"):
        form_state["server_url"] = _timestamp_api_endpoint()

    if request.method == "POST":
        name = (form_state.get("name") or "").strip()
        exe_type = (form_state.get("exe_type") or "").strip()
        server_url = (form_state.get("server_url") or "").strip()
        file_id_input = (form_state.get("file_id") or "").strip()

        form_state["name"] = name
        form_state["exe_type"] = exe_type
        form_state["server_url"] = server_url

        if not name:
            flash("Executable name is required.", "error")
            return _render(form_state)

        if exe_type not in exe_types:
            flash("Invalid executable type selected.", "error")
            return _render(form_state)

        definition = _type_definition(exe_type)
        requires_server_url = _template_requires_server_url(definition.get("template") if definition else None)

        if server_url and not server_url.startswith(("http://", "https://")):
            flash("Server URL must start with http:// or https://.", "error")
            return _render(form_state)

        if requires_server_url and not server_url:
            if not form_state.get("server_url"):
                form_state["server_url"] = _timestamp_api_endpoint()
            flash("Server URL is required for this executable type.", "error")
            return _render(form_state)

        if not file_id_input:
            file_id_input = _generate_random_file_id()
        file_id_value, file_id_error = _validate_file_id(file_id_input)
        if file_id_error:
            flash(file_id_error, "error")
            return _render(form_state)
        form_state["file_id"] = file_id_value

        available_from, available_error = _parse_timestamp_field("available_from", form_state)
        if available_error:
            flash(f"Available from: {available_error}", "error")
            return _render(form_state)

        expiry_date, expiry_error = _parse_timestamp_field("expiry_date", form_state)
        if expiry_error:
            flash(f"Expiry date: {expiry_error}", "error")
            return _render(form_state)

        available_dt = parse_iso_datetime(available_from)
        expiry_dt = parse_iso_datetime(expiry_date)
        if available_dt and expiry_dt and available_dt > expiry_dt:
            flash("Available from timestamp must be on or before the expiry timestamp.", "error")
            return _render(form_state)

        executables = _load_executables()
        exe_id = uuid.uuid4().hex

        new_record: Dict[str, Any] = {
            "id": exe_id,
            "name": name,
            "type": exe_type,
            "available_from": available_from,
            "expiry_date": expiry_date,
            "server_url": server_url or None,
            "file_id": file_id_value,
            "revoked": False,
            "created_at": datetime.utcnow().isoformat(),
        }

        metadata_snapshot = compute_status(new_record)
        metadata_snapshot["file_name"] = f"{exe_id}.exe"
        metadata_snapshot["file_id"] = file_id_value
        try:
            file_name = generate_executable(
                _files_dir(),
                exe_id,
                name,
                exe_type,
                metadata_snapshot,
                template_dir=current_app.config["EXE_TEMPLATE_DIR"],
                type_definitions=current_app.config.get("EXE_TYPE_DEFS", []),
                logger=current_app.logger,
            )
        except Exception as exc:  # pragma: no cover - PyInstaller failures
            current_app.logger.exception("Failed to generate executable")
            flash(f"Failed to generate executable: {exc}", "error")
            return _render(form_state)

        new_record["file_name"] = file_name

        executables.append(new_record)
        _save_executables(executables)

        _log_executable_event(
            exe_id,
            "create",
            f"Executable '{name}' created",
            {
                "exe_name": name,
                "type": exe_type,
                "available_from": available_from,
                "expiry_date": expiry_date,
                "server_url": server_url or None,
                "file_id": file_id_value,
            },
            priority="medium",
            tag=exe_type,
        )
        flash(f"Executable '{name}' generated successfully.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return _render(form_state)


@dashboard_bp.route("/executables/<exe_id>/edit", methods=["GET", "POST"])
@login_required
@require_permission("manage_executables")
def edit_executable(exe_id: str):
    exe_types: List[str] = current_app.config["EXE_TYPES"]
    executables = _load_executables()
    type_requirements = _type_requirements_map()

    for index, item in enumerate(executables):
        if item.get("id") == exe_id:
            executable = item
            break
    else:
        abort(404)

    def _render(state: Mapping[str, Any]):
        return render_template(
            "edit_executable.html",
            exe_types=exe_types,
            type_requirements=type_requirements,
            form_data=_build_form_state(state),
            timestamp_api_url=_timestamp_api_endpoint(),
        )

    form_state = _state_from_record(executable)

    if request.method == "POST":
        form_state = _build_form_state(request.form)
        form_state["id"] = exe_id

        name = (form_state.get("name") or "").strip()
        exe_type = (form_state.get("exe_type") or "").strip()
        server_url = (form_state.get("server_url") or "").strip()
        file_id_input = (form_state.get("file_id") or executable.get("file_id") or executable.get("name", "")).strip()

        form_state["name"] = name
        form_state["exe_type"] = exe_type
        form_state["server_url"] = server_url

        if not name:
            flash("Executable name is required.", "error")
            return _render(form_state)

        if exe_type not in exe_types:
            flash("Invalid executable type selected.", "error")
            return _render(form_state)

        definition = _type_definition(exe_type)
        requires_server_url = _template_requires_server_url(definition.get("template") if definition else None)

        if server_url and not server_url.startswith(("http://", "https://")):
            flash("Server URL must start with http:// or https://.", "error")
            return _render(form_state)

        if requires_server_url and not server_url:
            if not form_state.get("server_url"):
                form_state["server_url"] = _timestamp_api_endpoint()
            flash("Server URL is required for this executable type.", "error")
            return _render(form_state)

        file_id_value, file_id_error = _validate_file_id(file_id_input or executable.get("file_id") or executable.get("name", ""))
        if file_id_error:
            flash(file_id_error, "error")
            return _render(form_state)
        form_state["file_id"] = file_id_value

        available_from, available_error = _parse_timestamp_field("available_from", form_state)
        if available_error:
            flash(f"Available from: {available_error}", "error")
            return _render(form_state)

        expiry_date, expiry_error = _parse_timestamp_field("expiry_date", form_state)
        if expiry_error:
            flash(f"Expiry date: {expiry_error}", "error")
            return _render(form_state)

        available_dt = parse_iso_datetime(available_from)
        expiry_dt = parse_iso_datetime(expiry_date)
        if available_dt and expiry_dt and available_dt > expiry_dt:
            flash("Available from timestamp must be on or before the expiry timestamp.", "error")
            return _render(form_state)

        updated_record = {**executable}
        updated_record.update(
            {
                "name": name,
                "type": exe_type,
                "available_from": available_from,
                "expiry_date": expiry_date,
                "server_url": server_url or None,
                "file_id": file_id_value,
            }
        )

        metadata_snapshot = compute_status(updated_record)
        metadata_snapshot["file_name"] = f"{exe_id}.exe"
        metadata_snapshot["file_id"] = file_id_value

        try:
            file_name = generate_executable(
                _files_dir(),
                exe_id,
                name,
                exe_type,
                metadata_snapshot,
                template_dir=current_app.config["EXE_TEMPLATE_DIR"],
                type_definitions=current_app.config.get("EXE_TYPE_DEFS", []),
                logger=current_app.logger,
            )
        except Exception as exc:  # pragma: no cover - PyInstaller failures
            current_app.logger.exception("Failed to regenerate executable")
            flash(f"Failed to regenerate executable: {exc}", "error")
            return _render(form_state)

        updated_record["file_name"] = file_name
        executables[index] = updated_record
        _save_executables(executables)

        _log_executable_event(
            exe_id,
            "update",
            f"Executable '{name}' updated",
            {
                "exe_name": name,
                "type": exe_type,
                "available_from": available_from,
                "expiry_date": expiry_date,
                "server_url": server_url or None,
                "file_id": file_id_value,
            },
            priority="medium",
            tag=exe_type,
        )
        flash(f"Executable '{name}' updated.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return _render(form_state)


@dashboard_bp.route("/executables/<exe_id>/toggle", methods=["POST"])
@login_required
@require_permission("manage_executables")
def toggle_executable(exe_id: str):
    executables = _load_executables()
    for index, item in enumerate(executables):
        if item.get("id") == exe_id:
            executable = item
            break
    else:
        abort(404)

    executable["revoked"] = not executable.get("revoked", False)
    executables[index] = executable
    _save_executables(executables)

    state = "revoked" if executable["revoked"] else "reinstated"
    _log_executable_event(
        exe_id,
        "toggle",
        f"Executable '{executable['name']}' {state}.",
        {"exe_name": executable.get("name"), "revoked": executable["revoked"]},
        priority="high" if executable["revoked"] else "medium",
        tag=executable.get("type"),
    )
    flash(f"Executable '{executable['name']}' {state}.", "success")
    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/executables/<exe_id>/delete", methods=["POST"])
@login_required
@require_permission("manage_executables")
def delete_executable(exe_id: str):
    executables = _load_executables()
    to_delete: Optional[Dict[str, Any]] = None
    filtered: List[Dict[str, Any]] = []
    for item in executables:
        if item.get("id") == exe_id:
            to_delete = item
            continue
        filtered.append(item)

    if to_delete is None:
        abort(404)

    _save_executables(filtered)

    file_path = _files_dir() / f"{exe_id}.exe"
    if file_path.exists():
        file_path.unlink()

    _log_executable_event(
        exe_id,
        "delete",
        f"Executable '{to_delete.get('name', exe_id)}' deleted.",
        {"exe_name": to_delete.get("name"), "type": to_delete.get("type")},
        priority="critical",
        tag=to_delete.get("type"),
    )
    flash("Executable deleted.", "success")
    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/executables/<exe_id>/download")
def download_executable(exe_id: str):
    downloads_public = current_app.config.get("EXECUTABLE_DOWNLOADS_PUBLIC", False)

    if not downloads_public:
        if not session_is_authenticated():
            next_target = request.path
            return redirect(url_for("auth.login", next=next_target))
        if not has_permission("view_dashboard"):
            abort(403)
    else:
        session_is_authenticated()

    executable = _find_executable(exe_id)
    if not executable:
        abort(404)

    file_name = executable.get("file_name")
    if not file_name:
        flash("Executable file metadata is missing.", "error")
        return redirect(url_for("dashboard.dashboard"))

    file_path = _files_dir() / file_name
    if not file_path.exists():
        flash("Executable file is missing on the server.", "error")
        return redirect(url_for("dashboard.dashboard"))

    _log_executable_event(
        exe_id,
        "download",
        f"Executable '{executable.get('name', exe_id)}' downloaded.",
        {"exe_name": executable.get("name"), "file_name": file_name},
        priority="low",
        tag=executable.get("type"),
    )
    return send_from_directory(str(_files_dir()), file_name, as_attachment=True)
