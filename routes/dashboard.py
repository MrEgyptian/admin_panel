import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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

from routes.decorators import login_required, require_permission, session_is_authenticated
from utils.exe import compute_status, generate_stub_executable, load_executables, save_executables
from utils.logs import append_log_entry
from utils.time import parse_form_date, parse_iso_date


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

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        exe_type = request.form.get("exe_type", "").strip()
        available_from_raw = request.form.get("available_from", "").strip()
        expiry_date_raw = request.form.get("expiry_date", "").strip()
        server_url = request.form.get("server_url", "").strip()

        if not name:
            flash("Executable name is required.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        if exe_type not in exe_types:
            flash("Invalid executable type selected.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        available_from = parse_form_date(available_from_raw)
        if available_from_raw and not available_from:
            flash("Available from date must follow YYYY-MM-DD.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        expiry_date = parse_form_date(expiry_date_raw)
        if expiry_date_raw and not expiry_date:
            flash("Expiry date must follow YYYY-MM-DD.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        if server_url and not server_url.startswith(("http://", "https://")):
            flash("Server URL must start with http:// or https://.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        available_from_date = parse_iso_date(available_from)
        expiry_date_date = parse_iso_date(expiry_date)
        if available_from_date and expiry_date_date and available_from_date > expiry_date_date:
            flash("Available from date must be on or before the expiry date.", "error")
            return render_template("new_executable.html", exe_types=exe_types)

        executables = _load_executables()
        exe_id = uuid.uuid4().hex

        new_record: Dict[str, Any] = {
            "id": exe_id,
            "name": name,
            "type": exe_type,
            "available_from": available_from,
            "expiry_date": expiry_date,
            "server_url": server_url or None,
            "revoked": False,
            "created_at": datetime.utcnow().isoformat(),
        }

        status_snapshot = compute_status(new_record)
        file_name = generate_stub_executable(_files_dir(), exe_id, name, exe_type, status_snapshot)
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
            },
            priority="medium",
            tag=exe_type,
        )
        flash(f"Executable '{name}' generated successfully.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("new_executable.html", exe_types=exe_types)


@dashboard_bp.route("/executables/<exe_id>/edit", methods=["GET", "POST"])
@login_required
@require_permission("manage_executables")
def edit_executable(exe_id: str):
    exe_types: List[str] = current_app.config["EXE_TYPES"]
    executables = _load_executables()

    for index, item in enumerate(executables):
        if item.get("id") == exe_id:
            executable = item
            break
    else:
        abort(404)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        exe_type = request.form.get("exe_type", "").strip()
        available_from_raw = request.form.get("available_from", "").strip()
        expiry_date_raw = request.form.get("expiry_date", "").strip()
        server_url = request.form.get("server_url", "").strip()

        form_values: Dict[str, Any] = {
            "id": exe_id,
            "name": name,
            "type": exe_type,
            "available_from": available_from_raw,
            "expiry_date": expiry_date_raw,
            "server_url": server_url,
            "revoked": executable.get("revoked", False),
        }

        if not name:
            flash("Executable name is required.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        if exe_type not in exe_types:
            flash("Invalid executable type selected.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        available_from = parse_form_date(available_from_raw)
        if available_from_raw and not available_from:
            flash("Available from date must follow YYYY-MM-DD.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        expiry_date = parse_form_date(expiry_date_raw)
        if expiry_date_raw and not expiry_date:
            flash("Expiry date must follow YYYY-MM-DD.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        if server_url and not server_url.startswith(("http://", "https://")):
            flash("Server URL must start with http:// or https://.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        available_from_date = parse_iso_date(available_from)
        expiry_date_date = parse_iso_date(expiry_date)
        if available_from_date and expiry_date_date and available_from_date > expiry_date_date:
            flash("Available from date must be on or before the expiry date.", "error")
            return render_template("edit_executable.html", exe=form_values, exe_types=exe_types)

        executable["name"] = name
        executable["type"] = exe_type
        executable["available_from"] = available_from
        executable["expiry_date"] = expiry_date
        executable["server_url"] = server_url or None

        status_snapshot = compute_status(executable)
        executable["file_name"] = generate_stub_executable(
            _files_dir(),
            exe_id,
            name,
            exe_type,
            status_snapshot,
        )

        executables[index] = executable
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
            },
            priority="medium",
            tag=exe_type,
        )
        flash(f"Executable '{name}' updated.", "success")
        return redirect(url_for("dashboard.dashboard"))

    return render_template("edit_executable.html", exe=executable, exe_types=exe_types)


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
@login_required
@require_permission("view_dashboard")
def download_executable(exe_id: str):
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
