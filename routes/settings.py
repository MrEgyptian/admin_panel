import configparser
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from routes.decorators import login_required, require_permission
from utils.database import load_admins, save_admins
from utils.exe import load_executables
from utils.exe_types import (
    build_options_from_labels,
    load_type_definitions,
    parse_option_string,
    save_type_definitions,
)
from utils.roles import (
    AVAILABLE_PERMISSIONS,
    ROLE_DEFINITIONS,
    ROLE_DISPLAY_ORDER,
    normalize_role,
    permission_labels_map,
    resolve_permissions,
)

settings_bp = Blueprint("settings", __name__)


def _config_parser() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    config_file: Path = current_app.config["CONFIG_FILE"]
    parser.read(config_file, encoding="utf-8")
    for section in ("flask", "admin", "executables", "api"):
        if not parser.has_section(section):
            parser.add_section(section)
    return parser


def _write_config(parser: configparser.ConfigParser) -> None:
    config_file: Path = current_app.config["CONFIG_FILE"]
    with config_file.open("w", encoding="utf-8") as handle:
        parser.write(handle)


def _type_definitions() -> List[Dict[str, Any]]:
    definitions = current_app.config.get("EXE_TYPE_DEFS")
    if definitions is None:
        definitions = load_type_definitions(current_app.config["EXE_TYPE_DEFS_FILE"], current_app.config.get("EXE_TYPES", []))
        current_app.config["EXE_TYPE_DEFS"] = definitions
    # return a deep-ish copy to avoid mutating config directly
    result: List[Dict[str, Any]] = []
    for item in definitions:
        entry = {
            "name": item.get("name", ""),
            "template": item.get("template", ""),
            "options": [
                {
                    "key": option.get("key", ""),
                    "label": option.get("label", ""),
                }
                for option in item.get("options", [])
                if isinstance(option, dict)
            ],
        }
        result.append(entry)
    return result


def _persist_type_definitions(definitions: List[Dict[str, Any]]) -> None:
    save_type_definitions(current_app.config["EXE_TYPE_DEFS_FILE"], definitions)
    current_app.config["EXE_TYPE_DEFS"] = definitions
    current_app.config["EXE_TYPES"] = [item.get("name") for item in definitions]


def _available_templates() -> List[str]:
    template_dir = Path(current_app.config["EXE_TEMPLATE_DIR"])
    template_dir.mkdir(parents=True, exist_ok=True)
    templates = sorted({path.name for path in template_dir.glob("*.py") if path.is_file()})
    return templates


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "template"


def _save_uploaded_template(file_storage, type_name: str) -> Optional[str]:
    if not file_storage or not file_storage.filename:
        return None

    filename = secure_filename(file_storage.filename)
    if not filename.lower().endswith(".py"):
        return None

    template_dir = Path(current_app.config["EXE_TEMPLATE_DIR"])
    template_dir.mkdir(parents=True, exist_ok=True)

    unique_name = f"{_slugify(type_name)}-{uuid4().hex[:8]}.py"
    target_path = template_dir / unique_name
    file_storage.save(target_path)
    return unique_name


def _redirect_app_tab():
    return redirect(url_for("settings.settings_index", tab="app"))


def _admin_management_context(admins: List[Dict[str, Any]]) -> Dict[str, Any]:
    permission_labels = permission_labels_map()
    role_options = [
        {
            "name": role,
            "label": ROLE_DEFINITIONS[role]["label"],
            "description": ROLE_DEFINITIONS[role]["description"],
        }
        for role in ROLE_DISPLAY_ORDER
    ]

    enriched_admins = []
    for admin in admins:
        resolved = admin.get("resolved_permissions") or resolve_permissions(admin.get("role"), admin.get("permissions"))
        enriched_admins.append(
            {
                **admin,
                "role_label": ROLE_DEFINITIONS.get(admin.get("role"), {}).get("label", admin.get("role")),
                "permissions_display": [permission_labels.get(item, item) for item in resolved],
                "resolved_permissions": resolved,
            }
        )

    return {
        "admins": enriched_admins,
        "roles": role_options,
        "permissions": AVAILABLE_PERMISSIONS,
    }


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
@require_permission("manage_settings")
def settings_index():
    parser = _config_parser()
    requested_tab = request.args.get("tab") or request.form.get("active_tab") or "app"
    existing_definitions = _type_definitions()

    if request.method == "POST":
        secret_key = request.form.get("secret_key", "").strip()
        same_site = request.form.get("session_cookie_samesite", "Lax").strip()
        http_only = request.form.get("session_cookie_http_only") == "on"
        downloads_public = request.form.get("executables_public_downloads") == "on"
        api_host_raw = (request.form.get("api_host", "") or "").strip()
        type_indexes = request.form.getlist("type_index[]")

        if not secret_key:
            flash("Secret key cannot be empty.", "error")
            return _redirect_app_tab()

        allowed_same_site = {"Lax", "Strict", "None"}
        if same_site not in allowed_same_site:
            flash("Invalid SameSite value selected.", "error")
            return _redirect_app_tab()

        if not type_indexes:
            flash("Define at least one executable type.", "error")
            return _redirect_app_tab()

        existing_map = {item.get("name", "").lower(): item for item in existing_definitions}
        template_dir = Path(current_app.config["EXE_TEMPLATE_DIR"])
        type_definitions: List[Dict[str, Any]] = []
        seen_names: set[str] = set()

        for index in type_indexes:
            name = request.form.get(f"type_name_{index}", "").strip()
            if not name:
                flash("Each executable type requires a name.", "error")
                return _redirect_app_tab()

            lowered = name.lower()
            if lowered in seen_names:
                flash("Executable type names must be unique.", "error")
                return _redirect_app_tab()

            current_template = request.form.get(f"type_template_current_{index}", "").strip()
            selected_template = request.form.get(f"type_template_existing_{index}", "").strip()
            upload_field = f"type_template_upload_{index}"
            uploaded_file = request.files.get(upload_field)

            if uploaded_file and uploaded_file.filename and not uploaded_file.filename.lower().endswith(".py"):
                flash("Template uploads must be Python files.", "error")
                return _redirect_app_tab()

            saved_template = _save_uploaded_template(uploaded_file, name) if uploaded_file and uploaded_file.filename else None
            template_name = saved_template or selected_template or current_template
            if template_name:
                template_name = Path(template_name).name
            if not template_name:
                flash("Each executable type must reference a template.", "error")
                return _redirect_app_tab()

            if not saved_template:
                candidate_path = template_dir / template_name
                if not candidate_path.exists():
                    flash(f"Template '{template_name}' does not exist. Upload it or select another template.", "error")
                    return _redirect_app_tab()

            options_raw = request.form.get(f"type_options_{index}", "")
            option_labels = parse_option_string(options_raw)
            existing_options = []
            if lowered in existing_map:
                existing_entry = existing_map[lowered]
                existing_options = existing_entry.get("options", []) if isinstance(existing_entry, dict) else []
            options = build_options_from_labels(option_labels, existing_options)

            type_definitions.append(
                {
                    "name": name,
                    "template": template_name,
                    "options": options,
                }
            )
            seen_names.add(lowered)

        if not type_definitions:
            flash("Executable types cannot be empty.", "error")
            return _redirect_app_tab()

        exe_types = [item["name"] for item in type_definitions]

        api_host_clean = ""
        if api_host_raw:
            parsed_host = urlparse(api_host_raw)
            if parsed_host.scheme not in {"http", "https"} or not parsed_host.netloc:
                flash("API host must be a valid http(s) URL (e.g. https://example.com).", "error")
                return _redirect_app_tab()
            api_host_clean = api_host_raw.rstrip("/")

        parser.set("flask", "secret_key", secret_key)
        parser.set("flask", "session_cookie_http_only", "true" if http_only else "false")
        parser.set("flask", "session_cookie_samesite", same_site)
        parser.set("executables", "types", ",".join(exe_types))
        parser.set("executables", "public_downloads", "true" if downloads_public else "false")
        parser.set("api", "host", api_host_clean)

        _write_config(parser)
        _persist_type_definitions(type_definitions)

        current_app.config.update(
            SECRET_KEY=secret_key,
            SESSION_COOKIE_HTTPONLY=http_only,
            SESSION_COOKIE_SAMESITE=same_site,
            EXECUTABLE_DOWNLOADS_PUBLIC=downloads_public,
            API_BASE_URL=api_host_clean,
        )

        flash("Settings saved successfully.", "success")
        return _redirect_app_tab()

    current_values = {
        "secret_key": current_app.config["SECRET_KEY"],
        "session_cookie_http_only": current_app.config.get("SESSION_COOKIE_HTTPONLY", True),
        "session_cookie_samesite": current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        "exe_types": ", ".join(current_app.config.get("EXE_TYPES", [])),
        "exe_types_list": [item.get("name", "") for item in existing_definitions],
        "type_definitions": existing_definitions,
        "available_templates": _available_templates(),
        "executables_public_downloads": current_app.config.get("EXECUTABLE_DOWNLOADS_PUBLIC", False),
        "api_host": current_app.config.get("API_BASE_URL", ""),
    }

    api_path = url_for("api.timestamp_window", _external=False)
    if current_values["api_host"]:
        current_values["api_timestamp_endpoint"] = f"{current_values['api_host'].rstrip('/')}{api_path}"
    else:
        current_values["api_timestamp_endpoint"] = url_for("api.timestamp_window", _external=True)

    can_manage_admins = "manage_admins" in (session.get("permissions") or [])
    can_view_logs = "view_logs" in (session.get("permissions") or [])
    admin_context: Optional[Dict[str, Any]] = None

    if can_manage_admins:
        admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
        admin_context = _admin_management_context(admins)
        admin_context["can_view_logs"] = can_view_logs

    allowed_tabs = {"app"}
    if admin_context:
        allowed_tabs.add("admins")
    active_tab = requested_tab if requested_tab in allowed_tabs else "app"

    return render_template(
        "settings.html",
        current=current_values,
        active_tab=active_tab,
        admin_context=admin_context,
    )


@settings_bp.route("/settings/admins", methods=["GET", "POST"])
@login_required
@require_permission("manage_admins")
def manage_admins():
    admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
    current_is_god = session.get("role") == "god"
    can_access_settings = "manage_settings" in (session.get("permissions") or [])
    can_view_logs = "view_logs" in (session.get("permissions") or [])

    def _redirect_to_admins_tab():
        if can_access_settings:
            return redirect(url_for("settings.settings_index", tab="admins"))
        return redirect(url_for("settings.manage_admins"))

    if request.method == "GET" and can_access_settings:
        return _redirect_to_admins_tab()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            role = normalize_role(request.form.get("role"))
            custom_permissions = request.form.getlist("custom_permissions")

            if not username:
                flash("Username is required.", "error")
                return _redirect_to_admins_tab()

            if not password:
                flash("Password is required.", "error")
                return _redirect_to_admins_tab()

            if password != confirm:
                flash("Passwords do not match.", "error")
                return _redirect_to_admins_tab()

            if any(admin.get("username") == username for admin in admins):
                flash("An admin with that username already exists.", "error")
                return _redirect_to_admins_tab()

            if role == "custom" and not custom_permissions:
                flash("Custom roles must include at least one permission.", "error")
                return _redirect_to_admins_tab()

            if role == "god" and not current_is_god:
                flash("Only a God admin can assign the God role to another administrator.", "error")
                return _redirect_to_admins_tab()

            resolved_permissions = resolve_permissions(role, custom_permissions)

            admins.append(
                {
                    "username": username,
                    "password_hash": generate_password_hash(password),
                    "created_at": datetime.utcnow().isoformat(),
                    "role": role,
                    "permissions": resolved_permissions if role == "custom" else None,
                    "resolved_permissions": resolved_permissions,
                }
            )
            # Clean up optional permission field for non-custom roles
            if role != "custom":
                admins[-1].pop("permissions", None)

            save_admins(current_app.config["ADMINS_FILE"], admins)
            admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
            flash(f"Admin '{username}' added successfully.", "success")
            return _redirect_to_admins_tab()

        if action == "delete":
            username = request.form.get("username", "")
            if not username:
                flash("No admin selected for deletion.", "error")
                return _redirect_to_admins_tab()

            if len(admins) <= 1:
                flash("At least one admin account must remain.", "error")
                return _redirect_to_admins_tab()

            if username == session.get("user"):
                flash("You cannot delete the account currently in use.", "error")
                return _redirect_to_admins_tab()

            filtered = [admin for admin in admins if admin.get("username") != username]
            if len(filtered) == len(admins):
                flash("Admin account could not be found.", "error")
                return _redirect_to_admins_tab()

            if not any(
                "manage_admins" in resolve_permissions(admin.get("role"), admin.get("permissions"))
                for admin in filtered
            ):
                flash("At least one administrator must retain the manage administrators permission.", "error")
                return _redirect_to_admins_tab()

            save_admins(current_app.config["ADMINS_FILE"], filtered)
            admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
            flash(f"Admin '{username}' removed.", "success")
            return _redirect_to_admins_tab()

        if action == "update":
            username = request.form.get("username", "").strip()
            role = normalize_role(request.form.get("role"))
            custom_permissions = request.form.getlist("custom_permissions")

            target = next((admin for admin in admins if admin.get("username") == username), None)
            if not target:
                flash("Admin account could not be found.", "error")
                return _redirect_to_admins_tab()

            if role == "custom" and not custom_permissions:
                flash("Custom roles must include at least one permission.", "error")
                return _redirect_to_admins_tab()

            if role == "god" and not current_is_god:
                flash("Only a God admin can assign the God role to another administrator.", "error")
                return _redirect_to_admins_tab()

            target["role"] = role
            if role == "custom":
                permissions = resolve_permissions(role, custom_permissions)
                target["permissions"] = permissions
            else:
                target.pop("permissions", None)
                permissions = resolve_permissions(role)

            target["resolved_permissions"] = permissions

            if not any(
                "manage_admins" in resolve_permissions(admin.get("role"), admin.get("permissions"))
                for admin in admins
            ):
                flash("At least one administrator must retain the manage administrators permission.", "error")
                return _redirect_to_admins_tab()

            save_admins(current_app.config["ADMINS_FILE"], admins)
            admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)

            if username == session.get("user"):
                session["role"] = target.get("role")
                session["permissions"] = target.get("resolved_permissions", [])

            flash(f"Admin '{username}' updated successfully.", "success")
            return _redirect_to_admins_tab()

    context = _admin_management_context(admins)
    context["can_view_logs"] = can_view_logs
    return render_template("admins.html", **context)
