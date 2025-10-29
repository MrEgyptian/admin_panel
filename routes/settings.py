import configparser
from datetime import datetime
from pathlib import Path
from typing import List

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

from routes.decorators import login_required, require_permission
from utils.database import load_admins, save_admins
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
    for section in ("flask", "admin", "executables"):
        if not parser.has_section(section):
            parser.add_section(section)
    return parser


def _write_config(parser: configparser.ConfigParser) -> None:
    config_file: Path = current_app.config["CONFIG_FILE"]
    with config_file.open("w", encoding="utf-8") as handle:
        parser.write(handle)


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
@require_permission("manage_settings")
def settings_index():
    parser = _config_parser()

    if request.method == "POST":
        secret_key = request.form.get("secret_key", "").strip()
        same_site = request.form.get("session_cookie_samesite", "Lax").strip()
        http_only = request.form.get("session_cookie_http_only") == "on"
        exe_types_raw = request.form.get("exe_types", "").strip()

        if not secret_key:
            flash("Secret key cannot be empty.", "error")
            return redirect(url_for("settings.settings_index"))

        allowed_same_site = {"Lax", "Strict", "None"}
        if same_site not in allowed_same_site:
            flash("Invalid SameSite value selected.", "error")
            return redirect(url_for("settings.settings_index"))

        exe_types: List[str] = [item.strip() for item in exe_types_raw.split(",") if item.strip()]
        if not exe_types:
            flash("Executable types cannot be empty.", "error")
            return redirect(url_for("settings.settings_index"))

        parser.set("flask", "secret_key", secret_key)
        parser.set("flask", "session_cookie_http_only", "true" if http_only else "false")
        parser.set("flask", "session_cookie_samesite", same_site)
        parser.set("executables", "types", ",".join(exe_types))

        _write_config(parser)

        current_app.config.update(
            SECRET_KEY=secret_key,
            SESSION_COOKIE_HTTPONLY=http_only,
            SESSION_COOKIE_SAMESITE=same_site,
            EXE_TYPES=exe_types,
        )

        flash("Settings saved successfully.", "success")
        return redirect(url_for("settings.settings_index"))

    current_values = {
        "secret_key": current_app.config["SECRET_KEY"],
        "session_cookie_http_only": current_app.config.get("SESSION_COOKIE_HTTPONLY", True),
        "session_cookie_samesite": current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        "exe_types": ", ".join(current_app.config.get("EXE_TYPES", [])),
    }

    return render_template("settings.html", current=current_values)


@settings_bp.route("/settings/admins", methods=["GET", "POST"])
@login_required
@require_permission("manage_admins")
def manage_admins():
    admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)

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
                return redirect(url_for("settings.manage_admins"))

            if not password:
                flash("Password is required.", "error")
                return redirect(url_for("settings.manage_admins"))

            if password != confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("settings.manage_admins"))

            if any(admin.get("username") == username for admin in admins):
                flash("An admin with that username already exists.", "error")
                return redirect(url_for("settings.manage_admins"))

            if role == "custom" and not custom_permissions:
                flash("Custom roles must include at least one permission.", "error")
                return redirect(url_for("settings.manage_admins"))

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
            flash(f"Admin '{username}' added successfully.", "success")
            return redirect(url_for("settings.manage_admins"))

        if action == "delete":
            username = request.form.get("username", "")
            if not username:
                flash("No admin selected for deletion.", "error")
                return redirect(url_for("settings.manage_admins"))

            if len(admins) <= 1:
                flash("At least one admin account must remain.", "error")
                return redirect(url_for("settings.manage_admins"))

            if username == session.get("user"):
                flash("You cannot delete the account currently in use.", "error")
                return redirect(url_for("settings.manage_admins"))

            filtered = [admin for admin in admins if admin.get("username") != username]
            if len(filtered) == len(admins):
                flash("Admin account could not be found.", "error")
                return redirect(url_for("settings.manage_admins"))

            if not any(
                "manage_admins" in resolve_permissions(admin.get("role"), admin.get("permissions"))
                for admin in filtered
            ):
                flash("At least one administrator must retain the manage administrators permission.", "error")
                return redirect(url_for("settings.manage_admins"))

            save_admins(current_app.config["ADMINS_FILE"], filtered)
            flash(f"Admin '{username}' removed.", "success")
            return redirect(url_for("settings.manage_admins"))

        if action == "update":
            username = request.form.get("username", "").strip()
            role = normalize_role(request.form.get("role"))
            custom_permissions = request.form.getlist("custom_permissions")

            target = next((admin for admin in admins if admin.get("username") == username), None)
            if not target:
                flash("Admin account could not be found.", "error")
                return redirect(url_for("settings.manage_admins"))

            if role == "custom" and not custom_permissions:
                flash("Custom roles must include at least one permission.", "error")
                return redirect(url_for("settings.manage_admins"))

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
                return redirect(url_for("settings.manage_admins"))

            save_admins(current_app.config["ADMINS_FILE"], admins)

            if username == session.get("user"):
                session["role"] = target.get("role")
                session["permissions"] = target.get("resolved_permissions", [])

            flash(f"Admin '{username}' updated successfully.", "success")
            return redirect(url_for("settings.manage_admins"))

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

    return render_template(
        "admins.html",
        admins=enriched_admins,
        roles=role_options,
        permissions=AVAILABLE_PERMISSIONS,
    )
