from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from routes.decorators import session_is_authenticated
from utils.database import authenticate_admin, ensure_admin_store, load_admins
from utils.roles import resolve_permissions

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    ensure_admin_store(
        current_app.config["ADMINS_FILE"],
        current_app.config["DEFAULT_ADMIN_USERNAME"],
        current_app.config["DEFAULT_ADMIN_PASSWORD"],
        logger=current_app.logger,
    )

    next_url = request.args.get("next") or request.form.get("next") or url_for("dashboard.dashboard")
    target = next_url if next_url.startswith("/") else url_for("dashboard.dashboard")

    if request.method == "GET" and session_is_authenticated():
        return redirect(target)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
        matched_admin = authenticate_admin(admins, username, password)
        if matched_admin:
            session.clear()
            session["user"] = username
            session["role"] = matched_admin.get("role")
            session["permissions"] = matched_admin.get("resolved_permissions") or resolve_permissions(
                matched_admin.get("role"), matched_admin.get("permissions")
            )
            flash("Signed in successfully.", "success")
            return redirect(target)

        flash("Invalid username or password.", "error")

    return render_template("login.html", next_url=target)


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("auth.login"))
