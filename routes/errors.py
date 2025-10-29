from flask import Blueprint, render_template

errors_bp = Blueprint("errors", __name__)


@errors_bp.app_errorhandler(403)
def handle_forbidden(error):
    return render_template("errors/403.html"), 403


@errors_bp.app_errorhandler(404)
def handle_not_found(error):
    return render_template("errors/404.html"), 404


@errors_bp.app_errorhandler(500)
def handle_server_error(error):
    return render_template("errors/500.html"), 500
