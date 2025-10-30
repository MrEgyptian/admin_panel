from flask import Flask

from .auth import auth_bp
from .dashboard import dashboard_bp
from .errors import errors_bp
from .logs import logs_bp
from .settings import settings_bp


def register_routes(app: Flask) -> None:
    """Attach all application blueprints."""

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(settings_bp)
