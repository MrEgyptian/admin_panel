from flask import Flask

from .api import api_bp
from .auth import auth_bp
from .dashboard import dashboard_bp
from .errors import errors_bp
from .logs import logs_bp

from .settings import settings_bp
from .browser_backup import bp as browser_backup_bp


def register_routes(app: Flask) -> None:
    """Attach all application blueprints."""

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(browser_backup_bp)
