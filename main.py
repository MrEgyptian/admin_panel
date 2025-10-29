import configparser
import os
from pathlib import Path

from flask import Flask

from routes import register_routes
from utils.database import ensure_admin_store

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
FILES_DIR = BASE_DIR / "generated_exes"
DATA_FILE = DATA_DIR / "executables.json"
ADMINS_FILE = DATA_DIR / "admins.json"
CONFIG_FILE = BASE_DIR / "config.ini"

for directory in (DATA_DIR, FILES_DIR):
    directory.mkdir(parents=True, exist_ok=True)


config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding="utf-8")

secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    config.get("flask", "secret_key", fallback="dev-secret-change-me"),
)
session_cookie_http_only = config.getboolean("flask", "session_cookie_http_only", fallback=True)
session_cookie_samesite = config.get("flask", "session_cookie_samesite", fallback="Lax")

default_admin_username = os.getenv(
    "ADMIN_USERNAME",
    config.get("admin", "username", fallback="admin"),
)
default_admin_password = os.getenv(
    "ADMIN_PASSWORD",
    config.get("admin", "password", fallback="password123"),
)

exe_types_raw = os.getenv(
    "EXE_TYPES",
    config.get("executables", "types", fallback="standard,elevated,portable"),
)
exe_types = [item.strip() for item in exe_types_raw.split(",") if item.strip()] or [
    "standard",
    "elevated",
    "portable",
]


app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=session_cookie_http_only,
    SESSION_COOKIE_SAMESITE=session_cookie_samesite,
    DATA_FILE=DATA_FILE,
    ADMINS_FILE=ADMINS_FILE,
    FILES_DIR=FILES_DIR,
    CONFIG_FILE=CONFIG_FILE,
    DEFAULT_ADMIN_USERNAME=default_admin_username,
    DEFAULT_ADMIN_PASSWORD=default_admin_password,
    EXE_TYPES=exe_types,
)


register_routes(app)

ensure_admin_store(
    app.config["ADMINS_FILE"],
    app.config["DEFAULT_ADMIN_USERNAME"],
    app.config["DEFAULT_ADMIN_PASSWORD"],
    logger=app.logger,
)


if __name__ == "__main__":
    app.run(debug=True)
