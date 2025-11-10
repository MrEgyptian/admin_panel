import configparser
import os
from pathlib import Path

from flask import Flask

from routes import register_routes
from utils.database import ensure_admin_store
from utils.exe_types import load_type_definitions, save_type_definitions

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
FILES_DIR = BASE_DIR / "generated_exes"
TEMPLATE_DIR = BASE_DIR / "exe_templates"
TYPE_DEFS_FILE = DATA_DIR / "exe_types.json"
DATA_FILE = DATA_DIR / "executables.json"
ADMINS_FILE = DATA_DIR / "admins.json"
LOGS_FILE = DATA_DIR / "logs.json"
CONFIG_FILE = BASE_DIR / "config.ini"

for directory in (DATA_DIR, FILES_DIR, TEMPLATE_DIR):
    directory.mkdir(parents=True, exist_ok=True)


config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding="utf-8")
for section in ("flask", "admin", "executables", "api"):
    if not config.has_section(section):
        config.add_section(section)

secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    config.get("flask", "secret_key", fallback="dev-secret-change-me"),
)
session_cookie_http_only = config.getboolean("flask", "session_cookie_http_only", fallback=True)
session_cookie_samesite = config.get("flask", "session_cookie_samesite", fallback="Lax")

exe_types_raw = os.getenv(
    "EXE_TYPES",
    config.get("executables", "types", fallback="standard,elevated,portable"),
)
exe_types = [item.strip() for item in exe_types_raw.split(",") if item.strip()] or [
    "standard",
    "elevated",
    "portable",
]

api_base_url = os.getenv(
    "API_BASE_URL",
    config.get("api", "host", fallback=""),
).strip()
if api_base_url:
    api_base_url = api_base_url.rstrip("/")

type_definitions = load_type_definitions(TYPE_DEFS_FILE, exe_types)
if not type_definitions:
    type_definitions = [{"name": name, "template": "", "options": []} for name in exe_types]
    save_type_definitions(TYPE_DEFS_FILE, type_definitions)
exe_types = [definition["name"] for definition in type_definitions]
default_admin_username = os.getenv(
    "ADMIN_USERNAME",
    config.get("admin", "username", fallback="admin"),
)
default_admin_password = os.getenv(
    "ADMIN_PASSWORD",
    config.get("admin", "password", fallback="password123"),
)

executables_public_downloads = config.getboolean(
    "executables",
    "public_downloads",
    fallback=False,
)


app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=session_cookie_http_only,
    SESSION_COOKIE_SAMESITE=session_cookie_samesite,
    DATA_FILE=DATA_FILE,
    ADMINS_FILE=ADMINS_FILE,
    FILES_DIR=FILES_DIR,
    EXE_TYPE_DEFS_FILE=TYPE_DEFS_FILE,
    EXE_TEMPLATE_DIR=TEMPLATE_DIR,
    LOGS_FILE=LOGS_FILE,
    CONFIG_FILE=CONFIG_FILE,
    DEFAULT_ADMIN_USERNAME=default_admin_username,
    DEFAULT_ADMIN_PASSWORD=default_admin_password,
    EXE_TYPES=exe_types,
    EXE_TYPE_DEFS=type_definitions,
    EXECUTABLE_DOWNLOADS_PUBLIC=executables_public_downloads,
    API_BASE_URL=api_base_url,
)


register_routes(app)

ensure_admin_store(
    app.config["ADMINS_FILE"],
    app.config["DEFAULT_ADMIN_USERNAME"],
    app.config["DEFAULT_ADMIN_PASSWORD"],
    logger=app.logger,
)


if __name__ == "__main__":
    os.environ["WATCHFILES_IGNORE_PATHS"] = (
    "site-packages,PyInstaller,anaconda3,Lib,AppData"
)
    os.environ["WATCHFILES_FORCE_POLLING"] = "true"  # optional, stabilizes watcher on Windows
    app.run(debug=True, use_reloader=True, reloader_type='stat')
