# Admin Panel

A Flask-based administrative control panel for managing executable builds, administrators, and activity logs. The interface provides role-based access control (RBAC), configurable application settings, and an audit trail for key actions.

## Features

- Role-aware dashboards with per-permission controls for viewing and managing executables.
- Executable lifecycle management: create, update metadata, download, and delete artefacts stored on disk.
- Template-driven executable builds compiled with PyInstaller from curated Python templates.
- Centralised activity logging across users, executables, and recent events with tabbed filters and clear actions.
- Administrator management with modal-driven add/update flows and configurable permissions.
- Application settings surface with live persistence to `config.ini`, including session options and executable download visibility.
- JSON-based persistence for executables, administrators, and logs to simplify deployment.

## Prerequisites

- Python 3.10+
- pip (or compatible environment manager)

> The project expects a writable `data/` directory and a `generated_exes/` folder for executable artefacts. These are created automatically when the application starts.

## Installation

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

If `requirements.txt` is missing, install the core dependencies manually:

```bash
pip install flask werkzeug
```

## Configuration

Runtime configuration lives in `config.ini`. Key sections include:

- `[flask]`: session secret key, cookie behaviour.
- `[admin]`: default administrator bootstrap credentials (used on first launch only).
- `[executables]`:
  - `types`: comma-separated list of executable classifications available in the UI.
  - `public_downloads`: `true` to allow anonymous access to `/executables/<id>/download`; `false` keeps downloads gated behind authentication (`view_dashboard`).

Environment variables (`FLASK_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `EXE_TYPES`) override matching config values when present.

## Running Locally

```bash
python main.py
```

The app starts in debug mode on `http://127.0.0.1:5000/`. Log in with the bootstrap admin credentials from `config.ini` or environment variables, then update the password under Settings → Administrators.

## Testing

Automated tests are not bundled yet. Suggested next steps:

1. Add unit tests for log utilities in `utils/logs.py`.
2. Cover route-level permissions and configuration toggles with integration tests (e.g. using `pytest` and `pytest-flask`).

## Project Structure

```
my project/
├── main.py                # Flask application factory and bootstrap
├── routes/                # Blueprint routes (dashboard, settings, logs, auth, errors)
├── templates/             # Jinja templates for UI views
├── utils/                 # Helper modules (logging, executables, database)
├── data/                  # JSON persistence (created at runtime)
└── generated_exes/        # Generated executable files
```

## Logging

User actions are recorded to `data/logs.json`. Review activity via the Logs tab in the UI or by inspecting the JSON directly. The log viewer provides filters by priority, source, tag, and free-text search, along with section-specific clear operations.

## Deployment Notes

- Disable debug mode (`FLASK_ENV=production`) and configure a stronger secret key before exposing the app publicly.
- Serve behind a production-grade WSGI server (e.g. gunicorn, waitress) and front-end proxy for TLS termination.
- Harden the generated executables directory by limiting write permissions and monitoring for tampering.
