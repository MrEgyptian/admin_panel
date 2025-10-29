from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast

from flask import abort, current_app, g, redirect, request, session, url_for

from utils.database import load_admins
from utils.roles import resolve_permissions

F = TypeVar("F", bound=Callable[..., Any])


def _fetch_current_admin() -> Optional[dict]:
    current_user = session.get("user")
    if not current_user:
        return None

    admins = load_admins(current_app.config["ADMINS_FILE"], logger=current_app.logger)
    for admin in admins:
        if admin.get("username") == current_user:
            resolved = admin.get("resolved_permissions") or resolve_permissions(
                admin.get("role"), admin.get("permissions")
            )
            admin["resolved_permissions"] = resolved
            return admin
    return None


def session_is_authenticated() -> bool:
    if "current_admin" not in g:
        g.current_admin = _fetch_current_admin()

    admin = g.get("current_admin")
    if not admin:
        session.pop("user", None)
        session.pop("role", None)
        session.pop("permissions", None)
        return False

    session["role"] = admin.get("role")
    session["permissions"] = admin.get("resolved_permissions", [])
    return True


def login_required(view: F) -> F:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if not session_is_authenticated():
            next_target = request.path if request.method == "GET" else url_for("dashboard.dashboard")
            return redirect(url_for("auth.login", next=next_target))
        return view(*args, **kwargs)

    return cast(F, wrapped_view)


def has_permission(permission: str) -> bool:
    if not session_is_authenticated():
        return False

    admin = g.get("current_admin")
    if not admin:
        return False

    permissions = admin.get("resolved_permissions") or []
    return permission in permissions


def require_permission(permission: str) -> Callable[[F], F]:
    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped_view(*args: Any, **kwargs: Any) -> Any:
            if not session_is_authenticated():
                next_target = request.path if request.method == "GET" else url_for("dashboard.dashboard")
                return redirect(url_for("auth.login", next=next_target))

            if not has_permission(permission):
                abort(403)

            return view(*args, **kwargs)

        return cast(F, wrapped_view)

    return decorator
