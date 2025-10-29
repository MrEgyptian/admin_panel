from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

AVAILABLE_PERMISSIONS: List[Dict[str, str]] = [
    {
        "name": "view_dashboard",
        "label": "View dashboard & download executables",
    },
    {
        "name": "manage_executables",
        "label": "Create, revoke, and delete executables",
    },
    {
        "name": "manage_settings",
        "label": "Update application configuration",
    },
    {
        "name": "manage_admins",
        "label": "Add or remove administrator accounts",
    },
]

ROLE_DEFINITIONS: Dict[str, Dict[str, object]] = {
    "god": {
        "label": "God Admin",
        "description": "Full system control, cannot be restricted.",
        "permissions": ["*"],
    },
    "super_admin": {
        "label": "Super Admin",
        "description": "Manage executables, settings, and administrator accounts.",
        "permissions": [
            "view_dashboard",
            "manage_executables",
            "manage_settings",
            "manage_admins",
        ],
    },
    "normal_admin": {
        "label": "Normal Admin",
        "description": "Manage executables only.",
        "permissions": ["view_dashboard", "manage_executables"],
    },
    "custom": {
        "label": "Custom",
        "description": "Select an explicit set of permissions.",
        "permissions": [],
    },
}

ROLE_DISPLAY_ORDER: List[str] = ["god", "super_admin", "normal_admin", "custom"]
DEFAULT_ROLE: str = "super_admin"


def _all_permission_names() -> List[str]:
    return [entry["name"] for entry in AVAILABLE_PERMISSIONS]


def normalize_role(role: Optional[str]) -> str:
    if not role:
        return DEFAULT_ROLE
    if role not in ROLE_DEFINITIONS:
        return DEFAULT_ROLE
    return role


def resolve_permissions(role: str, custom_permissions: Optional[Iterable[str]] = None) -> List[str]:
    role = normalize_role(role)
    available: Set[str] = set(_all_permission_names())

    definition = ROLE_DEFINITIONS.get(role, {})
    declared = definition.get("permissions", []) if isinstance(definition, dict) else []

    if isinstance(declared, list) and "*" in declared:
        return list(sorted(available))

    if role == "custom":
        selected = set(custom_permissions or [])
        return list(sorted(available.intersection(selected)))

    if isinstance(declared, list):
        return [perm for perm in declared if perm in available]

    return list(sorted(available))


def normalize_admin_record(admin: Dict[str, object]) -> Dict[str, object]:
    record = dict(admin)
    role = normalize_role(record.get("role"))
    record["role"] = role

    if role == "custom":
        custom_perms = record.get("permissions")
        if isinstance(custom_perms, list):
            record["permissions"] = resolve_permissions(role, custom_perms)
        else:
            record["permissions"] = []
    else:
        record.pop("permissions", None)

    record["resolved_permissions"] = resolve_permissions(role, record.get("permissions"))
    return record


def admin_has_permission(admin: Dict[str, object], permission: str) -> bool:
    permissions = admin.get("resolved_permissions")
    if isinstance(permissions, list):
        return permission in permissions
    role = normalize_role(admin.get("role"))
    return permission in resolve_permissions(role, admin.get("permissions"))


def permission_labels_map() -> Dict[str, str]:
    return {entry["name"]: entry["label"] for entry in AVAILABLE_PERMISSIONS}