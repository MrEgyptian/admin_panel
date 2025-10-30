import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.database import read_json, write_json

OptionDef = Dict[str, str]
TypeDefinition = Dict[str, Any]


def _slugify(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
    return slug or "option"


def _normalize_options(options: Any) -> List[OptionDef]:
    normalized: List[OptionDef] = []
    if isinstance(options, list):
        for item in options:
            if isinstance(item, dict):
                key = str(item.get("key") or "").strip()
                label = str(item.get("label") or "").strip() or key or "Option"
                key = _slugify(key or label)
                normalized.append({"key": key, "label": label})
            elif isinstance(item, str):
                label = item.strip()
                if not label:
                    continue
                key = _slugify(label)
                normalized.append({"key": key, "label": label})
    return _deduplicate_options(normalized)


def _deduplicate_options(options: List[OptionDef]) -> List[OptionDef]:
    seen: set[str] = set()
    result: List[OptionDef] = []
    for option in options:
        key = option["key"]
        label = option["label"]
        base_key = key
        counter = 2
        while key in seen:
            key = f"{base_key}_{counter}"
            counter += 1
        seen.add(key)
        result.append({"key": key, "label": label})
    return result


def build_options_from_labels(labels: List[str], existing: Optional[List[OptionDef]] = None) -> List[OptionDef]:
    existing = existing or []
    existing_map = {item["label"].lower(): item for item in existing}
    existing_keys = {item["key"] for item in existing}

    result: List[OptionDef] = []
    used_keys: set[str] = set()

    for label in labels:
        normalized_label = label.strip()
        if not normalized_label:
            continue

        existing_match = existing_map.get(normalized_label.lower())
        if existing_match:
            key = existing_match["key"]
        else:
            base_key = _slugify(normalized_label)
            key = base_key
            counter = 2
            while key in used_keys or key in existing_keys:
                key = f"{base_key}_{counter}"
                counter += 1
        result.append({"key": key, "label": normalized_label})
        used_keys.add(result[-1]["key"])

    return _deduplicate_options(result)


def parse_option_string(raw: str) -> List[str]:
    if not isinstance(raw, str):
        return []
    parts = re.split(r"[\n,]", raw)
    return [item.strip() for item in parts if item.strip()]


def normalize_type_definitions(definitions: Any, fallback_names: Optional[List[str]] = None) -> List[TypeDefinition]:
    normalized: List[TypeDefinition] = []
    if isinstance(definitions, list):
        for item in definitions:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            template = str(item.get("template") or "").strip()
            options = _normalize_options(item.get("options"))
            normalized.append(
                {
                    "name": name,
                    "template": template,
                    "options": options,
                }
            )

    if not normalized and fallback_names:
        for name in fallback_names:
            normalized.append({"name": name, "template": "", "options": []})

    # ensure unique names preserving order
    seen_names: set[str] = set()
    unique: List[TypeDefinition] = []
    for item in normalized:
        key = item["name"].lower()
        if key in seen_names:
            continue
        seen_names.add(key)
        unique.append(item)
    return unique


def load_type_definitions(file_path: Path, fallback_names: Optional[List[str]] = None) -> List[TypeDefinition]:
    data = read_json(file_path, default=[], logger=None)
    return normalize_type_definitions(data, fallback_names)


def save_type_definitions(file_path: Path, definitions: List[TypeDefinition]) -> None:
    write_json(file_path, definitions)


__all__ = [
    "TypeDefinition",
    "OptionDef",
    "load_type_definitions",
    "save_type_definitions",
    "normalize_type_definitions",
    "parse_option_string",
    "build_options_from_labels",
]
