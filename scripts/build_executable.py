import argparse
import json
import os
import sys
from pathlib import Path

from PyInstaller.__main__ import run as pyinstaller_run  # type: ignore[import]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an executable using PyInstaller based on supplied context.")
    parser.add_argument("--context", required=True, help="Path to the build context JSON file.")
    return parser.parse_args()


def _load_context(path: str) -> dict:
    context_path = Path(path)
    if not context_path.exists():
        raise FileNotFoundError(f"Build context file not found: {context_path}")
    with context_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _ensure_paths(context: dict) -> None:
    dist_path = Path(context["dist_path"])
    dist_path.mkdir(parents=True, exist_ok=True)
    Path(context["work_path"]).mkdir(parents=True, exist_ok=True)
    Path(context["spec_path"]).mkdir(parents=True, exist_ok=True)


def build_from_context(context: dict) -> None:
    _ensure_paths(context)

    metadata_path = context["metadata_path"]
    add_data_arg = f"{metadata_path}{os.pathsep}."

    args = [
        context["source"],
        "--onefile",
        "--noconsole",
        "--noconfirm",
        "--clean",
        "--name",
        context["exe_name"],
        "--distpath",
        context["dist_path"],
        "--workpath",
        context["work_path"],
        "--specpath",
        context["spec_path"],
        "--add-data",
        add_data_arg,
    ]

    pyinstaller_run(args)


def main() -> None:
    args = _parse_args()
    context = _load_context(args.context)
    build_from_context(context)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        # Re-raise so the calling process can capture return code.
        raise
    except Exception as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        sys.exit(1)
