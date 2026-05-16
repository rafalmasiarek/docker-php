#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

HOTFIX_ID_RE = re.compile(r"^#\s*hotfix-id:\s*(?P<value>.+?)\s*$")
HOTFIX_CVES_RE = re.compile(r"^#\s*hotfix-cves:\s*(?P<value>.+?)\s*$")
HOTFIX_PACKAGES_RE = re.compile(r"^#\s*hotfix-packages:\s*(?P<value>.+?)\s*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def read_script_metadata(script: Path) -> dict[str, Any] | None:
    """
    Read only explicit metadata comments from a hotfix script.

    This is intentionally append-only and metadata-only:
    - no guessing from apk commands,
    - no backfilling legacy scripts,
    - no rewriting manually indexed scripts.
    """
    hotfix_id = ""
    cves: list[str] = []
    packages: list[str] = []

    for line in script.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.startswith("#"):
            continue

        if match := HOTFIX_ID_RE.match(line):
            hotfix_id = match.group("value").strip()
            continue

        if match := HOTFIX_CVES_RE.match(line):
            cves = split_csv(match.group("value"))
            continue

        if match := HOTFIX_PACKAGES_RE.match(line):
            packages = split_csv(match.group("value"))
            continue

    if not hotfix_id and not cves and not packages:
        return None

    missing: list[str] = []
    if not hotfix_id:
        missing.append("hotfix-id")
    if not cves:
        missing.append("hotfix-cves")
    if not packages:
        missing.append("hotfix-packages")

    if missing:
        raise SystemExit(
            f"Incomplete hotfix metadata in {script}: missing {', '.join(missing)}"
        )

    for cve in cves:
        if not CVE_RE.fullmatch(cve):
            raise SystemExit(f"Invalid CVE in {script}: {cve}")

    return {
        "id": hotfix_id,
        "file": script.name,
        "match": {
            "cves": cves,
            "packages": packages,
        },
    }


def load_index(index_path: Path) -> dict[str, Any]:
    if not index_path.exists():
        return {"hotfixes": []}

    data = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}

    if not isinstance(data, dict):
        raise SystemExit(f"Invalid index format in {index_path}: expected YAML object")

    hotfixes = data.get("hotfixes")

    if hotfixes is None:
        data["hotfixes"] = []
    elif not isinstance(hotfixes, list):
        raise SystemExit(f"Invalid index format in {index_path}: hotfixes must be a list")

    return data


def append_missing_metadata_entries(directory: Path) -> bool:
    index_path = directory / "index.yaml"
    data = load_index(index_path)

    existing_ids: set[str] = set()
    existing_files: set[str] = set()

    for item in data.get("hotfixes", []):
        if not isinstance(item, dict):
            continue

        hotfix_id = item.get("id")
        file_name = item.get("file")

        if hotfix_id:
            existing_ids.add(str(hotfix_id))
        if file_name:
            existing_files.add(str(file_name))

    appended: list[dict[str, Any]] = []

    for script in sorted(directory.glob("*.sh")):
        metadata = read_script_metadata(script)

        if metadata is None:
            print(f"Skipping {script}: no metadata comments")
            continue

        if metadata["id"] in existing_ids:
            print(f"Skipping {script}: id already indexed")
            continue

        if metadata["file"] in existing_files:
            print(f"Skipping {script}: file already indexed")
            continue

        data["hotfixes"].append(metadata)
        existing_ids.add(metadata["id"])
        existing_files.add(metadata["file"])
        appended.append(metadata)

    if not appended:
        return False

    content = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    index_path.write_text(content, encoding="utf-8")

    for item in appended:
        print(f"Appended {item['id']} to {index_path}")

    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append metadata-based hotfix scripts to index.yaml files."
    )
    parser.add_argument("--root", default="hotfixes", help="Hotfix root directory.")
    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        print(f"{root} does not exist, nothing to refresh.")
        return 0

    changed = False

    for directory in sorted({script.parent for script in root.rglob("*.sh")}):
        if append_missing_metadata_entries(directory):
            changed = True

    if not changed:
        print("No hotfix index changes needed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
