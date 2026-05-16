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


def sorted_unique(values: list[str]) -> list[str]:
    return sorted({value.strip() for value in values if value.strip()})


def read_script_metadata(script: Path) -> dict[str, Any] | None:
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

    cves = sorted_unique(cves)
    packages = sorted_unique(packages)

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


def merge_metadata_into_entry(entry: dict[str, Any], metadata: dict[str, Any]) -> bool:
    changed = False

    if not entry.get("id"):
        entry["id"] = metadata["id"]
        changed = True

    if not entry.get("file"):
        entry["file"] = metadata["file"]
        changed = True

    match = entry.setdefault("match", {})
    if not isinstance(match, dict):
        raise SystemExit(f"Invalid hotfix entry for {metadata['file']}: match must be an object")

    current_cves = match.get("cves") or []
    current_packages = match.get("packages") or []

    if not isinstance(current_cves, list):
        raise SystemExit(f"Invalid hotfix entry for {metadata['file']}: match.cves must be a list")

    if not isinstance(current_packages, list):
        raise SystemExit(f"Invalid hotfix entry for {metadata['file']}: match.packages must be a list")

    merged_cves = sorted_unique([str(cve) for cve in current_cves] + metadata["match"]["cves"])
    merged_packages = sorted_unique(
        [str(package) for package in current_packages] + metadata["match"]["packages"]
    )

    if merged_cves != current_cves:
        match["cves"] = merged_cves
        changed = True

    if merged_packages != current_packages:
        match["packages"] = merged_packages
        changed = True

    return changed


def append_or_update_metadata_entries(directory: Path) -> bool:
    index_path = directory / "index.yaml"
    data = load_index(index_path)

    by_id: dict[str, dict[str, Any]] = {}
    by_file: dict[str, dict[str, Any]] = {}

    for item in data.get("hotfixes", []):
        if not isinstance(item, dict):
            continue

        hotfix_id = item.get("id")
        file_name = item.get("file")

        if hotfix_id:
            by_id[str(hotfix_id)] = item

        if file_name:
            by_file[str(file_name)] = item

    changed = False

    for script in sorted(directory.glob("*.sh")):
        metadata = read_script_metadata(script)

        if metadata is None:
            print(f"Skipping {script}: no metadata comments")
            continue

        existing = by_file.get(metadata["file"]) or by_id.get(metadata["id"])

        if existing is not None:
            if merge_metadata_into_entry(existing, metadata):
                print(f"Updated {metadata['id']} in {index_path}")
                changed = True
            else:
                print(f"Skipping {script}: already indexed")
            continue

        data["hotfixes"].append(metadata)
        by_id[metadata["id"]] = metadata
        by_file[metadata["file"]] = metadata
        changed = True

        print(f"Appended {metadata['id']} to {index_path}")

    if not changed:
        return False

    content = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    index_path.write_text(content, encoding="utf-8")

    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append or update metadata-based hotfix entries in index.yaml files."
    )
    parser.add_argument("--root", default="hotfixes", help="Hotfix root directory.")
    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        print(f"{root} does not exist, nothing to refresh.")
        return 0

    changed = False

    for directory in sorted({script.parent for script in root.rglob("*.sh")}):
        if append_or_update_metadata_entries(directory):
            changed = True

    if not changed:
        print("No hotfix index changes needed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())