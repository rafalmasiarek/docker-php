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
    return sorted({item.strip() for item in value.split(",") if item.strip()})


def read_metadata(script: Path) -> dict[str, Any]:
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

    if not hotfix_id:
        hotfix_id = script.stem

    if not cves:
        found = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", script.read_text(encoding="utf-8", errors="ignore"))))
        cves = found

    for cve in cves:
        if not CVE_RE.match(cve):
            raise SystemExit(f"Invalid CVE in {script}: {cve}")

    if not packages:
        raise SystemExit(
            f"Missing hotfix package metadata in {script}. "
            "Expected comment: # hotfix-packages: package<version"
        )

    return {
        "id": hotfix_id,
        "file": script.name,
        "match": {
            "cves": cves,
            "packages": packages,
        },
    }


def write_index(directory: Path) -> bool:
    scripts = sorted(directory.glob("*.sh"))
    index_path = directory / "index.yaml"

    if not scripts:
        if index_path.exists():
            index_path.unlink()
            return True
        return False

    hotfixes = [read_metadata(script) for script in scripts]
    hotfixes = sorted(hotfixes, key=lambda item: item["id"])

    data = {
        "hotfixes": hotfixes,
    }

    content = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )

    old_content = index_path.read_text(encoding="utf-8") if index_path.exists() else ""

    if old_content == content:
        return False

    index_path.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate hotfix index.yaml files from hotfix shell scripts.")
    parser.add_argument("--root", default="hotfixes", help="Hotfix root directory.")
    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        print(f"{root} does not exist, nothing to refresh.")
        return 0

    directories = sorted({script.parent for script in root.rglob("*.sh")})
    changed = False

    for directory in directories:
        if write_index(directory):
            print(f"Refreshed {directory / 'index.yaml'}")
            changed = True

    return 0 if changed or not changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
