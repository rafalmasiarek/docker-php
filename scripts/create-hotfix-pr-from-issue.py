#!/usr/bin/env python3
"""
Create Alpine hotfix files from a managed Trivy security issue.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml


HOTFIX_MARKER_RE = re.compile(
    r"<!--\s*trivy-hotfix-json:\s*(.*?)\s*-->",
    re.DOTALL,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_ID_RE = re.compile(r"[^a-z0-9._-]+")


def run_json(args: list[str]) -> Any:
    output = subprocess.check_output(args, text=True)
    return json.loads(output)


def slug(value: str) -> str:
    value = value.strip().lower()
    value = SAFE_ID_RE.sub("-", value)
    value = value.strip("-")
    return value or "unknown"


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [value.strip()] if value.strip() else []

    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                result.append(text)
        return result

    return []


def extract_hotfix_json(body: str) -> dict[str, Any]:
    match = HOTFIX_MARKER_RE.search(body or "")
    if not match:
        raise SystemExit("Missing trivy-hotfix-json marker in issue body.")

    raw_json = match.group(1).strip()

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid trivy-hotfix-json marker: {exc}") from exc

    if not isinstance(data, dict):
        raise SystemExit("trivy-hotfix-json marker must contain a JSON object.")

    return data


def normalize_hotfix_data(data: dict[str, Any]) -> dict[str, Any]:
    cves = normalize_list(data.get("cves"))

    cve = str(data.get("cve") or "").strip()
    if cve:
        cves.append(cve)

    cves = sorted(set(cves))

    for cve_item in cves:
        if not CVE_RE.match(cve_item):
            raise SystemExit(f"Invalid CVE value: {cve_item}")

    alpine_minor = str(data.get("alpine_minor") or "").strip()
    alpine_full_versions = normalize_list(data.get("alpine_full_versions"))

    if not alpine_full_versions and alpine_minor:
        alpine_full_versions = [alpine_minor]

    packages_raw = data.get("packages") or []
    if not isinstance(packages_raw, list):
        raise SystemExit("packages must be a list in trivy-hotfix-json.")

    packages: list[dict[str, str]] = []

    for item in packages_raw:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name") or item.get("package") or "").strip()
        installed_version = str(item.get("installed_version") or "").strip()
        fixed_version = str(item.get("fixed_version") or "").strip()

        if not name:
            continue

        if not fixed_version or fixed_version.lower() == "unknown":
            continue

        packages.append(
            {
                "name": name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
            }
        )

    if not cves:
        raise SystemExit("No CVEs found in trivy-hotfix-json.")

    if not alpine_full_versions:
        raise SystemExit("No Alpine versions found in trivy-hotfix-json.")

    if not packages:
        raise SystemExit("No fixed packages found in trivy-hotfix-json.")

    return {
        "schema_version": int(data.get("schema_version") or 1),
        "source": str(data.get("source") or "trivy-cve-sync"),
        "scope": str(data.get("scope") or ""),
        "severity": str(data.get("severity") or ""),
        "php": str(data.get("php") or ""),
        "alpine_minor": alpine_minor,
        "alpine_full_versions": sorted(set(alpine_full_versions)),
        "php_branches": normalize_list(data.get("php_branches")),
        "variants": normalize_list(data.get("variants")),
        "cves": cves,
        "packages": packages,
    }


def load_index(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"hotfixes": []}

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    if not isinstance(data, dict):
        raise SystemExit(f"Invalid YAML root in {path}")

    data.setdefault("hotfixes", [])

    if not isinstance(data["hotfixes"], list):
        raise SystemExit(f"Invalid hotfixes list in {path}")

    return data


def save_index(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )


def upsert_hotfix(index: dict[str, Any], entry: dict[str, Any]) -> None:
    hotfixes = index.setdefault("hotfixes", [])

    for idx, existing in enumerate(hotfixes):
        if existing.get("id") == entry["id"]:
            hotfixes[idx] = entry
            return

    hotfixes.append(entry)


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_upgrade_args(packages: list[dict[str, str]]) -> list[str]:
    args: list[str] = []

    for package in packages:
        name = package["name"].strip()
        fixed_version = package["fixed_version"].strip()

        if not name or not fixed_version:
            continue

        args.append(shell_single_quote(f"{name}>={fixed_version}"))

    return sorted(set(args))


def write_hotfix_script(path: Path, packages: list[dict[str, str]]) -> None:
    upgrade_args = build_upgrade_args(packages)

    if not upgrade_args:
        raise SystemExit("No apk upgrade arguments were generated.")

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        "#!/usr/bin/env sh\n"
        "set -eu\n"
        "\n"
        f"apk upgrade --no-cache {' '.join(upgrade_args)}\n",
        encoding="utf-8",
    )

    path.chmod(path.stat().st_mode | 0o111)


def build_package_match_rules(packages: list[dict[str, str]]) -> list[str]:
    rules: list[str] = []

    for package in packages:
        name = package["name"].strip()
        fixed_version = package["fixed_version"].strip()

        if not name or not fixed_version:
            continue

        rules.append(f"{name}<{fixed_version}")

    return sorted(set(rules))


def merge_existing_cves(index: dict[str, Any], hotfix_id: str, cves: list[str]) -> list[str]:
    merged = set(cves)

    for item in index.get("hotfixes", []):
        if item.get("id") != hotfix_id:
            continue

        for cve in item.get("match", {}).get("cves", []) or []:
            if isinstance(cve, str) and cve.strip():
                merged.add(cve.strip())

    return sorted(merged)


def generate_hotfix_files(data: dict[str, Any]) -> list[str]:
    changed_files: list[str] = []

    cve_slug = slug("-".join(cve.lower() for cve in data["cves"]))
    hotfix_id = f"apk-upgrade-{cve_slug}"
    script_name = f"{hotfix_id}.sh"

    for alpine_version in data["alpine_full_versions"]:
        hotfix_dir = Path("hotfixes") / "alpine" / alpine_version
        script_path = hotfix_dir / script_name
        index_path = hotfix_dir / "index.yaml"

        index = load_index(index_path)
        merged_cves = merge_existing_cves(index, hotfix_id, data["cves"])

        write_hotfix_script(script_path, data["packages"])

        entry = {
            "id": hotfix_id,
            "file": script_name,
            "match": {
                "cves": merged_cves,
                "packages": build_package_match_rules(data["packages"]),
            },
        }

        upsert_hotfix(index, entry)
        save_index(index_path, index)

        changed_files.append(str(script_path))
        changed_files.append(str(index_path))

    return sorted(set(changed_files))


def build_pr_summary(issue_number: str, data: dict[str, Any], changed_files: list[str]) -> str:
    cves = ", ".join(f"`{cve}`" for cve in data["cves"])
    alpine_versions = ", ".join(f"`{version}`" for version in data["alpine_full_versions"])

    package_lines = []
    for package in data["packages"]:
        package_lines.append(
            f"- `{package['name']}`: `{package['installed_version'] or 'unknown'}` -> `{package['fixed_version']}`"
        )

    file_lines = [f"- `{path}`" for path in changed_files]

    return "\n".join(
        [
            f"Adds an Alpine hotfix generated from security issue #{issue_number}.",
            "",
            "## CVEs",
            cves,
            "",
            "## Alpine versions",
            alpine_versions,
            "",
            "## Package constraints",
            *package_lines,
            "",
            "## Generated files",
            *file_lines,
            "",
            "After merge, the regular image build will verify whether the CVE is gone.",
            "",
            f"Fixes #{issue_number}",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Alpine hotfix files from a managed Trivy security issue."
    )
    parser.add_argument("--repo", required=True, help="GitHub repository, for example owner/repo.")
    parser.add_argument("--issue", required=True, help="GitHub issue number.")
    parser.add_argument(
        "--output",
        default="generated-hotfix.json",
        help="Write generated PR summary to this file.",
    )

    args = parser.parse_args()

    issue = run_json(
        [
            "gh",
            "issue",
            "view",
            str(args.issue),
            "--repo",
            args.repo,
            "--json",
            "number,title,body,labels",
        ]
    )

    body = issue.get("body") or ""
    hotfix_json = extract_hotfix_json(body)
    data = normalize_hotfix_data(hotfix_json)
    changed_files = generate_hotfix_files(data)

    summary = build_pr_summary(str(args.issue), data, changed_files)

    Path(args.output).write_text(summary, encoding="utf-8")

    report = {
        "issue": int(args.issue),
        "data": data,
        "changed_files": changed_files,
    }

    Path("generated-hotfix-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())