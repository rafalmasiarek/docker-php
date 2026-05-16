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

HOTFIX_MARKER_PATTERNS = [
    re.compile(r"<!--\s*trivy-hotfix-json\s*(?P<json>.*?)\s*-->", re.DOTALL),
    re.compile(
        r"<!--\s*trivy-hotfix-json:start\s*-->\s*(?P<json>.*?)\s*<!--\s*trivy-hotfix-json:end\s*-->",
        re.DOTALL,
    ),
    re.compile(r"```trivy-hotfix-json\s*(?P<json>.*?)\s*```", re.DOTALL),
]

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
        value = value.strip()
        return [value] if value else []

    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                result.append(text)
        return result

    return []


def extract_hotfix_json(body: str) -> dict[str, Any]:
    for pattern in HOTFIX_MARKER_PATTERNS:
        match = pattern.search(body or "")
        if not match:
            continue

        raw_json = match.group("json").strip()

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            raise SystemExit("trivy-hotfix-json marker must contain a JSON object.")

        return data

    raise SystemExit("Missing or invalid trivy-hotfix-json marker in issue body.")


def extract_hotfix_data_from_legacy_issue(body: str) -> dict[str, Any]:
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", body)))

    alpine_minor = ""
    alpine_full_versions: list[str] = []

    match = re.search(
        r"Alpine branch:\s*`([^`]+)`",
        body,
        re.IGNORECASE,
    )
    if match:
        alpine_minor = match.group(1).strip()

    match = re.search(
        r"Alpine version detected in affected images:\s*`([^`]+)`",
        body,
        re.IGNORECASE,
    )
    if match:
        alpine_full_versions = [
            item.strip()
            for item in match.group(1).split(",")
            if item.strip()
        ]

    packages: list[dict[str, str]] = []

    def add_package(name: str, installed_version: str, fixed_version: str) -> None:
        name = name.strip()
        installed_version = installed_version.strip()
        fixed_version = fixed_version.strip()

        if not re.match(r"^[a-z0-9][a-z0-9+_.-]*$", name, re.IGNORECASE):
            return

        if fixed_version.lower() in {"unknown", "none", "n/a"}:
            return

        if not re.search(r"\d", fixed_version):
            return

        item = {
            "name": name,
            "installed_version": installed_version,
            "fixed_version": fixed_version,
        }

        if item not in packages:
            packages.append(item)

    # Format rendered/plain:
    # `curl` `8.17.0-r1` `8.19.0-r0`
    for name, installed_version, fixed_version in re.findall(
        r"`([^`]+)`\s+`([^`]+)`\s+`([^`]+)`",
        body,
    ):
        add_package(name, installed_version, fixed_version)

    # Markdown table format:
    # | `curl` | `8.17.0-r1` | `8.19.0-r0` |
    for line in body.splitlines():
        stripped = line.strip()

        if not stripped.startswith("|"):
            continue

        cells = [
            cell.strip().strip("`").strip()
            for cell in stripped.strip("|").split("|")
        ]

        if len(cells) < 3:
            continue

        name, installed_version, fixed_version = cells[:3]

        if name.lower() in {"package", "packages"}:
            continue

        if set(name) <= {"-", ":"}:
            continue

        add_package(name, installed_version, fixed_version)

    if not cves or not alpine_full_versions or not packages:
        print("Legacy issue parser failed.", flush=True)
        print(f"CVEs found: {cves}", flush=True)
        print(f"Alpine versions found: {alpine_full_versions}", flush=True)
        print(f"Packages found: {packages}", flush=True)
        raise SystemExit("Missing or invalid trivy-hotfix-json marker in issue body.")

    return {
        "schema_version": 1,
        "source": "legacy-issue-body",
        "scope": "",
        "severity": "",
        "php": "",
        "alpine_minor": alpine_minor,
        "alpine_full_versions": alpine_full_versions,
        "php_branches": [],
        "variants": [],
        "cves": cves,
        "packages": packages,
    }


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

    packages = sorted(
        packages,
        key=lambda package: (
            package["name"],
            package["fixed_version"],
            package["installed_version"],
        ),
    )

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


def build_package_match_rules(packages: list[dict[str, str]]) -> list[str]:
    rules: list[str] = []

    for package in packages:
        name = package["name"].strip()
        fixed_version = package["fixed_version"].strip()

        if not name or not fixed_version:
            continue

        rules.append(f"{name}<{fixed_version}")

    return sorted(set(rules))


def package_constraint_for_slug(package: dict[str, str]) -> str:
    name = package["name"].strip()
    fixed_version = package.get("fixed_version", "").strip()

    if fixed_version:
        return f"{name}-{fixed_version}"

    return name


def hotfix_slug_from_packages(packages: list[dict[str, str]]) -> str:
    parts = [package_constraint_for_slug(package) for package in packages]
    return slug("-".join(sorted(parts)))


def hotfix_identity(data: dict[str, Any]) -> dict[str, Any]:
    package_slug = hotfix_slug_from_packages(data["packages"])
    hotfix_id = f"apk-upgrade-{package_slug}"
    script_name = f"{hotfix_id}.sh"

    paths = [
        str(Path("hotfixes") / "alpine" / alpine_version / script_name)
        for alpine_version in data["alpine_full_versions"]
    ]

    return {
        "hotfix_id": hotfix_id,
        "script_name": script_name,
        "paths": paths,
        "alpine_full_versions": data["alpine_full_versions"],
        "cves": data["cves"],
        "packages": build_package_match_rules(data["packages"]),
    }


def read_existing_hotfix_cves(path: Path) -> list[str]:
    if not path.exists():
        return []

    cves: set[str] = set()

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.startswith("# hotfix-cves:"):
            continue

        value = line.split(":", 1)[1]
        for cve in value.split(","):
            cve = cve.strip()
            if cve:
                cves.add(cve)

    return sorted(cves)


def write_hotfix_script(
    path: Path,
    packages: list[dict[str, str]],
    *,
    hotfix_id: str,
    cves: list[str],
) -> None:
    upgrade_args = build_upgrade_args(packages)
    if not upgrade_args:
        raise SystemExit("No apk upgrade arguments were generated.")

    package_match_rules = build_package_match_rules(packages)

    existing_cves = read_existing_hotfix_cves(path)
    merged_cves = sorted(set(existing_cves) | set(cves))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/usr/bin/env sh\n"
        "# generated-by: create-hotfix-pr-from-issue.py\n"
        f"# hotfix-id: {hotfix_id}\n"
        f"# hotfix-cves: {','.join(merged_cves)}\n"
        f"# hotfix-packages: {','.join(package_match_rules)}\n"
        "set -eu\n"
        "\n"
        f"apk add --no-cache --upgrade {' '.join(upgrade_args)}\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | 0o111)


def generate_hotfix_files(data: dict[str, Any]) -> list[str]:
    changed_files: list[str] = []

    identity = hotfix_identity(data)
    hotfix_id = identity["hotfix_id"]
    script_name = identity["script_name"]

    for alpine_version in data["alpine_full_versions"]:
        hotfix_dir = Path("hotfixes") / "alpine" / alpine_version
        script_path = hotfix_dir / script_name

        write_hotfix_script(
            script_path,
            data["packages"],
            hotfix_id=hotfix_id,
            cves=data["cves"],
        )

        changed_files.append(str(script_path))

    return sorted(set(changed_files))


def build_pr_summary(issue_number: str, data: dict[str, Any], changed_files: list[str]) -> str:
    cves = ", ".join(f"`{cve}`" for cve in data["cves"])
    alpine_versions = ", ".join(f"`{version}`" for version in data["alpine_full_versions"])

    package_lines = [
        f"- `{package['name']}`: `{package['installed_version'] or 'unknown'}` -> `{package['fixed_version']}`"
        for package in data["packages"]
    ]

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
        default="/tmp/generated-hotfix-pr-body.md",
        help="Write generated PR summary markdown to this file.",
    )
    parser.add_argument(
        "--metadata-output",
        help="Write generated hotfix identity metadata JSON to this file.",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Only compute metadata and PR body; do not write hotfix files.",
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
    try:
        hotfix_json = extract_hotfix_json(body)
    except SystemExit:
        hotfix_json = extract_hotfix_data_from_legacy_issue(body)

    data = normalize_hotfix_data(hotfix_json)
    identity = hotfix_identity(data)

    if args.no_write:
        changed_files = identity["paths"]
    else:
        changed_files = generate_hotfix_files(data)

    summary = build_pr_summary(str(args.issue), data, changed_files)
    Path(args.output).write_text(summary, encoding="utf-8")

    report = {
        "issue": int(args.issue),
        "data": data,
        "identity": identity,
        "changed_files": changed_files,
    }

    if args.metadata_output:
        Path(args.metadata_output).write_text(
            json.dumps(identity, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(report, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())