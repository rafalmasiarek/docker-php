#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-curl-8.19.0-r0-libcurl-8.19.0-r0
# hotfix-cves: CVE-2025-14017,CVE-2025-14524,CVE-2025-14819,CVE-2026-1965,CVE-2026-3783,CVE-2026-3784,CVE-2026-3805
# hotfix-packages: curl<8.19.0-r0,libcurl<8.19.0-r0
set -eu

apk add --no-cache --upgrade 'curl>=8.19.0-r0' 'libcurl>=8.19.0-r0'
