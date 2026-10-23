#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libssh2-1.11.1-r4
# hotfix-cves: CVE-2025-15661,CVE-2026-58050,CVE-2026-58051,CVE-2026-66032,CVE-2026-66033,CVE-2026-66034,CVE-2026-66035
# hotfix-packages: libssh2<1.11.1-r4
set -eu

apk add --no-cache --upgrade 'libssh2>=1.11.1-r4'
