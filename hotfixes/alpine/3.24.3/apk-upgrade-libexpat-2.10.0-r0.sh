#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libexpat-2.10.0-r0
# hotfix-cves: CVE-2026-113351,CVE-2026-117610,CVE-2026-118370
# hotfix-packages: libexpat<2.10.0-r0
set -eu

apk add --no-cache --upgrade 'libexpat>=2.10.0-r0'
