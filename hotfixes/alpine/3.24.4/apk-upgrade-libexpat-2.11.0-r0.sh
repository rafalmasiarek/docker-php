#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libexpat-2.11.0-r0
# hotfix-cves: CVE-2026-124317,CVE-2026-128241,CVE-2026-134703
# hotfix-packages: libexpat<2.11.0-r0
set -eu

apk add --no-cache --upgrade 'libexpat>=2.11.0-r0'
