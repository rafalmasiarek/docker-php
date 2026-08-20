#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-sqlite-libs-3.53.4-r0
# hotfix-cves: CVE-2026-11822,CVE-2026-11824
# hotfix-packages: sqlite-libs<3.53.4-r0
set -eu

apk add --no-cache --upgrade 'sqlite-libs>=3.53.4-r0'
