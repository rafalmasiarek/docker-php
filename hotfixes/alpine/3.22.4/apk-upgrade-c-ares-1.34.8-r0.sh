#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-c-ares-1.34.8-r0
# hotfix-cves: CVE-2026-33630
# hotfix-packages: c-ares<1.34.8-r0
set -eu

apk add --no-cache --upgrade 'c-ares>=1.34.8-r0'
