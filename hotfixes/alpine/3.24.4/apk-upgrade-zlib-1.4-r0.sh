#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-zlib-1.4-r0
# hotfix-cves: CVE-2026-4738
# hotfix-packages: zlib<1.4-r0
set -eu

apk add --no-cache --upgrade 'zlib>=1.4-r0'
