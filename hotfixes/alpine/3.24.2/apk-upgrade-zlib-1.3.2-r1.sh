#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-zlib-1.3.2-r1
# hotfix-cves: CVE-2026-85091
# hotfix-packages: zlib<1.3.2-r1
set -eu

apk add --no-cache --upgrade 'zlib>=1.3.2-r1'
