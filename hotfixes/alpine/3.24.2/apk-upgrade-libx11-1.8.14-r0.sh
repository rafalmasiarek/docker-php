#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libx11-1.8.14-r0
# hotfix-cves: CVE-2026-88806,CVE-2026-94283,CVE-2026-94284,CVE-2026-94285
# hotfix-packages: libx11<1.8.14-r0
set -eu

apk add --no-cache --upgrade 'libx11>=1.8.14-r0'
