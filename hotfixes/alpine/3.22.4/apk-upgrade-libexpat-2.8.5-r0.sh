#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libexpat-2.8.5-r0
# hotfix-cves: CVE-2026-93990
# hotfix-packages: libexpat<2.8.5-r0
set -eu

apk add --no-cache --upgrade 'libexpat>=2.8.5-r0'
