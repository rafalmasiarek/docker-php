#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libexpat-2.8.1-r0
# hotfix-cves: CVE-2026-45186
# hotfix-packages: libexpat<2.8.1-r0
set -eu

apk add --no-cache --upgrade 'libexpat>=2.8.1-r0'
