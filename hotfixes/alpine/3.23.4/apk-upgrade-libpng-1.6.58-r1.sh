#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libpng-1.6.58-r1
# hotfix-cves: CVE-2026-40930
# hotfix-packages: libpng<1.6.58-r1
set -eu

apk add --no-cache --upgrade 'libpng>=1.6.58-r1'
