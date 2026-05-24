#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libecpg-17.10-r0-libpq-17.10-r0
# hotfix-cves: CVE-2026-6472,CVE-2026-6473,CVE-2026-6474,CVE-2026-6475
# hotfix-packages: libecpg<17.10-r0,libpq<17.10-r0
set -eu

apk add --no-cache --upgrade 'libecpg>=17.10-r0' 'libpq>=17.10-r0'
