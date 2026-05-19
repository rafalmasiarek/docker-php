#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libecpg-18.4-r0-libpq-18.4-r0
# hotfix-cves: CVE-2026-6472,CVE-2026-6473,CVE-2026-6476,CVE-2026-6478,CVE-2026-6575,CVE-2026-6638
# hotfix-packages: libecpg<18.4-r0,libpq<18.4-r0
set -eu

apk add --no-cache --upgrade 'libecpg>=18.4-r0' 'libpq>=18.4-r0'
