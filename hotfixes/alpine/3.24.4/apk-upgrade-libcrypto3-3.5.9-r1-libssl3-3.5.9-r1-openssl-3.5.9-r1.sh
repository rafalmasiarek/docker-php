#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libcrypto3-3.5.9-r1-libssl3-3.5.9-r1-openssl-3.5.9-r1
# hotfix-cves: CVE-2026-107496,CVE-2026-88822,CVE-2026-88823,CVE-2026-95691,CVE-2026-95692
# hotfix-packages: libcrypto3<3.5.9-r1,libssl3<3.5.9-r1,openssl<3.5.9-r1
set -eu

apk add --no-cache --upgrade 'libcrypto3>=3.5.9-r1' 'libssl3>=3.5.9-r1' 'openssl>=3.5.9-r1'
