#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libcrypto3-3.5.7-r0-libssl3-3.5.7-r0-openssl-3.5.7-r0
# hotfix-cves: CVE-2026-34182,CVE-2026-34183,CVE-2026-42764,CVE-2026-45445,CVE-2026-45447
# hotfix-packages: libcrypto3<3.5.7-r0,libssl3<3.5.7-r0,openssl<3.5.7-r0
set -eu

apk add --no-cache --upgrade 'libcrypto3>=3.5.7-r0' 'libssl3>=3.5.7-r0' 'openssl>=3.5.7-r0'
