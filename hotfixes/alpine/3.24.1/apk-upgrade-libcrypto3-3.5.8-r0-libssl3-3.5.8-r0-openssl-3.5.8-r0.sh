#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libcrypto3-3.5.8-r0-libssl3-3.5.8-r0-openssl-3.5.8-r0
# hotfix-cves: CVE-2026-14456,CVE-2026-18798,CVE-2026-63072,CVE-2026-63076
# hotfix-packages: libcrypto3<3.5.8-r0,libssl3<3.5.8-r0,openssl<3.5.8-r0
set -eu

apk add --no-cache --upgrade 'libcrypto3>=3.5.8-r0' 'libssl3>=3.5.8-r0' 'openssl>=3.5.8-r0'
