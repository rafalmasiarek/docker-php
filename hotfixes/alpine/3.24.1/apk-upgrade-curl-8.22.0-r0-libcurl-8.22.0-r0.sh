#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-curl-8.22.0-r0-libcurl-8.22.0-r0
# hotfix-cves: CVE-2026-13608,CVE-2026-18924,CVE-2026-19931,CVE-2026-80229,CVE-2026-80230,CVE-2026-80255,CVE-2026-82209
# hotfix-packages: curl<8.22.0-r0,libcurl<8.22.0-r0
set -eu

apk add --no-cache --upgrade 'curl>=8.22.0-r0' 'libcurl>=8.22.0-r0'
