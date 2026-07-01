#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-curl-8.21.0-r0-libcurl-8.21.0-r0
# hotfix-cves: CVE-2026-11856,CVE-2026-8925,CVE-2026-8927,CVE-2026-9079
# hotfix-packages: curl<8.21.0-r0,libcurl<8.21.0-r0
set -eu

apk add --no-cache --upgrade 'curl>=8.21.0-r0' 'libcurl>=8.21.0-r0'
