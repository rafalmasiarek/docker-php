#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-curl-8.23.0-r0-libcurl-8.23.0-r0
# hotfix-cves: CVE-2026-92388,CVE-2026-92392
# hotfix-packages: curl<8.23.0-r0,libcurl<8.23.0-r0
set -eu

apk add --no-cache --upgrade 'curl>=8.23.0-r0' 'libcurl>=8.23.0-r0'
