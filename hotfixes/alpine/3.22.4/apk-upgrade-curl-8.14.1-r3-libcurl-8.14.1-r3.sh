#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-curl-8.14.1-r3-libcurl-8.14.1-r3
# hotfix-cves: CVE-2026-5545
# hotfix-packages: curl<8.14.1-r3,libcurl<8.14.1-r3
set -eu

apk add --no-cache --upgrade 'curl>=8.14.1-r3' 'libcurl>=8.14.1-r3'
