#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-nghttp2-libs-1.70.0-r0
# hotfix-cves: CVE-2026-58055
# hotfix-packages: nghttp2-libs<1.70.0-r0
set -eu

apk add --no-cache --upgrade 'nghttp2-libs>=1.70.0-r0'
