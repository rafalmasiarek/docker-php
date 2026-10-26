#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-brotli-libs-1.2.1-r0
# hotfix-cves: CVE-2026-111497
# hotfix-packages: brotli-libs<1.2.1-r0
set -eu

apk add --no-cache --upgrade 'brotli-libs>=1.2.1-r0'
