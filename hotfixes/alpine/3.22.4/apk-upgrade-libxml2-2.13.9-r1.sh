#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libxml2-2.13.9-r1
# hotfix-cves: CVE-2026-6732
# hotfix-packages: libxml2<2.13.9-r1
set -eu

apk add --no-cache --upgrade 'libxml2>=2.13.9-r1'
