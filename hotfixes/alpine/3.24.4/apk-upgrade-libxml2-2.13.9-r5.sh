#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libxml2-2.13.9-r5
# hotfix-cves: CVE-2026-11979,CVE-2026-1757
# hotfix-packages: libxml2<2.13.9-r5
set -eu

apk add --no-cache --upgrade 'libxml2>=2.13.9-r5'
