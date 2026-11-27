#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libxml2-2.13.9-r4
# hotfix-cves: CVE-2026-0990,CVE-2026-86137,CVE-2026-86138,CVE-2026-86139,CVE-2026-86140,CVE-2026-86142,CVE-2026-86143
# hotfix-packages: libxml2<2.13.9-r4
set -eu

apk add --no-cache --upgrade 'libxml2>=2.13.9-r4'
