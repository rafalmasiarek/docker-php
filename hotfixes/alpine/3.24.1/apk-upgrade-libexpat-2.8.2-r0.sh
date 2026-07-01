#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libexpat-2.8.2-r0
# hotfix-cves: CVE-2026-50219,CVE-2026-56132,CVE-2026-56403,CVE-2026-56404,CVE-2026-56405,CVE-2026-56406,CVE-2026-56410,CVE-2026-56411,CVE-2026-56412
# hotfix-packages: libexpat<2.8.2-r0
set -eu

apk add --no-cache --upgrade 'libexpat>=2.8.2-r0'
