#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libssh2-1.11.1-r3
# hotfix-cves: CVE-2026-55199,CVE-2026-55200
# hotfix-packages: libssh2<1.11.1-r3
set -eu

apk add --no-cache --upgrade 'libssh2>=1.11.1-r3'
