#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-libssh2-1.11.1-r2
# hotfix-cves: CVE-2026-7598
# hotfix-packages: libssh2<1.11.1-r2
set -eu

apk add --no-cache --upgrade 'libssh2>=1.11.1-r2'
