#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-pcre2-10.49-r0
# hotfix-cves: CVE-2026-103111
# hotfix-packages: pcre2<10.49-r0
set -eu

apk add --no-cache --upgrade 'pcre2>=10.49-r0'
