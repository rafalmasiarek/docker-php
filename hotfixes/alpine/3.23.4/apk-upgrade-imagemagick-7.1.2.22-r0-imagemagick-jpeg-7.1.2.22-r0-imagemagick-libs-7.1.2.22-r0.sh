#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-imagemagick-7.1.2.22-r0-imagemagick-jpeg-7.1.2.22-r0-imagemagick-libs-7.1.2.22-r0
# hotfix-cves: CVE-2026-42326,CVE-2026-45358,CVE-2026-45359
# hotfix-packages: imagemagick-jpeg<7.1.2.22-r0,imagemagick-libs<7.1.2.22-r0,imagemagick<7.1.2.22-r0
set -eu

apk add --no-cache --upgrade 'imagemagick-jpeg>=7.1.2.22-r0' 'imagemagick-libs>=7.1.2.22-r0' 'imagemagick>=7.1.2.22-r0'
