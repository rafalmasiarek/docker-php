#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-imagemagick-7.1.2.23-r0-imagemagick-jpeg-7.1.2.23-r0-imagemagick-libs-7.1.2.23-r0
# hotfix-cves: CVE-2026-46523,CVE-2026-47166
# hotfix-packages: imagemagick-jpeg<7.1.2.23-r0,imagemagick-libs<7.1.2.23-r0,imagemagick<7.1.2.23-r0
set -eu

apk add --no-cache --upgrade 'imagemagick-jpeg>=7.1.2.23-r0' 'imagemagick-libs>=7.1.2.23-r0' 'imagemagick>=7.1.2.23-r0'
