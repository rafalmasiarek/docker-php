#!/usr/bin/env sh
# generated-by: create-hotfix-pr-from-issue.py
# hotfix-id: apk-upgrade-imagemagick-7.1.2.27-r0-imagemagick-jpeg-7.1.2.27-r0-imagemagick-libs-7.1.2.27-r0
# hotfix-cves: CVE-2026-53466,CVE-2026-53467,CVE-2026-55510,CVE-2026-55577,CVE-2026-55594,CVE-2026-55595,CVE-2026-55597,CVE-2026-55628
# hotfix-packages: imagemagick-jpeg<7.1.2.27-r0,imagemagick-libs<7.1.2.27-r0,imagemagick<7.1.2.27-r0
set -eu

apk add --no-cache --upgrade 'imagemagick-jpeg>=7.1.2.27-r0' 'imagemagick-libs>=7.1.2.27-r0' 'imagemagick>=7.1.2.27-r0'
