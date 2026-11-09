#!/usr/bin/env bash
set -euo pipefail
mkdir -p package
cp android/app/build/outputs/apk/release/*.apk "package/FCAE_VPN-${FCAE_MATRIX_NAME}.apk" 2>/dev/null || true
test -f "package/FCAE_VPN-${FCAE_MATRIX_NAME}.apk"
ls -lah package/
