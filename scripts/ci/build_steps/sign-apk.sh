#!/usr/bin/env bash
set -euo pipefail
echo "$KEYSTORE_BASE64" | base64 -d > /tmp/release.keystore

BT=$(ls -d /usr/local/lib/android/sdk/build-tools/*/ | sort -V | tail -1)
"${BT}apksigner" sign \
  --ks /tmp/release.keystore \
  --ks-pass "pass:${KEYSTORE_PASSWORD}" \
  --key-pass "pass:${KEY_PASSWORD}" \
  --ks-key-alias "${KEY_ALIAS}" \
  android/app/build/outputs/apk/release/*.apk

"${BT}apksigner" verify --verbose \
  android/app/build/outputs/apk/release/*.apk || true
echo "APK signed successfully"
rm -f /tmp/release.keystore
