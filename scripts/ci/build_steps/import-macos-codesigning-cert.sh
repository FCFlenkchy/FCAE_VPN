#!/usr/bin/env bash
set -euo pipefail
KEYCHAIN_PASSWORD=$(openssl rand -base64 24)
KEYCHAIN_PATH="$RUNNER_TEMP/build.keychain-db"

echo "$MACOS_CERT_BASE64" | base64 -d > "$RUNNER_TEMP/macoscert.p12"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

security import "$RUNNER_TEMP/macoscert.p12" -P "$MACOS_CERT_PASSWORD" \
  -A -t cert -f pkcs12 -k "$KEYCHAIN_PATH"

security set-key-partition-list -S apple-tool:,apple:,codesign: \
  -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security list-keychain -d user -s "$KEYCHAIN_PATH" login.keychain-db

rm -f "$RUNNER_TEMP/macoscert.p12"
