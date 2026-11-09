#!/usr/bin/env bash
set -euo pipefail
if [ -z "${WIN_CERT_BASE64:-}" ]; then
  echo "WIN_CERT_BASE64 secret not set, skipping windows signing"
  exit 0
fi
echo "$WIN_CERT_BASE64" | base64 -d > "$RUNNER_TEMP/wincert.pfx"

for f in package/*.exe; do
  [ -f "$f" ] || continue
  osslsigncode sign \
    -pkcs12 "$RUNNER_TEMP/wincert.pfx" \
    -pass "$WIN_CERT_PASSWORD" \
    -n "FCAE VPN" \
    -i "https://github.com/${GITHUB_REPOSITORY}" \
    -t http://timestamp.digicert.com \
    -in "$f" \
    -out "${f}.signed"
  mv -f "${f}.signed" "$f"
  osslsigncode verify -in "$f" || true
done

rm -f "$RUNNER_TEMP/wincert.pfx"
echo "Windows exe signed successfully"
