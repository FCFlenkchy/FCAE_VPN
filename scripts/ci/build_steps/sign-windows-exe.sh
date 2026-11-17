#!/usr/bin/env bash
set -euo pipefail
# An unsigned Windows build is not a build that "did not sign": it is the one
# artifact Defender and SmartScreen score worst, and every user sees "unknown
# publisher" plus whatever an ML engine makes of a fresh unsigned VPN binary.
# So the skip is loud, and a signature that does not verify fails the job
# instead of being swallowed -- a broken signature over a good binary is worse
# than none at all, because it looks like tampering.
if [ -z "${WIN_CERT_BASE64:-}" ]; then
  echo "::warning title=windows signing skipped::WIN_CERT_BASE64 is not set; this build is UNSIGNED. Windows users will get SmartScreen/Defender warnings for it."
  echo "WIN_CERT_BASE64 secret not set, skipping windows signing"
  exit 0
fi
echo "$WIN_CERT_BASE64" | base64 -d > "$RUNNER_TEMP/wincert.pfx"
trap 'rm -f "$RUNNER_TEMP/wincert.pfx"' EXIT

signed=0
for f in package/*.exe; do
  [ -f "$f" ] || continue
  osslsigncode sign \
    -pkcs12 "$RUNNER_TEMP/wincert.pfx" \
    -pass "$WIN_CERT_PASSWORD" \
    -h sha256 \
    -n "FCAE VPN" \
    -i "https://github.com/${GITHUB_REPOSITORY}" \
    -t http://timestamp.digicert.com \
    -in "$f" \
    -out "${f}.signed"
  mv -f "${f}.signed" "$f"
  # No `|| true`: a signature that cannot be verified is a release nobody
  # should download.
  osslsigncode verify -in "$f"
  signed=$((signed + 1))
done

if [ "$signed" -eq 0 ]; then
  # A glob that matched nothing means the artifact this job just built is
  # about to be published unsigned, which is exactly the case this step exists
  # to prevent.
  echo "::error title=windows signing failed::no *.exe under package/ to sign"
  exit 1
fi
echo "Windows exe signed successfully ($signed file(s))"
