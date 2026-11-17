#!/usr/bin/env bash
set -euo pipefail
# Signs every packaged Windows artifact with the project's own certificate.
#
# That certificate is self-signed, so osslsigncode reports an untrusted chain
# ("self-signed certificate in certificate chain", "Signature verification:
# failed") for a correct signature. The signing certificate is therefore passed
# as its own trust anchor first; if the chain is still untrusted, the artifact
# is accepted on the checks that matter here -- the signature is present and
# the digest it covers matches the file -- and the untrusted chain is reported.
# A digest mismatch or a missing signature fails the job.
if [ -z "${WIN_CERT_BASE64:-}" ]; then
  echo "::warning title=windows signing skipped::WIN_CERT_BASE64 is not set; artifacts are published unsigned."
  echo "WIN_CERT_BASE64 secret not set, skipping windows signing"
  exit 0
fi
PFX="$RUNNER_TEMP/wincert.pfx"
ANCHOR="$RUNNER_TEMP/wincert.pem"
LOG="$RUNNER_TEMP/signature-verify.log"
echo "$WIN_CERT_BASE64" | base64 -d > "$PFX"
trap 'rm -f "$PFX" "$ANCHOR" "$LOG"' EXIT

# The signing certificate as a trust anchor: a self-signed certificate in the
# verification store is a root OpenSSL accepts.
if command -v openssl >/dev/null 2>&1; then
  openssl pkcs12 -in "$PFX" -nokeys -clcerts -passin "pass:${WIN_CERT_PASSWORD:-}" \
    -out "$ANCHOR" >/dev/null 2>&1 || true
  [ -s "$ANCHOR" ] || rm -f "$ANCHOR"
fi

# Sets VERDICT for one artifact: "verified" (trusted chain), "untrusted" (chain
# not in the trust store, signature intact) or "broken". A global rather than
# stdout, so the log prints unmodified.
VERDICT=""
verify_one() {
  local file="$1"
  local status=0
  if [ -s "$ANCHOR" ]; then
    osslsigncode verify -in "$file" -CAfile "$ANCHOR" >"$LOG" 2>&1 || status=$?
  else
    osslsigncode verify -in "$file" >"$LOG" 2>&1 || status=$?
  fi
  sed 's/^/    /' "$LOG"
  if [ "$status" -eq 0 ]; then
    VERDICT="verified"
    return 0
  fi
  # A digest or checksum that disagrees with the signature means the file is
  # not the file that was signed.
  if grep -q 'MISMATCH!!!' "$LOG"; then
    VERDICT="broken"
    return 0
  fi
  # osslsigncode reports 0 when the file carries no signature at all.
  if ! grep -qE 'Number of verified signatures: *[1-9]' "$LOG"; then
    VERDICT="broken"
    return 0
  fi
  VERDICT="untrusted"
}

signed=0
untrusted=0
for f in package/*.exe; do
  [ -f "$f" ] || continue
  osslsigncode sign \
    -pkcs12 "$PFX" \
    -pass "${WIN_CERT_PASSWORD:-}" \
    -h sha256 \
    -n "FCAE VPN" \
    -i "https://github.com/${GITHUB_REPOSITORY}" \
    -t http://timestamp.digicert.com \
    -in "$f" \
    -out "${f}.signed"
  mv -f "${f}.signed" "$f"
  verify_one "$f"
  case "$VERDICT" in
    verified) ;;
    untrusted)
      untrusted=$((untrusted + 1))
      echo "::warning title=windows signature not publicly trusted::$f is signed; its certificate is self-signed, so Windows shows an unknown publisher."
      ;;
    *)
      echo "::error title=windows signature broken::$f does not carry an intact signature."
      exit 1
      ;;
  esac
  signed=$((signed + 1))
done

if [ "$signed" -eq 0 ]; then
  echo "::error title=windows signing failed::no *.exe under package/ to sign"
  exit 1
fi
echo "Windows exe signed successfully ($signed file(s), $untrusted self-signed)"
