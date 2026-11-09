#!/usr/bin/env bash
set -euo pipefail
if [ -z "${GPG_PRIVATE_KEY:-}" ]; then
  echo "GPG_PRIVATE_KEY secret not set, skipping linux signing"
  exit 0
fi

export GNUPGHOME="$RUNNER_TEMP/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

echo "$GPG_PRIVATE_KEY" | gpg --batch --import
KEY_ID=$(gpg --list-secret-keys --with-colons | awk -F: '/^sec/{print $5; exit}')
echo "Signing with key: $KEY_ID"

for f in package/*; do
  [ -f "$f" ] || continue
  gpg --batch --yes --local-user "$KEY_ID" --detach-sign --armor "$f"
done

gpg --batch --armor --export "$KEY_ID" > package/FCAE_VPN-public-key.asc

rm -rf "$GNUPGHOME"
ls -la package/
echo "Linux binaries signed successfully"
