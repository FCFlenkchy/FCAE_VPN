#!/usr/bin/env bash
set -euo pipefail
sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  echo "waiting for boot-time apt processes to release locks..."
  sleep 5
done
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zip
mkdir -p release-zips
for dir in artifacts/*/; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  if ls "$dir"/*.dmg 1>/dev/null 2>&1; then
    for dmg in "$dir"/*.dmg; do
      dmg_base=$(basename "$dmg" .dmg)
      cp "$dmg" "release-zips/${dmg_base}-${FCAE_VERSION}.dmg"
      echo "Copied release-zips/${dmg_base}-${FCAE_VERSION}.dmg"
    done
  else
    zip_name="${name}-${FCAE_VERSION}.zip"
    (
      cd "$dir"
      # upload/download-artifact do not preserve Unix modes; the
      # unzipped binary must run without a chmod detour.
      find . -maxdepth 1 -type f -name 'FCAE_VPN-*' ! -name '*.asc' ! -name '*.exe' -exec chmod +x {} +
      zip -9 -j "../../release-zips/${zip_name}" ./*
    )
    echo "Created release-zips/${zip_name}"
    unzip -l "release-zips/${zip_name}" | head -20
  fi
done
ls -lah release-zips/
test $(ls -1 release-zips/* 2>/dev/null | wc -l) -ge 1
