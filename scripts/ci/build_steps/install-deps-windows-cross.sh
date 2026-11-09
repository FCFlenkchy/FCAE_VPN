#!/usr/bin/env bash
set -euxo pipefail
sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  echo "waiting for boot-time apt processes to release locks..."
  sleep 5
done
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 nasm \
  clang lld llvm cmake
echo "=== MinGW toolchain check ==="
which x86_64-w64-mingw32-gcc x86_64-w64-mingw32-g++
x86_64-w64-mingw32-gcc --version | head -1
x86_64-w64-mingw32-g++ --version | head -1
