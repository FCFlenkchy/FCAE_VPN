#!/usr/bin/env bash
set -euxo pipefail
sudo systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  echo "waiting for boot-time apt processes to release locks..."
  sleep 5
done
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  libgl1-mesa-dev libx11-dev libxi-dev libxcursor-dev \
  libxrandr-dev libxinerama-dev libxxf86vm-dev libasound2-dev \
  libssl-dev libcurl4-openssl-dev libbz2-dev liblzma-dev zlib1g-dev \
  libevent-dev protobuf-compiler nasm cmake ninja-build
curl -fsSL --retry 6 --retry-all-errors --retry-delay 5 --connect-timeout 30 \
  https://github.com/glfw/glfw/archive/refs/tags/3.4.tar.gz -o glfw.tar.gz
tar xzf glfw.tar.gz
cd glfw-3.4
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local/glfw_static \
  -DBUILD_SHARED_LIBS=OFF \
  -DGLFW_BUILD_WAYLAND=OFF \
  -DGLFW_BUILD_DOCS=OFF -DGLFW_BUILD_EXAMPLES=OFF -DGLFW_BUILD_TESTS=OFF
cmake --build build
sudo cmake --install build
cd ..
