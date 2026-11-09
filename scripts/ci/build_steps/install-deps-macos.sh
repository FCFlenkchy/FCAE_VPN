#!/usr/bin/env bash
brew_ok=0
for attempt in 1 2 3; do
  brew install cmake ninja nasm protobuf && { brew_ok=1; break; }
  echo "::warning::brew install failed (attempt $attempt/3); retrying in 15s"
  sleep 15
done
if [ "$brew_ok" != 1 ]; then
  echo "::error::brew install failed after 3 attempts"
  exit 1
fi
if [ "${FCAE_MATRIX_NAME}" = "macos-x64" ]; then
  ARCH_ARGS="-DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0"
else
  ARCH_ARGS="-DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0"
fi
GLFW_PREFIX="${GITHUB_WORKSPACE}/.glfw/${FCAE_MATRIX_NAME}"
echo "GLFW_PREFIX=${GLFW_PREFIX}" >> "$GITHUB_ENV"
if [ -f "${GLFW_PREFIX}/lib/libglfw3.a" ]; then
  echo "glfw restored from cache at ${GLFW_PREFIX}"
else
  curl -fsSL --retry 6 --retry-all-errors --retry-delay 5 --connect-timeout 30 \
    https://github.com/glfw/glfw/archive/refs/tags/3.4.tar.gz -o glfw.tar.gz
  tar xzf glfw.tar.gz
  cd glfw-3.4
  cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    ${ARCH_ARGS} \
    -DCMAKE_INSTALL_PREFIX="${GLFW_PREFIX}" \
    -DBUILD_SHARED_LIBS=OFF \
    -DGLFW_BUILD_DOCS=OFF -DGLFW_BUILD_EXAMPLES=OFF -DGLFW_BUILD_TESTS=OFF
  cmake --build build
  cmake --install build
  cd ..
fi
