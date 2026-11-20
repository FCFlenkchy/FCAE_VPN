#!/usr/bin/env bash
# The macOS front end no longer needs a windowing library or OpenGL: it renders
# through AppKit and Metal, which ship with the OS. GLFW is therefore no longer
# built here, and there is no cached static prefix to publish.
#
# The toolchain packages the rest of the build wants are still installed the
# same way, with the same retries.
packages=(cmake ninja nasm protobuf)
if [ "${FCAE_MATRIX_NAME:-}" = "ios-arm64" ]; then
  packages+=(xcodegen llvm pkg-config)
fi
brew_ok=0
for attempt in 1 2 3; do
  brew install "${packages[@]}" && { brew_ok=1; break; }
  echo "::warning::brew install failed (attempt $attempt/3); retrying in 15s"
  sleep 15
done
if [ "$brew_ok" != 1 ]; then
  echo "::error::brew install failed after 3 attempts"
  exit 1
fi
