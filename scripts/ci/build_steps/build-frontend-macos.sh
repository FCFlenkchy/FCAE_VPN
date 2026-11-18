#!/usr/bin/env bash
mkdir -p build && cd build
# No GLFW prefix any more: the front end links AppKit, Metal and MetalKit from
# the SDK, so there is nothing to point CMAKE_PREFIX_PATH at.
cmake .. -G Ninja \
  ${FCAE_CMAKE_ARGS} -DRUST_TARGET=${FCAE_MATRIX_TARGET} \
  -DFCAE_VERSION_OVERRIDE="$FCAE_VERSION" \
  -DFCAE_IS_PRERELEASE="$FCAE_IS_PRERELEASE"
cmake --build . --config Release
