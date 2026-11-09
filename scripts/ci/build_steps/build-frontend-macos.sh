#!/usr/bin/env bash
mkdir -p build && cd build
export CMAKE_PREFIX_PATH="${GLFW_PREFIX:?glfw prefix not published by the install step}"
cmake .. -G Ninja \
  ${FCAE_CMAKE_ARGS} -DRUST_TARGET=${FCAE_MATRIX_TARGET} \
  -DFCAE_VERSION_OVERRIDE="$FCAE_VERSION" \
  -DFCAE_IS_PRERELEASE="$FCAE_IS_PRERELEASE"
cmake --build . --config Release
