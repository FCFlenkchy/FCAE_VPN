#!/usr/bin/env bash
mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_PREFIX_PATH=/usr/local/glfw_static \
  ${FCAE_CMAKE_ARGS} -DRUST_TARGET=${FCAE_MATRIX_TARGET} \
  -DFCAE_VERSION_OVERRIDE="$FCAE_VERSION" \
  -DFCAE_IS_PRERELEASE="$FCAE_IS_PRERELEASE"
cmake --build . --config Release
