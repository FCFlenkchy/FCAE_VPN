#!/usr/bin/env bash
set -euo pipefail

rm -rf target/release/build/aether-engine-* target/debug/build/aether-engine-* 2>/dev/null || true

if [ "${FCAE_MATRIX_NAME}" = "macos-x64" ]; then
  export MACOSX_DEPLOYMENT_TARGET=13.0
fi

if [[ "${FCAE_MATRIX_NAME}" == android-* ]]; then
  NDK="${ANDROID_NDK_HOME:-${FCAE_NDK_PATH}}"
  if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "ANDROID_NDK_HOME not set or missing: $NDK"
    exit 1
  fi
  HOST_TAG=linux-x86_64
  PREBUILT="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"
  BIN="$PREBUILT/bin"
  export PATH="$BIN:$PATH"
  export ANDROID_NDK_HOME="$NDK"
  export ANDROID_NDK_ROOT="$NDK"

  if [ "${FCAE_MATRIX_NAME}" = "android-universal" ]; then
    echo "Building Rust for all Android ABIs (universal)..."

    for TARGET_TRIPLE in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
      echo "  -> Building for $TARGET_TRIPLE"

      if [ "$TARGET_TRIPLE" = "aarch64-linux-android" ]; then
        NDK_CLANG_PREFIX=aarch64-linux-android
        RUST_ENV_LOWER=aarch64_linux_android
        RUST_ENV_UPPER=AARCH64_LINUX_ANDROID
      elif [ "$TARGET_TRIPLE" = "x86_64-linux-android" ]; then
        NDK_CLANG_PREFIX=x86_64-linux-android
        RUST_ENV_LOWER=x86_64_linux_android
        RUST_ENV_UPPER=X86_64_LINUX_ANDROID
      else
        NDK_CLANG_PREFIX=armv7a-linux-androideabi
        RUST_ENV_LOWER=armv7_linux_androideabi
        RUST_ENV_UPPER=ARMV7_LINUX_ANDROIDEABI
      fi

      CLANG="$BIN/${NDK_CLANG_PREFIX}29-clang"
      CLANGXX="$BIN/${NDK_CLANG_PREFIX}29-clang++"

      # boring-sys hands CC_<target> to CMake as CMAKE_C_COMPILER next to the
      # NDK toolchain file, which picks bin/clang. Any other path makes CMake
      # wipe its cache when boring-sys configures the second (crypto) target,
      # and BoringSSL's bundled benchmark fails that fresh configure.
      export "CC_${RUST_ENV_LOWER}"="$BIN/clang"
      export "CXX_${RUST_ENV_LOWER}"="$BIN/clang++"
      export "AR_${RUST_ENV_LOWER}"="$BIN/llvm-ar"
      export "CARGO_TARGET_${RUST_ENV_UPPER}_LINKER"="$CLANG"
      export "CARGO_TARGET_${RUST_ENV_UPPER}_AR"="$BIN/llvm-ar"
      ln -sf "$CLANG" "$BIN/${NDK_CLANG_PREFIX}-clang"
      ln -sf "$CLANGXX" "$BIN/${NDK_CLANG_PREFIX}-clang++"
      export CC="${NDK_CLANG_PREFIX}29-clang"
      export CXX="${NDK_CLANG_PREFIX}29-clang++"
      export AR=llvm-ar

      export "BINDGEN_EXTRA_CLANG_ARGS_${RUST_ENV_LOWER}"="--sysroot=$PREBUILT/sysroot"
      export "CFLAGS_${RUST_ENV_LOWER}"="--target=${NDK_CLANG_PREFIX}29 --sysroot=$PREBUILT/sysroot"
      export "CXXFLAGS_${RUST_ENV_LOWER}"="--target=${NDK_CLANG_PREFIX}29 --sysroot=$PREBUILT/sysroot"

      case "$TARGET_TRIPLE" in
        aarch64-linux-android)   HEV_ABI=arm64-v8a ;;
        armv7-linux-androideabi) HEV_ABI=armeabi-v7a ;;
        x86_64-linux-android)    HEV_ABI=x86_64 ;;
      esac
      export FCAE_HEV_LIBDIR="$(pwd)/core/hev-socks5-tunnel/bin/android/$HEV_ABI"
      export FCAE_ZEPTUN_LIBDIR="$(pwd)/core/zeptun/zig-out/android/prebuilt/$HEV_ABI"

      cargo build --manifest-path core/fcae-ffi/Cargo.toml --locked --release --target "$TARGET_TRIPLE" -p fcae-ffi --features aether,tor,psiphon,firefox,zeptun,hev

      DEST="$(pwd)/target/$TARGET_TRIPLE/release/libfcae_ffi.a"
      ls -lh "$DEST"
      test -f "$DEST"
    done
    echo "All Android Rust targets built successfully"
  else
    if [ "${FCAE_MATRIX_NAME}" = "android-arm64-v8a" ]; then
      NDK_CLANG_PREFIX=aarch64-linux-android
      RUST_ENV_LOWER=aarch64_linux_android
      RUST_ENV_UPPER=AARCH64_LINUX_ANDROID
    elif [ "${FCAE_MATRIX_NAME}" = "android-x86_64" ]; then
      NDK_CLANG_PREFIX=x86_64-linux-android
      RUST_ENV_LOWER=x86_64_linux_android
      RUST_ENV_UPPER=X86_64_LINUX_ANDROID
    else
      NDK_CLANG_PREFIX=armv7a-linux-androideabi
      RUST_ENV_LOWER=armv7_linux_androideabi
      RUST_ENV_UPPER=ARMV7_LINUX_ANDROIDEABI
    fi

    CLANG="$BIN/${NDK_CLANG_PREFIX}29-clang"
    CLANGXX="$BIN/${NDK_CLANG_PREFIX}29-clang++"

    # See the universal branch: CC_<target> must be the NDK's own clang.
    export "CC_${RUST_ENV_LOWER}"="$BIN/clang"
    export "CXX_${RUST_ENV_LOWER}"="$BIN/clang++"
    export "AR_${RUST_ENV_LOWER}"="$BIN/llvm-ar"
    export "CARGO_TARGET_${RUST_ENV_UPPER}_LINKER"="$CLANG"
    export "CARGO_TARGET_${RUST_ENV_UPPER}_AR"="$BIN/llvm-ar"
    ln -sf "$CLANG" "$BIN/${NDK_CLANG_PREFIX}-clang"
    ln -sf "$CLANGXX" "$BIN/${NDK_CLANG_PREFIX}-clang++"
    export CC="${NDK_CLANG_PREFIX}29-clang"
    export CXX="${NDK_CLANG_PREFIX}29-clang++"
    export AR=llvm-ar

    export "BINDGEN_EXTRA_CLANG_ARGS_${RUST_ENV_LOWER}"="--sysroot=$PREBUILT/sysroot"
    export "CFLAGS_${RUST_ENV_LOWER}"="--target=${NDK_CLANG_PREFIX}29 --sysroot=$PREBUILT/sysroot"
    export "CXXFLAGS_${RUST_ENV_LOWER}"="--target=${NDK_CLANG_PREFIX}29 --sysroot=$PREBUILT/sysroot"

    echo "Using NDK: $NDK"
    "$CLANG" --version | head -1

    cargo build --manifest-path core/fcae-ffi/Cargo.toml --locked --release --target ${FCAE_MATRIX_TARGET} -p fcae-ffi --features aether,tor,psiphon,firefox,zeptun,hev

    DEST="$(pwd)/target/${FCAE_MATRIX_TARGET}/release/libfcae_ffi.a"
    ls -lh "$DEST"
    test -f "$DEST"
  fi
else
  case "${FCAE_MATRIX_NAME}" in
    windows-x64|linux-x64|macos-arm64|macos-x64) FEATURES=aether,tor,psiphon-live,firefox,zeptun,hev ;;
    *) echo "::error::Unsupported desktop target: ${FCAE_MATRIX_NAME}"; exit 1 ;;
  esac
  if [ "${FCAE_MATRIX_NAME}" = "windows-x64" ]; then
    # boring-sys's BoringSSL: BUILD_TESTING pulls in google-benchmark, whose
    # FindThreads puts -pthread on Threads::Threads; NASM reads that as
    # "-p thread" (pre-include a file named thread) and every .asm fails.
    tc="$RUNNER_TEMP/x86_64-w64-mingw32.cmake"
    cat > "$tc" <<'EOF'
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(BUILD_TESTING OFF CACHE BOOL "")
EOF
    export CMAKE_TOOLCHAIN_FILE_x86_64_pc_windows_gnu="$tc"

  fi
  cargo build --manifest-path core/fcae-ffi/Cargo.toml --locked --release --target ${FCAE_MATRIX_TARGET} -p fcae-ffi --features "$FEATURES"

  DEST="$(pwd)/target/${FCAE_MATRIX_TARGET}/release/libfcae_ffi.a"
  ls -lh "$DEST"
  test -f "$DEST"
fi
