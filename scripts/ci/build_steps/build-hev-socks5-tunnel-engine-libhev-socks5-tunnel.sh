#!/usr/bin/env bash
set -euo pipefail
ROOT="$PWD"
cd core/hev-socks5-tunnel
case "${FCAE_MATRIX_NAME}" in
  linux-x64|macos-arm64)
    make static
    ;;
  macos-x64)
    # Both macOS legs run on an arm64 runner, so the host toolchain
    # would hand this leg arm64 objects -- which ld silently ignores
    # while linking x86_64, leaving every engine symbol undefined.
    # Build for the architecture this leg actually ships, with the
    # deployment target the Rust and CMake halves use.
    make static CFLAGS="-arch x86_64 -mmacosx-version-min=13.0"
    ;;
  windows-x64)
    # FCAE links with MinGW, while upstream's native static archives
    # target the MSVC ABI. Keep the DLL as the C ABI boundary, but
    # cross-compile it here instead of using a second Windows job.
    bash --noprofile --norc "$ROOT/scripts/ci/build_steps/install-xwin.sh"

    MSVC_ROOT="$RUNNER_TEMP/hev-msvc-sysroot"
    "$RUNNER_TEMP/fcae-xwin/bin/xwin" --accept-license --arch x86_64 \
      --cache-dir "$RUNNER_TEMP/hev-xwin-cache" splat --output "$MSVC_ROOT"
    clang --version
    llvm-ar --version
    lld-link --version

    MSVC_CC="clang --target=x86_64-pc-windows-msvc -fuse-ld=lld-link"
    MSVC_CFLAGS="-isystem $MSVC_ROOT/crt/include -isystem $MSVC_ROOT/sdk/include/ucrt -isystem $MSVC_ROOT/sdk/include/um -isystem $MSVC_ROOT/sdk/include/shared"
    MSVC_LFLAGS="-L$MSVC_ROOT/crt/lib/x86_64 -L$MSVC_ROOT/sdk/lib/ucrt/x86_64 -L$MSVC_ROOT/sdk/lib/um/x86_64"
    make exec OS=Windows_NT ARCH=x64 \
      CC="$MSVC_CC" AR=llvm-ar \
      CFLAGS="$MSVC_CFLAGS" LFLAGS="$MSVC_LFLAGS" \
      -j"$(nproc)"
    test -s bin/hev-socks5-tunnel.exe
    echo "FCAE_HEV_EXE=$PWD/bin/hev-socks5-tunnel.exe" >> "$GITHUB_ENV"
    ;;
  android-*)
    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
      echo "::error::ANDROID_NDK_HOME not set, cannot build hev-socks5-tunnel"
      exit 1
    fi
    TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
    if [ "${FCAE_MATRIX_NAME}" = "android-universal" ]; then
      ABIS="arm64-v8a armeabi-v7a x86_64"
    else
      ABIS="${FCAE_MATRIX_ABI}"
    fi
    # `make clean` removes the whole bin/ tree -- including the ABIs
    # already staged in it -- so every ABI is collected outside the
    # build tree and copied in once the last clean has happened.
    # (Without this a universal build kept only its last ABI, and the
    # Rust build of the earlier ones failed on a missing archive.)
    STAGE="$RUNNER_TEMP/hev-android"
    rm -rf "$STAGE"
    for abi in $ABIS; do
      echo "  -> Building hev-socks5-tunnel for $abi"
      make clean
      case "$abi" in
        arm64-v8a)    CLANG_TARGET=aarch64-linux-android ;;
        armeabi-v7a)  CLANG_TARGET=armv7a-linux-androideabi ;;
        x86_64)       CLANG_TARGET=x86_64-linux-android ;;
        *) echo "::error::Unsupported Android ABI: $abi"; exit 1 ;;
      esac
      # `make static` archives only the engine's own objects, so the
      # lwip/yaml/hev-task-system archives are staged next to it per
      # ABI (the bridge links all four). The flags mirror upstream's
      # Android.mk: bionic already types fd_set and socklen_t (lwip's
      # unix port redefines both otherwise), the third-party sources
      # are not warning-clean under the Makefile's -Werror with a
      # current NDK clang, and the archive ends up in a shared object,
      # so it must be PIC.
      ANDROID_CFLAGS="-fPIC -DFD_SET_DEFINED -DSOCKLEN_T_DEFINED -Wno-error"
      if [ "$abi" = "armeabi-v7a" ]; then
        ANDROID_CFLAGS="$ANDROID_CFLAGS -mfpu=neon"
      fi
      make static \
        CC="$TOOLCHAIN/bin/${CLANG_TARGET}29-clang" \
        AR="$TOOLCHAIN/bin/llvm-ar" \
        STRIP="$TOOLCHAIN/bin/llvm-strip" \
        PP="$TOOLCHAIN/bin/${CLANG_TARGET}29-clang -E" \
        CFLAGS="$ANDROID_CFLAGS"
      mkdir -p "$STAGE/$abi"
      cp bin/libhev-socks5-tunnel.a \
         third-part/lwip/bin/liblwip.a \
         third-part/yaml/bin/libyaml.a \
         third-part/hev-task-system/bin/libhev-task-system.a \
         "$STAGE/$abi/"
    done
    for abi in $ABIS; do
      mkdir -p "bin/android/$abi"
      cp "$STAGE/$abi/"*.a "bin/android/$abi/"
      test -s "bin/android/$abi/libhev-socks5-tunnel.a"
    done
    if [ "${FCAE_MATRIX_NAME}" != "android-universal" ]; then
      cp "bin/android/${FCAE_MATRIX_ABI}/libhev-socks5-tunnel.a" bin/libhev-socks5-tunnel.a
    fi
    ;;
  *) echo "::error::Unsupported hev target: ${FCAE_MATRIX_NAME}"; exit 1 ;;
esac
case "${FCAE_MATRIX_NAME}" in
  windows-x64) ls -lh bin/hev-socks5-tunnel.exe ;;
  android-universal) ls -lh bin/android/*/lib*.a ;;
  *) ls -lh bin/libhev-socks5-tunnel.a ;;
esac
