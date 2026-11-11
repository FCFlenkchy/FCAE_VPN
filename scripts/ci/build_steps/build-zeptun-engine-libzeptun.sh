#!/usr/bin/env bash
set -euo pipefail
cd core/zeptun
case "${FCAE_MATRIX_NAME}" in
  linux-x64)   zig build -Dtarget=x86_64-linux-gnu -Doptimize=small ;;
  windows-x64) zig build -Dtarget=x86_64-windows-gnu -Doptimize=small ;;
  macos-arm64) zig build -Dtarget=aarch64-macos -Doptimize=small ;;
  macos-x64)   zig build -Dtarget=x86_64-macos -Doptimize=small ;;
  android-*)
    SYSROOT="${ANDROID_NDK_HOME:?}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
    test -d "$SYSROOT/usr/include"
    LIBC_DIR="$(mktemp -d)"
    trap 'rm -rf "$LIBC_DIR"' EXIT
    for abi in arm64-v8a armeabi-v7a x86_64 x86; do
      case "$abi" in
        arm64-v8a)   ZIG_TARGET=aarch64-linux-android.29; NDK_TARGET=aarch64-linux-android ;;
        armeabi-v7a) ZIG_TARGET=arm-linux-androideabi.29; NDK_TARGET=arm-linux-androideabi ;;
        x86_64)      ZIG_TARGET=x86_64-linux-android.29; NDK_TARGET=x86_64-linux-android ;;
        x86)         ZIG_TARGET=x86-linux-android.29; NDK_TARGET=i686-linux-android ;;
      esac
      CRT_DIR="$SYSROOT/usr/lib/$NDK_TARGET/29"
      test -d "$SYSROOT/usr/include/$NDK_TARGET"
      test -f "$CRT_DIR/libc.so"
      test -f "$CRT_DIR/crtbegin_so.o"
      printf '%s\n' \
        "include_dir=$SYSROOT/usr/include" \
        "sys_include_dir=$SYSROOT/usr/include/$NDK_TARGET" \
        "cc_dir=$CRT_DIR" \
        "crt_dir=$CRT_DIR" \
        'msvc_lib_dir=' 'kernel32_lib_dir=' 'darwin_sdk_dir=' > "$LIBC_DIR/$abi.conf"
      zig build -Dtarget="$ZIG_TARGET" -Doptimize=small -Dstrip=true \
        -Dandroid-libc="$LIBC_DIR/$abi.conf" --libc "$LIBC_DIR/$abi.conf" \
        --prefix "$PWD/zig-out/android/$abi"
      install -D -m 644 "zig-out/android/$abi/lib/libzeptun.a" \
        "zig-out/android/prebuilt/$abi/libzeptun.a"
    done
    ;;
  *) echo "::error::Unsupported zeptun target: ${FCAE_MATRIX_NAME}"; exit 1 ;;
esac
if [ "${FCAE_MATRIX_NAME}" = "windows-x64" ]; then
  test -s zig-out/bin/zeptun.exe
  echo "FCAE_ZEPTUN_EXE=$PWD/zig-out/bin/zeptun.exe" >> "$GITHUB_ENV"
  exit 0
fi

# `-lzeptun` must resolve to the static archive. On Windows-gnu the
# import library (libzeptun.dll.a) is an archive too, and the linker
# prefers it over libzeptun.a — the exe then imports zeptun.dll
# instead of linking the engine statically. Purge every shared
# artifact so only the static archive remains linkable.
rm -f zig-out/lib/*.dll zig-out/lib/*.dll.a zig-out/lib/*.so* zig-out/lib/*.dylib
if ls zig-out/lib/*.dll zig-out/lib/*.dll.a >/dev/null 2>&1; then
  echo "::error::shared zeptun artifacts survived the purge:"
  ls -la zig-out/lib
  exit 1
fi
case "${FCAE_MATRIX_NAME}" in
  android-*)
    for abi in arm64-v8a armeabi-v7a x86_64 x86; do
      test -s "zig-out/android/prebuilt/$abi/libzeptun.a"
    done
    ;;
  *) test -s zig-out/lib/libzeptun.a ;;
esac
