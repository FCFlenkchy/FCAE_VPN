#!/usr/bin/env bash
set -euo pipefail
cd core/zeptun
ZIG_CACHE=""
ZEPTUN_ROOT="$PWD"
if [ "${FCAE_MATRIX_NAME}" = "windows-x64" ]; then
  ZIG_CACHE="$(mktemp -d "${RUNNER_TEMP:?}/zeptun-cache.XXXXXX")"
  trap 'rm -rf "$ZIG_CACHE"' EXIT
fi
# The app's deployment target. A bare `x86_64-macos` triple lets Zig take the
# *runner's* macOS version, which stamped the archive with LC_BUILD_VERSION 15.0
# while the app links against 13.0: ld warns that the object "was built for newer
# 'macOS' version", and the object may reference APIs that do not exist at the
# minimum the app still supports. Pin the version into the triple instead.
MACOS_MIN="13.0"
case "${FCAE_MATRIX_NAME}" in
  linux-x64)   zig build -Dtarget=x86_64-linux-gnu -Doptimize=small ;;
  windows-x64)
    # Use Zeptun's own libc allocator path, avoiding Zig's TLS-backed SMP
    # allocator in the Windows host. Keep the upstream sources unchanged.
    # The recipe lives in the zeptun bridge (core/fcae-ffi/bridges/zeptun/zig),
    # which is also what that bridge's build.rs runs when the archive is missing.
    ZIG_DIR="$PWD/../fcae-ffi/bridges/zeptun/zig"
    test -f "$ZIG_DIR/build.zig"
    (cd "$ZIG_DIR" && zig build -Dtarget=x86_64-windows-gnu -Doptimize=small \
      --cache-dir "$ZIG_CACHE" --prefix "$ZEPTUN_ROOT/zig-out")
    ;;
  macos-arm64) zig build -Dtarget="aarch64-macos.$MACOS_MIN" -Doptimize=small ;;
  macos-x64)   zig build -Dtarget="x86_64-macos.$MACOS_MIN" -Doptimize=small ;;
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
  # The static archive and DLL import library can both be called zeptun.lib
  # for a Windows COFF target. Inspect this build's isolated cache, not the
  # potentially overwritten install output or a restored cache.
  STATIC_ZEPTUN=""
  while IFS= read -r -d '' candidate; do
    if ! llvm-nm --defined-only "$candidate" > "$ZIG_CACHE/symbols.txt" 2> "$ZIG_CACHE/nm-error.txt"; then
      echo "Cannot inspect Zeptun candidate $candidate:"
      cat "$ZIG_CACHE/nm-error.txt"
      continue
    fi
    if ! grep -Eq '[[:space:]]T[[:space:]]+zeptun_create$' "$ZIG_CACHE/symbols.txt" ||
       grep -q '__imp_zeptun_create' "$ZIG_CACHE/symbols.txt"; then
      continue
    fi
    if [ -n "$STATIC_ZEPTUN" ] && ! cmp -s "$STATIC_ZEPTUN" "$candidate"; then
      echo "::error::multiple different Zeptun static archives found"
      exit 1
    fi
    STATIC_ZEPTUN="$candidate"
  done < <(find "$ZIG_CACHE/o" -type f \
    \( -name 'zeptun.lib' -o -name 'libzeptun.a' \) -print0)
  if [ -z "$STATIC_ZEPTUN" ]; then
    echo "::error::no Zeptun static archive with zeptun_create found in $ZIG_CACHE/o"
    find "$ZIG_CACHE/o" -type f \( -name '*.lib' -o -name '*.a' \) -print | head -80 || true
    exit 1
  fi
  llvm-nm --undefined-only "$STATIC_ZEPTUN" > "$ZIG_CACHE/undefined.txt"
  if ! grep -Eq '[[:space:]]U[[:space:]]+(__imp_)?malloc$' "$ZIG_CACHE/undefined.txt"; then
    echo "::error::Windows Zeptun archive does not reference the C allocator"
    exit 1
  fi
  mkdir -p zig-out/lib
  cp "$STATIC_ZEPTUN" zig-out/lib/libzeptun.a
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
