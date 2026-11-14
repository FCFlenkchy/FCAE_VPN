#!/usr/bin/env bash
set -euo pipefail
mkdir -p package
# Named, never a glob: build/ is a restored cache and may still hold
# artifacts from an older run. zeptun is linked into the executable,
# so there is no zeptun binary or DLL to ship on any platform.
ARTIFACT="FCAE_VPN-${FCAE_MATRIX_NAME}"
case "${FCAE_MATRIX_NAME}" in
  windows-x64) cp build/fcaevpn.exe "package/$ARTIFACT.exe" ;;
  *)           cp build/fcaevpn     "package/$ARTIFACT" ;;
esac
chmod +x package/* 2>/dev/null || true

# cronet, the Chromium network stack behind sing-box's naive outbound, is not
# linked into the executable: sing-box's Go binding loads it in-process with
# cronet-go's purego loader, which looks in the executable's own directory first
# and nowhere near a lib/ subdirectory. So it ships flat beside the binary, under
# the name that loader builds from GOOS.
case "${FCAE_MATRIX_NAME}" in
  windows-x64) CRONET_LIB=libcronet.dll ;;
  *)           CRONET_LIB=libcronet.so ;;
esac
test -f "build/$CRONET_LIB" || {
  echo "::error::build/$CRONET_LIB is missing; sing-box's naive outbound cannot load"
  exit 1
}
cp "build/$CRONET_LIB" "package/$CRONET_LIB"

if [ "${FCAE_MATRIX_NAME}" = "windows-x64" ]; then
  # HEV, Zeptun, Psiphon and tun2socks are linked in-process.
  # Wintun remains dynamically loaded.
  echo "Windows package:"
  ls -la package/
fi

if [ "${FCAE_MATRIX_NAME}" = "linux-x64" ]; then
  BIN=build/fcaevpn
  if [ -f "$BIN" ]; then
    echo "Checking dynamic dependencies:"
    ldd "$BIN" 2>/dev/null | grep -v -E 'linux-vdso|ld-linux|libc\.|libm\.|libdl\.|librt\.|libpthread\.|libstdc\+\+\.|libgcc_s\.|libX11\.|libXi\.|libGL\.|libGLX\.|libGLdispatch\.|libxcb\.|libXau\.|libXdmcp\.|libbsd\.|libmd\.' || true
    # No launcher wrapper: the released Linux package is the
    # executable alone. The exec bit is re-asserted in the zip job
    # because the artifact upload/download round-trip drops modes;
    # systems without libOpenGL.so.0 get the loader's own message
    # and the distro package is the fix, not a wrapper script.
  fi
fi

cd package
ls -la
case "${FCAE_MATRIX_NAME}" in
  windows-x64) SHIPPED="$ARTIFACT.exe" ;;
  *)           SHIPPED="$ARTIFACT" ;;
esac
test -f "$SHIPPED" || { echo "::error::$SHIPPED missing from the package"; exit 1; }

# Inspect the released artifact, never a path inside build/: that
# directory is a cache hit and can hold leftovers from an older run.
if [ "${FCAE_MATRIX_NAME}" = "windows-x64" ]; then
  EXE="$ARTIFACT.exe"

  # The app exe was copied straight to its released name, so it is
  # the only .exe allowed to be here. Anything else is a leftover
  # from the restored build/ cache.
  STRAY="$(find . -maxdepth 1 -name '*.exe' ! -name "$EXE" -printf '%f\n')"
  if [ -n "$STRAY" ]; then
    echo "::error::unexpected executable in the package:"
    printf '%s\n' "$STRAY" | sed 's/^/  /'
    exit 1
  fi
  test -f "$EXE" || { echo "::error::$EXE missing from the package"; exit 1; }

  # No PE import may name a file that is embedded in the exe or
  # linked into it statically, or a user with the exe alone fails at
  # process start instead of at engine load.
  OBJDUMP=""
  for candidate in objdump x86_64-w64-mingw32-objdump; do
    if command -v "$candidate" >/dev/null 2>&1; then
      OBJDUMP="$candidate"
      break
    fi
  done
  if [ -z "$OBJDUMP" ]; then
    echo "::warning::no objdump on PATH; skipping the $EXE import check"
  else
    IMPORTS="$("$OBJDUMP" -p "$EXE" | awk '/DLL Name:/ { print $3 }' | sort -u)"
    echo "$EXE imports:"
    echo "$IMPORTS" | sed 's/^/  /'
    if echo "$IMPORTS" | grep -qiE '^(libhev-socks5-tunnel\.dll|hev-socks5-tunnel\.dll|wintun\.dll|zeptun\.dll|libfcae_psiphon\.dll|libgcc_s_seh-1\.dll|libstdc\+\+-6\.dll|libwinpthread-1\.dll)$'; then
      echo "::error::$EXE imports a DLL that is supposed to be embedded or statically linked"
      exit 1
    fi
    # cronet is loaded at run time beside the exe, so it must not be an import
    # as well: that would put Chromium's net/QUIC stack back into the exe.
    if echo "$IMPORTS" | grep -qiE '^libcronet\.dll$'; then
      echo "::error::$EXE imports libcronet.dll; it must be loaded at run time from beside the exe"
      exit 1
    fi
  fi

  : "${FCAE_HEV_LIBDIR:?the HEV static archive directory was not exported}"
  for name in hev-socks5-tunnel yaml lwip hev-task-system; do
    test -s "$FCAE_HEV_LIBDIR/lib$name.a" || {
      echo "::error::missing HEV archive lib$name.a"; exit 1;
    }
  done
  # The task-system coroutine switch cannot run with a CET shadow stack.
  # GNU PE links normally leave this flag unset; reject an incompatible EXE.
  CET_INFO="$(llvm-readobj --coff-debug-directory "$EXE")"
  if grep -qi 'CET_COMPAT' <<< "$CET_INFO"; then
    echo "::error::$EXE is marked CET shadow-stack compatible"
    exit 1
  fi

fi

if [ "${FCAE_MATRIX_NAME}" = "linux-x64" ]; then
  # Direct DT_NEEDED entries only: ldd shows transitive deps too
  # (libGL pulls libz), which must not fail this check.
  NEEDED="$(readelf -d "$SHIPPED" | awk -F'[][]' '/NEEDED/ { print $2 }' | sort -u)"
  echo "$SHIPPED DT_NEEDED:"
  echo "$NEEDED" | sed 's/^/  /'
  # libOpenGL.so.0 must not reach the DT_NEEDED list: it ships only
  # in the optional `libopengl0` package, so a build that names it
  # fails to start on minimal installs. CMakeLists.txt links
  # libGL.so.1 instead; reject any link that brings the dispatcher
  # back.
  if echo "$NEEDED" | grep -qiE 'libzeptun|libfcae_psiphon|libhev|libfcae_go_bridge|libglfw|libstdc\+\+|libgcc_s|libz\.so|libbz2|liblzma|libssl|libcrypto'; then
    echo "::error::$SHIPPED links a library that is supposed to be statically linked"
    exit 1
  fi
  # cronet is the one engine library that is *not* linked: sing-box loads it
  # through cronet-go's purego binding, so a DT_NEEDED entry for it means the
  # executable carries Chromium's net/QUIC stack again.
  if echo "$NEEDED" | grep -qi 'libcronet'; then
    echo "::error::$SHIPPED links libcronet; it must be loaded at run time from beside the executable"
    exit 1
  fi
  if echo "$NEEDED" | grep -q 'libOpenGL\.so'; then
    echo "::error::$SHIPPED still pulls libOpenGL.so.0; CMakeLists.txt should link libGL.so.1 instead"
    exit 1
  fi
fi
