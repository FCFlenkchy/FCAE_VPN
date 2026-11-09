#!/usr/bin/env bash
set -euo pipefail
ZIG_VER=0.17.1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  TUPLE=x86_64-linux;  SHA=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;;
  Darwin-arm64)  TUPLE=aarch64-macos; SHA=75f1bc7a1e9852f17ec9a0c1895f767c4ec56d46bc8a834920eece1d0359dd8d ;;
  Darwin-x86_64) TUPLE=x86_64-macos;  SHA=9af07b20319fbd0c92ee46ad23e81d6a782b1aaea2cfb8dcbff35f1d2c7ddbb7 ;;
  *) echo "::error::unsupported runner $(uname -s)-$(uname -m)"; exit 1 ;;
esac
ARCHIVE="zig-${TUPLE}-${ZIG_VER}.tar.xz"
PREFIX="${RUNNER_TOOL_CACHE}/zig-${ZIG_VER}"
mkdir -p "$PREFIX"
if [ ! -x "${PREFIX}/zig" ]; then
  file_sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
  }
  URLS=(
    "https://ziglang.org/download/${ZIG_VER}/${ARCHIVE}"
    "https://ziglang.freetls.fastly.net/${ARCHIVE}"
    "https://pkg.hexops.org/zig/${ARCHIVE}"
    "https://zig.linus.dev/zig/${ARCHIVE}"
    "https://zig.squirl.dev/${ARCHIVE}"
    "https://zig.mirror.mschae23.de/zig/${ARCHIVE}"
    "https://zigmirror.com/${ARCHIVE}"
    "https://zig.tilok.dev/${ARCHIVE}"
    "https://zigmirror.hryx.net/zig/${ARCHIVE}"
  )
  if list=$(curl -fsSL --retry 2 --connect-timeout 15 --max-time 30 \
       https://ziglang.org/download/community-mirrors.txt 2>/dev/null); then
    while IFS= read -r base; do
      [ -n "$base" ] || continue
      URLS+=("${base%/}/${ARCHIVE}")
    done <<< "$list"
  fi
  TMP="${RUNNER_TEMP}/${ARCHIVE}"
  ok=0
  seen=
  for url in "${URLS[@]}"; do
    case " $seen " in *" $url "*) continue ;; esac
    seen+=" $url"
    echo "Trying $url"
    rm -f "$TMP"
    if curl -fL --retry 3 --retry-delay 2 --retry-all-errors \
         --connect-timeout 20 --max-time 180 -o "$TMP" "$url" \
         && [ "$(file_sha "$TMP")" = "$SHA" ]; then
      ok=1
      break
    fi
    echo "failed: $url"
  done
  if [ "$ok" != 1 ]; then
    echo "::error::failed to download Zig ${ZIG_VER} from every mirror"
    exit 1
  fi
  tar -xJf "$TMP" -C "$PREFIX" --strip-components=1
  rm -f "$TMP"
fi
echo "$PREFIX" >> "$GITHUB_PATH"
"${PREFIX}/zig" version
