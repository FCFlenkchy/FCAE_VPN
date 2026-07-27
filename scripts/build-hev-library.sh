#!/bin/bash
# Build hev-socks5-tunnel as a shared library for embedding

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HEV_SRC="$PROJECT_ROOT/hev-socks5-tunnel"

if [ ! -d "$HEV_SRC" ]; then
    echo "[-] hev-socks5-tunnel not found at $HEV_SRC"
    echo "[+] Please initialize submodule: git submodule update --init --recursive"
    exit 1
fi

echo "[*] Building hev-socks5-tunnel shared library..."
cd "$HEV_SRC"

# Build shared library
make shared

# Determine platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_NAME="libhev-socks5-tunnel.so"
    TARGET_DIR="$PROJECT_ROOT/target/release"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_NAME="libhev-socks5-tunnel.dylib"
    TARGET_DIR="$PROJECT_ROOT/target/release"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]]; then
    LIB_NAME="hev-socks5-tunnel.dll"
    TARGET_DIR="$PROJECT_ROOT/target/release"
else
    echo "[-] Unsupported platform: $OSTYPE"
    exit 1
fi

# Copy the library to target directory
mkdir -p "$TARGET_DIR"
if [ -f "$HEV_SRC/$LIB_NAME" ]; then
    cp "$HEV_SRC/$LIB_NAME" "$TARGET_DIR/"
    echo "[+] Copied $LIB_NAME to $TARGET_DIR/"
elif [ -f "$HEV_SRC/src/$LIB_NAME" ]; then
    cp "$HEV_SRC/src/$LIB_NAME" "$TARGET_DIR/"
    echo "[+] Copied $LIB_NAME to $TARGET_DIR/"
else
    echo "[-] Could not find $LIB_NAME in build output"
    echo "[-] Check if the build succeeded"
    exit 1
fi

echo "[+] Build complete! Library available at: $TARGET_DIR/$LIB_NAME"
echo "[+] To use it, set: export HEV_SOCKS5_TUNNEL_LIB=$TARGET_DIR/$LIB_NAME"
