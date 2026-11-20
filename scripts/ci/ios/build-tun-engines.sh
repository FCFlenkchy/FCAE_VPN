#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
root="$PWD"
: "${SDKROOT:?Set SDKROOT to the iPhoneOS SDK}"
: "${IPHONEOS_DEPLOYMENT_TARGET:=16.0}"
# Both engines accept a host-owned Darwin fd and use the four-byte AF prefix.
# Neither creates the system interface nor owns its routes/DNS on iOS.
zeptun="$root/target/ios-native/zeptun"
hev="$root/target/ios-native/hev"
mkdir -p "$zeptun" "$hev"
(cd core/zeptun && zig build -Dtarget="aarch64-ios.${IPHONEOS_DEPLOYMENT_TARGET}" \
    -Doptimize=small -Dmobile=true -Dstrip=true --sysroot "$SDKROOT")
cp core/zeptun/zig-out/lib/libzeptun.a "$zeptun/"
cc="$(xcrun --sdk iphoneos --find clang)"
ar="$(xcrun --sdk iphoneos --find ar)"
flags="-target arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET} -isysroot \"$SDKROOT\""
make -C core/hev-socks5-tunnel clean
make -C core/hev-socks5-tunnel static CC="$cc" PP="$cc" AR="$ar" CFLAGS="$flags" LFLAGS="$flags"
cp core/hev-socks5-tunnel/bin/libhev-socks5-tunnel.a "$hev/"
for library in yaml lwip hev-task-system; do
    cp "core/hev-socks5-tunnel/third-part/$library/bin/lib$library.a" "$hev/"
done
for archive in "$zeptun"/*.a "$hev"/*.a; do xcrun lipo -verify_arch arm64 "$archive"; done
