#!/usr/bin/env bash
set -euo pipefail
mkdir -p package
app="$PWD/build/ios/Build/Products/Release-iphoneos/FCAE.app"
# Fail the job instead of uploading an app without its VPN provider or core.
test -f "$app/PlugIns/PacketTunnel.appex/PacketTunnel"
xcrun lipo -verify_arch arm64 "$app/FCAE"
xcrun lipo -verify_arch arm64 "$app/PlugIns/PacketTunnel.appex/PacketTunnel"
xcrun nm "$app/PlugIns/PacketTunnel.appex/PacketTunnel" > build/ios/extension-symbols.txt
grep -q ' _fcae_start$' build/ios/extension-symbols.txt
for symbol in t2s_start zeptun_create hev_socks5_tunnel_main_from_str; do
  grep -q " _$symbol\$" build/ios/extension-symbols.txt
done
rm -rf build/ios/ipa; mkdir -p build/ios/ipa/Payload
cp -R "$app" build/ios/ipa/Payload/
ipa="$PWD/package/FCAE_VPN-ios-arm64.ipa"
(cd build/ios/ipa && /usr/bin/zip -q -9 -r "$ipa" Payload)
/usr/bin/unzip -t "$ipa"
