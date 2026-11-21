#!/usr/bin/env bash
set -euo pipefail
mkdir -p package
app="$PWD/build/ios/Build/Products/Release-iphoneos/FCAE.app"
# Fail the job instead of uploading an app without its VPN provider or core.
test -f "$app/PlugIns/PacketTunnel.appex/PacketTunnel"
# Re-signers must see a normal app/extension pair with matching identifiers.
# Runtime discovery follows the signed extension ID, not a hard-coded string.
python3 - "$app" <<'PYIOS'
import plistlib,sys
from pathlib import Path
app=Path(sys.argv[1])
with (app/'Info.plist').open('rb') as f: info=plistlib.load(f)
providers=[]
for extension in (app/'PlugIns').glob('*.appex'):
 with (extension/'Info.plist').open('rb') as f: item=plistlib.load(f)
 if item.get('NSExtension',{}).get('NSExtensionPointIdentifier')=='com.apple.networkextension.packet-tunnel':
  assert item['CFBundleIdentifier'].startswith(info['CFBundleIdentifier']+'.'), 'Tunnel bundle ID must extend the app bundle ID'
  assert (extension/item['CFBundleExecutable']).is_file(), 'Missing tunnel executable'
  providers.append(extension)
assert len(providers)==1, 'IPA must contain exactly one Packet Tunnel provider'
PYIOS
xcrun lipo "$app/FCAE" -verify_arch arm64
xcrun lipo "$app/PlugIns/PacketTunnel.appex/PacketTunnel" -verify_arch arm64
xcrun nm "$app/PlugIns/PacketTunnel.appex/PacketTunnel" > build/ios/extension-symbols.txt
grep -q ' _fcae_start$' build/ios/extension-symbols.txt
for symbol in t2s_start zeptun_create hev_socks5_tunnel_main_from_str; do
  grep -q " _$symbol\$" build/ios/extension-symbols.txt
done
rm -rf build/ios/ipa; mkdir -p build/ios/ipa/Payload
cp -R "$app" build/ios/ipa/Payload/
ipa="$PWD/package/FCAE_VPN-ios-arm64.ipa"
rm -f "$ipa"
(cd build/ios/ipa && /usr/bin/zip -q -9 -r "$ipa" Payload)
/usr/bin/unzip -t "$ipa"
