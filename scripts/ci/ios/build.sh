#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
export IPHONEOS_DEPLOYMENT_TARGET=16.0
export SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
export CARGO_TARGET_DIR="$PWD/target"
export CC_aarch64_apple_ios="$(xcrun --sdk iphoneos --find clang)"
export CXX_aarch64_apple_ios="$(xcrun --sdk iphoneos --find clang++)"
export AR_aarch64_apple_ios="$(xcrun --sdk iphoneos --find ar)"
export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="$CC_aarch64_apple_ios"
export CFLAGS_aarch64_apple_ios="-target arm64-apple-ios16.0 -isysroot $SDKROOT"
export CXXFLAGS_aarch64_apple_ios="$CFLAGS_aarch64_apple_ios"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_ios="$CFLAGS_aarch64_apple_ios"
export CMAKE_TOOLCHAIN_FILE_aarch64_apple_ios="$PWD/ios/toolchain.cmake"
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
unset MACOSX_DEPLOYMENT_TARGET || true
bash scripts/ci/ios/build-tun-engines.sh
export FCAE_ZEPTUN_LIBDIR="$PWD/target/ios-native/zeptun"
export FCAE_HEV_LIBDIR="$PWD/target/ios-native/hev"
cargo build --manifest-path core/fcae-ffi/Cargo.toml --locked --release \
  --target aarch64-apple-ios -p fcae-ffi \
  --features aether,firefox,psiphon-live,xray,singbox,zeptun,hev

# Generate app-icon assets from the existing project artwork, never a remote asset.
python3 - <<'PY'
from pathlib import Path
import json,subprocess
root=Path('ios/Assets.xcassets/AppIcon.appiconset');root.mkdir(parents=True,exist_ok=True)
images=[]
for idiom,size,scales in [('iphone',20,[2,3]),('iphone',29,[2,3]),('iphone',40,[2,3]),('iphone',60,[2,3]),('ipad',20,[1,2]),('ipad',29,[1,2]),('ipad',40,[1,2]),('ipad',76,[1,2]),('ipad',83.5,[2]),('ios-marketing',1024,[1])]:
 for scale in scales:
  pixels=int(size*scale);name=f'{idiom}-{size}-{scale}.png'
  subprocess.run(['sips','-z',str(pixels),str(pixels),'src_cpp/icon_1024.png','--out',str(root/name)],check=True,stdout=subprocess.DEVNULL)
  images.append({'idiom':idiom,'size':f'{size}x{size}','scale':f'{scale}x','filename':name})
(root/'Contents.json').write_text(json.dumps({'images':images,'info':{'version':1,'author':'xcode'}}))
PY
xcodegen generate --spec ios/project.yml
mkdir -p package
channel_flags=''
if [[ "${FCAE_IS_PRERELEASE:-false}" == true ]]; then channel_flags=FCAE_IS_PRERELEASE; fi
xcodebuild -project ios/FCAE.xcodeproj -scheme FCAE -configuration Release \
  -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath build/ios \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY='' \
  "MARKETING_VERSION=${FCAE_MACOS_VERSION:-1.0.0}" \
  "FCAE_RELEASE_VERSION=${FCAE_VERSION:-1.0.0}" \
  "FCAE_CHANNEL_FLAGS=$channel_flags" \
  CURRENT_PROJECT_VERSION="${GITHUB_RUN_NUMBER:-1}" build
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
ipa="$PWD/package/FCAE_VPN-ios-arm64-unsigned.ipa"
(cd build/ios/ipa && /usr/bin/zip -q -9 -r "$ipa" Payload)
/usr/bin/unzip -t "$ipa"
