#!/usr/bin/env bash
set -euo pipefail
mkdir -p package

APP="package/FCAE VPN.app"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Frameworks"
mkdir -p "$APP/Contents/Resources"

cp build/fcaevpn "$APP/Contents/MacOS/fcaevpn"
chmod +x "$APP/Contents/MacOS/fcaevpn"
# Desktop Psiphon shares the statically linked Go archive with tun2socks.

# cronet, the Chromium network stack behind sing-box's naive outbound, is a
# dylib rather than part of the executable. sing-box's Go binding loads it
# in-process with cronet-go's purego loader, which looks in the executable's own
# directory first and by that exact name -- so it goes in MacOS/, not Frameworks/.
test -f build/libcronet.dylib || {
  echo "::error::build/libcronet.dylib is missing; sing-box's naive outbound cannot load"
  exit 1
}
cp build/libcronet.dylib "$APP/Contents/MacOS/libcronet.dylib"

ICONSET="$RUNNER_TEMP/AppIcon.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

gen() { sips -s format png -z "$1" "$1" src_cpp/icon_1024.png --out "$ICONSET/$2" >/dev/null; }
gen 16   icon_16x16.png
gen 32   icon_16x16@2x.png
gen 32   icon_32x32.png
gen 64   icon_32x32@2x.png
gen 128  icon_128x128.png
gen 256  icon_128x128@2x.png
gen 256  icon_256x256.png
gen 512  icon_256x256@2x.png
gen 512  icon_512x512.png
gen 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
cp src_cpp/icon_1024.png "$APP/Contents/Resources/AppIcon.png"
ls -la "$APP/Contents/Resources/"

# FreeType is a text rasteriser, not an engine library: a package manager builds
# it as a dylib, so a machine with Homebrew gets a binary that only runs on a
# machine with Homebrew. When the build linked it dynamically, copy it into the
# bundle and point the executable at the embedded copy. Static builds (and
# builds without FreeType) skip all of this.
FT_DYLIB="$(otool -L "$APP/Contents/MacOS/fcaevpn" | tail -n +2 \
            | awk '/libfreetype/ {print $1; exit}')"
if [ -n "$FT_DYLIB" ] && [ -f "$FT_DYLIB" ]; then
  echo "Embedding FreeType: $FT_DYLIB"
  FT_BASE="$(basename "$FT_DYLIB")"
  cp "$FT_DYLIB" "$APP/Contents/Frameworks/$FT_BASE"
  chmod u+w "$APP/Contents/Frameworks/$FT_BASE"
  # Point the executable's reference inside the bundle instead of at the
  # package-manager prefix. Only that reference matters -- it is what the loader
  # follows -- so the dylib's own LC_ID_DYLIB is left alone.
  #
  # install_name_tool invalidates the code signature, which is why this runs
  # here and not after the signing block further down.
  install_name_tool -change "$FT_DYLIB" "@executable_path/../Frameworks/$FT_BASE" \
    "$APP/Contents/MacOS/fcaevpn"
  # The copied dylib's own dependencies are all system libraries (z, bz2, lzma,
  # libSystem), which resolve everywhere, so nothing else has to move with it.
fi

echo "Binary dynamic dependencies:"
otool -L "$APP/Contents/MacOS/fcaevpn" || true
# Every load must resolve from the OS: an engine library or a
# Homebrew prefix here means it linked dynamically instead of
# statically, and breaks on machines without that path.
if otool -L "$APP/Contents/MacOS/fcaevpn" | tail -n +2 | grep -qiE 'libzeptun|libfcae_psiphon|libhev|libfcae_go_bridge|/usr/local/|/opt/homebrew|/opt/local/'; then
  echo "::error::fcaevpn links a library that is supposed to be statically linked or embedded"
  exit 1
fi
# cronet is the one engine library that is not linked: it is loaded at run time
# from beside the executable, so an entry here means Chromium is in the binary.
if otool -L "$APP/Contents/MacOS/fcaevpn" | tail -n +2 | grep -qi 'libcronet'; then
  echo "::error::fcaevpn links libcronet; it must be loaded at run time from beside the executable"
  exit 1
fi

MACOS_VER="${FCAE_MACOS_VERSION}"
printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
  '<plist version="1.0">' \
  '<dict>' \
  '    <key>CFBundleExecutable</key>' \
  '    <string>fcaevpn</string>' \
  '    <key>CFBundleIdentifier</key>' \
  '    <string>com.fc.fcaevpn</string>' \
  '    <key>CFBundleName</key>' \
  '    <string>FCAE VPN</string>' \
  '    <key>CFBundleVersion</key>' \
  '    <string>'"${MACOS_VER}"'</string>' \
  '    <key>CFBundleShortVersionString</key>' \
  '    <string>'"${MACOS_VER}"'</string>' \
  '    <key>CFBundlePackageType</key>' \
  '    <string>APPL</string>' \
  '    <key>CFBundleIconFile</key>' \
  '    <string>AppIcon.icns</string>' \
  '    <key>CFBundleIconName</key>' \
  '    <string>AppIcon</string>' \
  '    <key>CFBundleDisplayName</key>' \
  '    <string>FCAE VPN</string>' \
  '    <key>CFBundleInfoDictionaryVersion</key>' \
  '    <string>6.0</string>' \
  '    <key>CFBundleSignature</key>' \
  '    <string>????</string>' \
  '    <key>LSApplicationCategoryType</key>' \
  '    <string>public.app-category.utilities</string>' \
  '    <key>NSPrincipalClass</key>' \
  '    <string>NSApplication</string>' \
  '    <key>NSHighResolutionCapable</key>' \
  '    <true/>' \
  '    <key>LSMinimumSystemVersion</key>' \
  '    <string>13.0</string>' \
  '</dict>' \
  '</plist>' > "$APP/Contents/Info.plist"

touch "$APP"

KEYCHAIN_PATH="$RUNNER_TEMP/build.keychain-db"
if [ -f "$KEYCHAIN_PATH" ]; then
  sign() {
    codesign --force --sign "FC" --keychain "$KEYCHAIN_PATH" --timestamp "$@" || \
      codesign --force --sign "FC" --keychain "$KEYCHAIN_PATH" "$@"
  }
else
  echo "No signing keychain found, falling back to ad-hoc signing"
  sign() { codesign --force --sign - "$@"; }
fi
# NetworkExtension provisioning is a separate distribution gate. Never apply
# copied entitlements to an ad-hoc build and advertise it as an installed helper.
if [ "${FCAE_PACKAGE_MACOS_NE:-0}" = 1 ]; then
  test -f "$KEYCHAIN_PATH" || { echo "::error::NetworkExtension packaging requires a signing identity"; exit 1; }
  test -f "${FCAE_MACOS_NE_APP_PROFILE:-}" || { echo "::error::Missing app NetworkExtension provisioning profile"; exit 1; }
  test -f "${FCAE_MACOS_NE_EXTENSION_PROFILE:-}" || { echo "::error::Missing extension provisioning profile"; exit 1; }
  test -d build/FCAEAppRouting.appex || { echo "::error::Build the FCAE macOS extension target first"; exit 1; }
  mkdir -p "$APP/Contents/PlugIns"
  ditto build/FCAEAppRouting.appex "$APP/Contents/PlugIns/FCAEAppRouting.appex"
  cp "$FCAE_MACOS_NE_APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
  cp "$FCAE_MACOS_NE_EXTENSION_PROFILE" "$APP/Contents/PlugIns/FCAEAppRouting.appex/Contents/embedded.provisionprofile"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $MACOS_VER" "$APP/Contents/PlugIns/FCAEAppRouting.appex/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $MACOS_VER" "$APP/Contents/PlugIns/FCAEAppRouting.appex/Contents/Info.plist"
  sign --entitlements macos/app-routing/Extension.entitlements "$APP/Contents/PlugIns/FCAEAppRouting.appex"
fi
# The cronet dylib is loaded inside the process, not by the loader, so it is
# code of its own and carries its own signature. Signing it before the bundle
# keeps the seal over it intact.
sign "$APP/Contents/MacOS/libcronet.dylib"
if [ -n "$FT_DYLIB" ] && [ -f "$FT_DYLIB" ]; then
  sign "$APP/Contents/Frameworks/$(basename "$FT_DYLIB")"
fi
if [ "${FCAE_PACKAGE_MACOS_NE:-0}" = 1 ]; then
  # Nested extension was signed with its own entitlements; --deep here would
  # replace those with the host's signature/entitlements.
  sign --entitlements macos/app-routing/App.entitlements "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
else
  sign --deep "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP" || true
fi

DMG_ROOT="$RUNNER_TEMP/dmgroot"
rm -rf "$DMG_ROOT"
mkdir -p "$DMG_ROOT"
cp -R "$APP" "$DMG_ROOT/"
ln -s /Applications "$DMG_ROOT/Applications"

DMG_NAME="FCAE_VPN-${FCAE_MATRIX_NAME}.dmg"
hdiutil create -volname "FCAE VPN" -srcfolder "$DMG_ROOT" -ov -format UDZO "package/${DMG_NAME}"

ls -lah package/
test -f "package/${DMG_NAME}"
