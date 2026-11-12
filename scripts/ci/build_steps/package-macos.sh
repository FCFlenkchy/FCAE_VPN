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

echo "Binary dynamic dependencies:"
otool -L "$APP/Contents/MacOS/fcaevpn" || true
# Every load must resolve from the OS: an engine library or a
# Homebrew prefix here means it linked dynamically instead of
# statically, and breaks on machines without that path.
if otool -L "$APP/Contents/MacOS/fcaevpn" | tail -n +2 | grep -qiE 'libzeptun|libfcae_psiphon|libhev|libfcae_go_bridge|/usr/local/|/opt/homebrew|/opt/local/'; then
  echo "::error::fcaevpn links a library that is supposed to be statically linked or embedded"
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
  codesign --force --deep --sign "FC" --keychain "$KEYCHAIN_PATH" --timestamp "$APP" || \
    codesign --force --deep --sign "FC" --keychain "$KEYCHAIN_PATH" "$APP"
else
  echo "No signing keychain found, falling back to ad-hoc signing"
  codesign --force --deep --sign - "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP" || true

DMG_ROOT="$RUNNER_TEMP/dmgroot"
rm -rf "$DMG_ROOT"
mkdir -p "$DMG_ROOT"
cp -R "$APP" "$DMG_ROOT/"
ln -s /Applications "$DMG_ROOT/Applications"

DMG_NAME="FCAE_VPN-${FCAE_MATRIX_NAME}.dmg"
hdiutil create -volname "FCAE VPN" -srcfolder "$DMG_ROOT" -ov -format UDZO "package/${DMG_NAME}"

ls -lah package/
test -f "package/${DMG_NAME}"
