#!/usr/bin/env bash
set -euo pipefail
export IPHONEOS_DEPLOYMENT_TARGET=16.0
unset MACOSX_DEPLOYMENT_TARGET || true
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
channel_flags=''
if [[ "${FCAE_IS_PRERELEASE:-false}" == true ]]; then channel_flags=FCAE_IS_PRERELEASE; fi
xcodebuild -project ios/FCAE.xcodeproj -scheme FCAE -configuration Release \
  -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath build/ios \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY='' \
  "MARKETING_VERSION=${FCAE_MACOS_VERSION:-1.0.0}" \
  "FCAE_RELEASE_VERSION=${FCAE_VERSION:-1.0.0}" \
  "FCAE_CHANNEL_FLAGS=$channel_flags" \
  CURRENT_PROJECT_VERSION="${GITHUB_RUN_NUMBER:-1}" build
