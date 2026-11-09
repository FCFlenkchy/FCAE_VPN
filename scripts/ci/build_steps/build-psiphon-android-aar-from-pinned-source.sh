#!/usr/bin/env bash
set -euo pipefail
ROOT="$PWD"
PSIPHON_REV=$(git rev-parse HEAD:core/psiphon)
test "$(git -C core/psiphon rev-parse HEAD)" = "$PSIPHON_REV"
PSIPHON_GIT_DIR=$(git -C core/psiphon rev-parse --absolute-git-dir)
echo "Building core/psiphon at $PSIPHON_REV"
PSIPHON_CONTEXT=$(mktemp -d "$RUNNER_TEMP/fcae-psiphon-context.XXXXXX")
trap 'rm -rf "$PSIPHON_CONTEXT"' EXIT
cp -a core/psiphon/MobileLibrary/. "$PSIPHON_CONTEXT/"
install -m 0644 /etc/ssl/certs/ca-certificates.crt "$PSIPHON_CONTEXT/.fcae-ca-bundle.crt"
python3 scripts/ci/prepare_psiphon_dockerfile.py \
  "$PSIPHON_CONTEXT/Android/Dockerfile" "$PSIPHON_CONTEXT/Android/Dockerfile.ci"
docker build --platform=linux/amd64 -t fcae-psiphon-android \
  -f "$PSIPHON_CONTEXT/Android/Dockerfile.ci" "$PSIPHON_CONTEXT"
rm -rf "$PSIPHON_CONTEXT"
docker run --platform=linux/amd64 --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/go-cache \
  -e GIT_DIR=/psiphon-git \
  -e GIT_WORK_TREE=/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core \
  -e PSIPHON_REV="$PSIPHON_REV" \
  -v "$PSIPHON_GIT_DIR:/psiphon-git:ro" \
  -v "$ROOT/core/psiphon:/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core" \
  fcae-psiphon-android /bin/bash -c '
    set -euo pipefail
    cd "$GIT_WORK_TREE/MobileLibrary/Android"
    test "$(git rev-parse HEAD)" = "$PSIPHON_REV"
    git rev-parse --short=10 HEAD
    ./make.bash
  '
mkdir -p android/psiphon/libs
cp core/psiphon/MobileLibrary/Android/ca.psiphon.aar android/psiphon/libs/
INSPECT=$(mktemp -d)
trap 'rm -rf "$INSPECT"' EXIT
unzip -q android/psiphon/libs/ca.psiphon.aar 'jni/*' -d "$INSPECT"
for ABI in arm64-v8a armeabi-v7a x86 x86_64; do
  LIB="$INSPECT/jni/$ABI/libgojni.so"
  test -s "$LIB"
  readelf -lW "$LIB" | awk '$1 == "LOAD" { found=1; if ($NF != "0x4000") bad=1 } END { exit (!found || bad) }'
done
