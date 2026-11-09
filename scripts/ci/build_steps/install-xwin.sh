#!/usr/bin/env bash
set -euo pipefail

version=0.10.0
package="xwin-${version}-x86_64-unknown-linux-musl"
archive="$RUNNER_TEMP/${package}.tar.gz"
binary_sha256=d870eb4b2f390878af6da1ccd3cf321d22fcb72720984853b4be732ae597fc88
source_sha256=e3ae2ef8d627ac8d97b3aeb67e4b711520154edca5cc80fbec551415c7b671ef
install_dir="$RUNNER_TEMP/fcae-xwin"

rm -rf "$install_dir" "$RUNNER_TEMP/$package" "$RUNNER_TEMP/xwin-$version"
rm -f "$archive"
mkdir -p "$install_dir/bin"
if curl -fsSL --retry 2 --retry-all-errors --retry-delay 5 --connect-timeout 20 --max-time 90 \
    "https://github.com/Jake-Shadle/xwin/releases/download/${version}/${package}.tar.gz" -o "$archive" \
    && printf '%s  %s\n' "$binary_sha256" "$archive" | sha256sum -c -; then
    tar -xzf "$archive" -C "$RUNNER_TEMP" "$package/xwin"
    install -m 755 "$RUNNER_TEMP/$package/xwin" "$install_dir/bin/xwin"
else
    echo '::warning::xwin release download unavailable or invalid; building the pinned crates.io source'
    source_archive="$RUNNER_TEMP/xwin-$version.crate"
    rm -f "$source_archive"
    curl -fsSL --retry 3 --retry-all-errors --retry-delay 5 --connect-timeout 20 --max-time 90 \
        "https://static.crates.io/crates/xwin/xwin-${version}.crate" -o "$source_archive"
    printf '%s  %s\n' "$source_sha256" "$source_archive" | sha256sum -c -
    tar -xzf "$source_archive" -C "$RUNNER_TEMP"
    cargo install --locked --path "$RUNNER_TEMP/xwin-$version" --root "$install_dir"
fi
test -x "$install_dir/bin/xwin"
