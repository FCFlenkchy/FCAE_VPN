# FCAE VPN

<p align="center">
  <img src="mountain.png" alt="FCAE VPN" width="100%">
</p>

<p align="center">
  <a href="https://github.com/FCFlenkchy/FCAE_VPN/releases">
    <img src="https://img.shields.io/github/downloads/FCFlenkchy/FCAE_VPN/total?style=for-the-badge&logo=github&label=Downloads" alt="Total downloads">
  </a>
</p>

A censorship circumvention client for Windows, Linux, macOS, Android, and iOS, with TUN and local proxy modes (iOS: TUN only).

## Available cores

- **Aether (WARP)** — Cloudflare WARP support, including Tor routing.
- **Firefox IP Protection** — Rust-based support for Mozilla's Firefox IP Protection service.
- **Psiphon** — Psiphon tunnel core.
- **URnetwork** — Decentralized VPN network. In-process.
- **Xray-core** — VLESS, VMess, Trojan, Shadowsocks, SOCKS5, HTTP, Hysteria2, WireGuard outbounds. In-process.
- **sing-box** — the same, plus TUIC, AnyTLS, Hysteria, NaiveProxy. In-process, full feature set.
- **Mihomo** — the same as Xray-core, plus TUIC, AnyTLS, Hysteria. In-process.

### TUN engines

TUN mode runs on one of these:

- **tun2socks** — Go, on gVisor's network stack. The default.
- **zeptun** — Zig, statically linked.
- **hev-socks5-tunnel** — C.
- **sing-box** — sing-box's own TUN.
- **Xray** — Xray-core's own TUN.
- **Mihomo** — Mihomo's own TUN.
- **sing-tun** — MetaCubeX's sing-tun, as an engine of its own.

## Inline Routing Rules (Aether only)

Aether supports custom routing rules directly in the UI (Routes tab) without needing an external file. These rules apply only to Aether. Rules use a simple format:

```
[direct]ip:190.9.2.4,192.33.45.6:400,example.com
[block]gazo.com,10.0.0.0/8,keyword:ads
```

**Format:**
- `[direct]` — traffic matching these rules bypasses the VPN (direct connection)
- `[block]` — traffic matching these rules is blocked entirely
- Entries are comma or newline separated
- Unprefixed entries default to `[direct]`

**Supported rule types:**
| Type | Example | Description |
|------|---------|-------------|
| Bare domain | `example.com` | Matches domain and all subdomains |
| Full domain | `full:example.com` | Exact domain match only |
| Keyword | `keyword:ads` | Matches if domain contains keyword |
| Regex | `regexp:^ad[0-9]+\.` | Regex pattern match |
| IP / CIDR | `10.0.0.0/8`, `1.2.3.4` | IP address or CIDR range |
| Port | `port:25`, `port:3000-3010` | Port or port range |
| Private | `private` | All LAN/private IPs |
| IP with port | `192.33.45.6:400` | IP address with specific port |

## Platforms

| Platform | Rendering host | UI |
|----------|---------|----|
| Windows | DirectX 11 | ImGui |
| Linux | GLFW + OpenGL | ImGui |
| macOS | AppKit + Metal | ImGui |
| Android | GLSurfaceView + OpenGL ES 3 + JNI | ImGui |
| iOS | UIKit + Metal | ImGui |

### Screenshots

<p align="center">
  <img src="windows_ui.png" alt="Windows UI" height="400">
  &nbsp;
  <img src="android_ui.png" alt="Android UI" height="400">
</p>

## Building

### Requirements

- Rust (latest stable)
- C/C++ compiler (GCC/Clang/MSVC)
- CMake >= 3.22
- Vulkan SDK or DirectX SDK (Windows)
- For Android: NDK, Android SDK, Kotlin
- For iOS: macOS, Xcode with iPhoneOS SDK, XcodeGen, Zig, and the Rust `aarch64-apple-ios` target

### Build the Rust engine first

```bash
cargo build --manifest-path core/Cargo.toml -p aether-ffi --release
```

### Build the native GUI

```bash
cmake -B build -DAETHER_TARGET=LINUX_X64
cmake --build build --config Release
```

Targets: `LINUX_X64`, `WIN_X64`, `MACOS_ARM64`, `MACOS_X64`, `ANDROID_ARM64`.

### Android

Open `android/` in Android Studio and build. The Gradle config invokes CMake with `ANDROID_ARM64` automatically.

### iOS

Build on macOS with full Xcode (including the iPhoneOS SDK), Homebrew, and
Rust installed. This produces an **unsigned arm64 iPhone/iPad app for iOS 16+**,
not a simulator build. Run the following from the repository root; the iOS
scripts build the Rust core themselves, so the generic engine/GUI commands
above are not prerequisites.

```bash
# Select your full Xcode installation if it is not already active.
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -runFirstLaunch

brew install cmake ninja nasm protobuf xcodegen llvm pkg-config go
rustup target add aarch64-apple-ios
rustup component add rust-src llvm-tools-preview
git submodule update --init --recursive

# Run the same iOS build steps as CI in an isolated shell.
(
  set -euo pipefail
  export FCAE_MATRIX_NAME=ios-arm64
  export IPHONEOS_DEPLOYMENT_TARGET=16.0
  export CARGO_TARGET_DIR="$PWD/target"
  export GO_BIN="$(command -v go)"
  export GOTOOLCHAIN=auto

  # Install the exact Zig version pinned by the repository.
  export RUNNER_TOOL_CACHE="$HOME/Library/Caches/fcae-tools"
  export RUNNER_TEMP="$(mktemp -d)"
  trap 'rm -rf "$RUNNER_TEMP"' EXIT
  export GITHUB_PATH="$RUNNER_TEMP/tool-paths"
  bash -e scripts/ci/build_steps/setup-zig.sh
  export PATH="$(cat "$GITHUB_PATH"):$PATH"

  bash -e scripts/ci/build_steps/build-zeptun-engine-libzeptun.sh
  bash -e scripts/ci/build_steps/build-hev-socks5-tunnel-engine-libhev-socks5-tunnel.sh
  bash -e scripts/ci/build_steps/build-rust-engine-ffi-in-process.sh
  bash -e scripts/ci/build_steps/build-frontend-ios.sh
  bash -e scripts/ci/build_steps/package-ios.sh
)
```

Outputs:
- App: `build/ios/Build/Products/Release-iphoneos/FCAE.app`
- IPA: `package/FCAE_VPN-ios-arm64.ipa`

## Credits

- **Firefox IP Protection** — Implemented in Rust. See the [Firefox IP Protection source code](https://searchfox.org/firefox-main/source/toolkit/components/ipprotection/) (used [Arman VPN](https://github.com/armanlife/arman-vpn-client) and [FoxyVPN](https://github.com/Vauth/FoxyVPN) as references).
- **[Aether](https://github.com/CluvexStudio/aether)** — The core censorship circumvention engine by CluvexStudio. Provides MASQUE, WireGuard, WARP-in-WARP and WARP-in-MASQUE protocols.
- **[Dear ImGui](https://github.com/ocornut/imgui)** — Immediate-mode GUI library Used for the shared desktop and Android interface.
- **[hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel)** — C SOCKS5 tunnel engine, runs in-process.
- **[Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core)** — Psiphon tunnel core library.
- **[URnetwork](https://github.com/urnetwork)** — Decentralized VPN backend, integrated in-process using the [SDK](https://github.com/urnetwork/sdk) and [Connect](https://github.com/urnetwork/connect) libraries.
- **[Xray-core](https://github.com/XTLS/Xray-core)** — Proxy core, in-process.
- **[sing-box](https://github.com/SagerNet/sing-box)** — Proxy core, in-process. ([sing-tun](https://github.com/MetaCubeX/sing-tun) is also available as a separate TUN engine.)
- **[Mihomo](https://github.com/MetaCubeX/mihomo)** — Proxy core and TUN engine, in-process.
- **[qpack](https://github.com/quic-go/qpack)** — QPACK header compression behind the quic-go forks in that archive. Psiphon's fork predates qpack 0.6's API while sing-box's and Xray-core's require it, so `core/fcae-ffi/gomods/qpack` carries one version with both, instead of pinning one the other half cannot build against.
- **[Quiche](https://github.com/cloudflare/quiche)** — Cloudflare's HTTP/3 and QUIC implementation. Used as the QUIC transport backend for MASQUE protocol support.
- **[Wintun](https://www.wintun.net/)** — A TUN driver for Windows by WireGuard. Provides a high-performance network interface at Layer 3 for tunneling traffic.
- **[tun2socks](https://github.com/xjasonlyu/tun2socks)** — A Go library that transparently routes TUN device traffic through a SOCKS5 proxy. Powers the system-wide VPN TUN mode across all supported platforms (Linux, Windows, macOS, and Android).
- **[zeptun](https://github.com/Noisemux/zeptun)** — A Zig TUN engine, statically linked and running in-process. Provides an alternative to tun2socks on Linux, macOS, and Android.

## Community

Join the official Telegram channel for release announcements, connectivity notices, and configuration tips — plus answers from the maintainers and other users:

<p align="center">
  <a href="https://t.me/FCAE_VPN">
    <img src="https://img.shields.io/badge/Telegram-@FCAE__VPN-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram channel @FCAE_VPN">
  </a>
</p>

- **Release announcements** — new versions, changelogs, and platform-specific notes.
- **Connectivity notices** — early warnings when endpoints are blocked or a route needs updating.
- **Support and tips** — setup help, troubleshooting, and answers from the community.

Bug reports and feature requests belong in **[GitHub Issues](https://github.com/FCFlenkchy/FCAE_VPN/issues)** so they stay tracked and searchable — the channel is for everything else.

## Support development

If you'd like to support the developer, you can send GRAM (The Open Network) to:

`UQAz9mcfJ5qlba97SPbrCw-Yt8OhhT58yG9PzARyu1Muz0jV`

Use The Open Network only. Donations are optional.

## Sponsorship

Interested in sponsoring FCAE? Read the **[Sponsor Policy](SPONSOR_POLICY.md)** for eligibility, content requirements, privacy rules, and contact information.

## Contributing

Contributions are welcome! Whether it's bug reports, feature requests, documentation improvements, or code contributions — feel free to open an issue or pull request.

### How to Contribute

For questions and general discussion, see the [Community](#community) section.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Released under the [LICENSE](LICENSE)

The names FCAE and FCAE VPN are trademarks of this project. See [TRADEMARK](TRADEMARK).

---

<div align="center">

### Found this useful?

If this project helped you bypass censorship or just saved you some time, consider giving it a **star** — it helps others discover the tool and motivates continued development.

[![Star](https://img.shields.io/github/stars/FCFlenkchy/FCAE_VPN?style=social)](https://github.com/FCFlenkchy/FCAE_VPN)

**Other languages:** [فارسی](READMEFA.md) | [中文](READMECH.md)

</div>
