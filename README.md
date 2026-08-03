<p align="center">
  <img src="mountain.png" alt="FCAE VPN" width="100%">
</p>

# FCAE VPN

A censorship circumvention client designed for heavily restricted networks. It automatically discovers reachable routes, establishes an encrypted tunnel, and exposes a local SOCKS5/HTTP proxy for your applications.

Built on top of **[Aether](https://github.com/CluvexStudio/aether)** with native GUI frontends for Windows, Linux, macOS, and Android.

## How It Works

FCAE VPN connects to **Cloudflare's WARP network** — the same infrastructure behind Cloudflare's 1.1.1.1 DNS service. Here's the flow:

1. **Account provisioning** — On first launch, the client creates a WARP device identity and obtains dedicated IPv4/IPv6 addresses plus WireGuard keypairs from Cloudflare's registration API.
2. **Endpoint scanning** — The client probes a list of Cloudflare edge IPs across multiple ports to find a reachable gateway. Each candidate is validated with a real handshake (and optionally a full HTTP request in ironclad mode) to confirm the route actually passes traffic.
3. **Tunnel establishment** — Once a working edge is found, an encrypted tunnel is opened:
   - **MASQUE** — Traffic is encapsulated inside HTTP/3 (QUIC) or HTTP/2 (TLS) sessions using the `CONNECT-IP` method, making it look like normal HTTPS traffic to DPI systems.
   - **WireGuard** — A standard WireGuard UDP tunnel is established directly to the edge node.
   - **WARP-in-WARP (gool)** — Two nested WireGuard tunnels for an additional encryption layer.
4. **Local proxy** — The tunnel exposes a local SOCKS5 proxy (port 1819) and HTTP proxy (port 1820). Applications configured to use these proxies route their traffic through the encrypted tunnel to the internet via Cloudflare's network.

All traffic between the client and Cloudflare is encrypted. From Cloudflare onward, traffic exits to the public internet normally.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Application                             │
│              (browser, app, or system traffic via TUN)              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ SOCKS5 :1819 / HTTP :1820
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       FCAE VPN Client                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐   │
│  │  Netstack  │  │  Scanner   │  │  Obfuscat. │  │  Health Mon. │   │
│  │ (TCP/IP)   │  │ (endpoint  │  │  (aether-  │  │  (reconnect  │   │
│  │            │  │  discovery)│  │   noize)   │  │   on fail)   │   │
│  └──────┬─────┘  └────────────┘  └────────────┘  └──────────────┘   │
│         │                                                           │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Encrypted Tunnel                          │   │
│  │   ┌───────────┐   ┌──────────────┐   ┌──────────────────┐    │   │
│  │   │  MASQUE   │   │  WireGuard   │   │  WARP-in-WARP    │    │   │
│  │   │ HTTP/3/2  │   │   (UDP)      │   │  (WG inside WG)  │    │   │
│  │   └─────┬─────┘   └──────┬───────┘   └────────┬─────────┘    │   │
│  └─────────┼────────────────┼────────────────────┼──────────────┘   │
└────────────┼────────────────┼────────────────────┼──────────────────┘
             │                │                    │
             ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Cloudflare WARP Edge                              │
│          (162.159.192.x — automatic discovery)                      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Public Internet                               │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol Comparison

| Protocol | Transport | DPI Resistance | Speed | Use Case |
|----------|-----------|---------------|-------|----------|
| **MASQUE (HTTP/3)** | QUIC over UDP | Best — looks like HTTPS | Fast | Default, most censorship-resistant |
| **MASQUE (HTTP/2)** | TLS over TCP | Best — looks like HTTPS | Fast | Fallback when QUIC is blocked |
| **WireGuard** | UDP | Moderate — encrypted but detectable | Fastest | When UDP is allowed |
| **WARP-in-WARP** | Nested UDP | High — double encryption | Moderate | Extra layer when WG alone is blocked |

## Features

- Automatic endpoint discovery with end-to-end data-plane validation
- MASQUE (HTTP/3 QUIC / HTTP/2), WireGuard, and WARP-in-WARP (gool) support
- Traffic obfuscation with configurable profiles
- Automatic reconnection with quick-reconnect
- Local SOCKS5 and HTTP proxies
- Native GUI on all platforms (ImGui + DirectX11 / OpenGL on desktop, Kotlin Material UI on Android)

## Inline Routing Rules

You can define custom routing rules directly in the UI (Routes tab) without needing an external file. Rules use a simple format:

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

**On Desktop:** Open the **Routes** tab and paste rules into the "Inline Routing Rules" text box.

**On Android:** Scroll to "Inline routing rules" and enter your rules. Tap **CONNECT** to apply.

Rules set via inline input take priority and are merged with any rules file specified in the "Routing Rules File" field.

## Platforms

| Platform | Backend | UI |
|----------|---------|----|
| Windows | DirectX 11 | ImGui |
| Linux | GLFW + OpenGL | ImGui |
| macOS | GLFW + OpenGL | ImGui |
| Android | Kotlin Material VpnService + JNI bridge | Kotlin Material UI |

## Building

### Requirements

- Rust (latest stable)
- C/C++ compiler (GCC/Clang/MSVC)
- CMake >= 3.22
- Vulkan SDK or DirectX SDK (Windows)
- For Android: NDK, Android SDK, Kotlin

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

## Credits

- **[Aether](https://github.com/CluvexStudio/aether)** — The core censorship circumvention engine by CluvexStudio. Provides MASQUE, WireGuard, and WARP-in-WARP protocols.
- **[Dear ImGui](https://github.com/ocornut/imgui)** — Immediate-mode GUI library Used for all native desktop rendering.
- **[Quiche](https://github.com/cloudflare/quiche)** — Cloudflare's HTTP/3 and QUIC implementation. Used as the QUIC transport backend for MASQUE protocol support.
- **[Wintun](https://www.wintun.net/)** — A TUN driver for Windows by WireGuard. Provides a high-performance network interface at Layer 3 for tunneling traffic.
- **[tun2socks](https://github.com/xjasonlyu/tun2socks)** — A Go library that transparently routes TUN device traffic through a SOCKS5 proxy. Powers the system-wide VPN TUN mode.

## Contributing

Contributions are welcome! Whether it's bug reports, feature requests, documentation improvements, or code contributions — feel free to open an issue or pull request.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

See the individual components for their respective licenses.

---

<div align="center">

### Found this useful?

If this project helped you bypass censorship or just saved you some time, consider giving it a **star** — it helps others discover the tool and motivates continued development.

[![Star](https://img.shields.io/github/stars/FCFlenkchy/FCAE_VPN?style=social)](https://github.com/FCFlenkchy/FCAE_VPN)

**Other languages:** [فارسی](READMEFA.md) | [中文](READMECH.md)

</div>
