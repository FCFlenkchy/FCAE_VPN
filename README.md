# FCAE VPN

<p align="center">
  <img src="mountain.png" alt="FCAE VPN" width="100%">
</p>

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
- **[tun2socks](https://github.com/xjasonlyu/tun2socks)** — A Go library that transparently routes TUN device traffic through a SOCKS5 proxy. Powers the system-wide VPN TUN mode across all supported platforms (Linux, Windows, macOS, and Android).

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


### Independent HTTP listeners and reconnect lifecycle

Android and desktop now have **Aether HTTP proxy** and **Tor HTTP proxy**
controls, with independently saved ports. Aether keeps port 1820; Tor HTTP is
opt-in and defaults to 1822. Tor SOCKS remains 1821. Core validation rejects
colliding active Tor HTTP, SOCKS, Aether and Psiphon ports. Changes apply on
the next connection. The new ABI field uses former `FcaeConfig._reserved[3]`;
the existing Psiphon chain flag in slot 0 and total struct size are preserved.
Rebuild the native bridge and UI together (including the Android JNI signature).

In Tor Chain mode, **Aether HTTP is the plain tunnel exit and bypasses Tor**;
Tor HTTP uses Arti through that tunnel. In Reverse mode, Aether HTTP exits
through the tunnel carried over Tor; Tor HTTP exits directly through Arti.
Tor-only starts no Aether HTTP listener. Disabling Tor clears its HTTP setting
from the engine environment. LAN sharing binds these listeners to IPv4 wildcard;
they have no authentication, so enable LAN only on trusted networks.

Source tracing found these reconnect hazards (not a reproduced device crash):
- The pinned tun2socks FD device closes its fd, while Rust also retained and
  closed that same numeric dup. Rapid reuse could close an unrelated/new fd.
  The bridge now has an explicit fd handoff, including partial-start errors.
  Go alone closes accepted fds; Rust only closes pre-handoff fds. The supplied-fd
  path uses the pinned device/stack APIs directly so ownership is observable.
  Desktop engine startup now checks the pinned API's returned error as well.
- Tor's normal stop avoided abort, but cancelled startup and next-start reaping
  still aborted it. Retained tasks now drain before runtime destruction and
  before the reconnect barrier clears. The engine no longer resets away a
  just-arrived Stop. Tor serving tasks are retained and shut down cooperatively.
- Android start/cleanup commands now share an executor. Late completion/state
  callbacks are generation-checked, and activity absence no longer triggers
  process-wide free/kill during service teardown. The process panic hook is
  installed once, rather than wrapping itself on every connection.

Stop remains cancellation-first and cleanup stays off the UI thread, but the
fd handoff is synchronized with native stack startup for safety. This is **not
an exact 5 ms guarantee**. A reconnect may report the existing two-second
cleanup timeout instead of starting over a still-draining session.

Validation checklist (builds/device tests not run by the patch author):
- Rapid Stop/Start during scan, Tor bootstrap, just-connected, and active traffic;
  repeat using notification actions, TUN/proxy mode, background/foreground,
  and activity recreation. Confirm no crash, fd growth, stale service teardown,
  or permanently retained ports. Exercise WARP-in-WARP and MASQUE-in-MASQUE.
- Enable both HTTP listeners in Tor Chain and Reverse; verify each exit using
  a proxy-aware client, disable each independently, reconnect, and test saved
  settings plus deliberate port collisions. Repeat on Android and desktop.
- Retest UDP DNS via Psiphon, Tor TCP DNS, LAN opt-in, notifications, and the
  upstream log-follow/RTT fixes. New Rust config/descriptor tests are included
  but have not been executed.
- If a crash persists, capture Android `adb logcat -b all -d` immediately,
  including `FATAL EXCEPTION`, libc/fdsan aborts, Rust panic, or native tombstone;
  note the protocol, mode and whether Stop came from the app or notification.


### Final-exit routing and UI follow-up

TUN now waits for the requested final exit. A failed Psiphon chain is an error,
not permission to fall back to the Aether/Tor carrier. The supervisor monitors
both hops and tears down TUN when either hop terminates. Existing explicit
DIRECT routing rules and platform VPN limitations are unchanged; this is not
a new system-wide kill switch.

Android's foreground notification owner services an ID-tagged native AAR attach
request, including the supervisor-selected upstream SOCKS endpoint. This fixes
both Aether → Psiphon and Tor-only → Psiphon without restarting the carrier or
raising a carrier-only TUN first. Startup continues with the activity backgrounded.
Late READY/FAILED notices from old requests are rejected. Native and Android
components must be rebuilt together because the JNI start signature changed.

Connected status identifies the actual final endpoint: Aether TUN, Tor TUN, or
Psiphon TUN. Tor Chain exits through Tor; Reverse exits through the tunnel carried
by Tor. Backend-prefixed local/LAN rows distinguish carrier listeners from final
exit listeners. In proxy-only mode clients still need to select the **final
exit's** SOCKS/HTTP port; using the carrier's port does not magically chain it.

Tor HTTP uses the same input styling as the other ports on Android and the same
integer-entry widget as Tor SOCKS on desktop. Both log panes have a persistent
vertical scrollbar and a fixed Latest button to resume following after reading
older lines. The button is fixed within the log pane, not inside the log text.
Psiphon region notices are normalized/deduplicated; unchanged lists do not replace
the spinner adapter. Real changes are deferred while it loses focus to a popup,
and a saved region is retained even when temporarily absent from a notice.

Psiphon already supports `ListenInterface=any`. Android now applies network-binding
policy **after** reading LAN settings. LAN mode avoids forcing all reply sockets
onto a cellular network, and discovers Wi-Fi/hotspot IPv4 separately. The app UID
(including :psiphon) remains excluded from its own VPN. LAN is unauthenticated and
opt-in; change the option before connecting. AP/client isolation, Android hotspot
restrictions, and host firewalls may still prevent access. A LAN address cannot
be advertised if the OS does not expose one.

Regression checks still requiring builds/devices:
- Test Aether → Tor, Tor → Aether (supported MASQUE Reverse), Aether → Psiphon,
  and Tor-only → Psiphon in TUN and proxy modes. Verify the public IP using the
  final exit; kill that exit and confirm no carrier-only Connected/TUN fallback.
- Background Android during chained startup, cancel during AAR attach, and rapidly
  reconnect; old bindings/READY messages must not attach to the replacement.
- Compare Psiphon loopback and LAN HTTP/SOCKS access from another device, with
  Wi-Fi and mobile data both enabled; then reconnect with LAN disabled.
- Scroll the open region dropdown during repeated notices; select a non-Auto
  region and reopen it. Copy/select old logs, use Latest, and fill the log ring.

Added Rust regression tests cover rejected/stale AAR attachments, final-exit
labels, and refusing TUN after chained-exit failure. They were not run locally.


### tun2socks TCP buffers and MTU

Android and desktop TUN settings now expose:

| Setting | Default | Accepted values |
| --- | --- | --- |
| TCP send buffer (bytes) | 128000 | 4096–4194304 |
| TCP receive buffer (bytes) | 128000 | 4096–4194304 |
| TCP auto-tuning | On | On / Off |
| TUN MTU (bytes) | 1500 | 1280–9000 |

Enter plain integer byte counts only. Unit suffixes and decimal fractions are
not supported: use `128000`, not `128K` or `128KB`. The buffer range follows the
pinned gVisor TCP limits. Receive auto-tuning may grow the receive buffer beyond
its configured default. MTU has a 1280-byte floor because the TUN supports IPv6.
This is the local TUN MTU, not the backend's encrypted tunnel MTU.

Settings persist on both platforms, including Android notification reconnects,
and apply on the next TUN connection. Android uses the same session MTU for
`VpnService.Builder.setMtu()` and tun2socks. Both the desktop engine Key path and
Android supplied-FD stack receive the TCP options. These controls do not tune
standalone proxy servers or mutate an already-running stack.

Two unused native config slots store buffer sizes and auto-tuning, preserving
config size, Psiphon flags and the Tor HTTP port. Zeroed legacy slots mean
128000-byte buffers with auto-tuning on. Rebuild native/UI/JNI/Go together since
internal start signatures changed. The bridge also accepts its already
registered Psiphon DNS proxy scheme during pre-validation.

Parser/config/ABI regression tests are included. No local builds
or unit/device tests were run. After rebuilding, check edited values, invalid
input, auto-tuning off/on persistence, Android notification reconnect, and
matching Android interface/tun2socks MTU on direct and chained TUN connections.
