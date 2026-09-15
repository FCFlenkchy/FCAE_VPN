# Psiphon Android library

`:app` consumes `:psiphon`, a pass-through artifact for
`android/psiphon/libs/ca.psiphon.aar`. The Android CI jobs build this file
from the pinned `core/psiphon` submodule, using that revision's Dockerfile,
vendored gomobile, Go and NDK. They verify all four ABI libraries have 16 KB
ELF LOAD alignment. The AAR is consumed locally by the Android app build;
it is not uploaded as a workflow artifact or a standalone release asset.

CI mounts both the submodule source and its resolved Git metadata directory
(read-only) into Docker. Explicit `GIT_DIR` and `GIT_WORK_TREE` let upstream's
`make.bash` read its build revision without following the submodule's `.git`
pointer outside the source mount. The checkout and container HEAD must match
FCAE's `HEAD:core/psiphon` gitlink; no separate upstream checkout or branch-tip
update is used.

For local APK builds, follow `core/psiphon/MobileLibrary/Android/README.md`
to build the pinned source and copy its `ca.psiphon.aar` to the path above.
No Maven prebuilt fallback is used.

Psiphon runs as a bound-only service in `:psiphon`, separate from the
application's tun2socks Go runtime. `ProxyNotification` owns the startup/proxy
notification and hands it to `FCAEVpnService` in TUN mode. Psiphon's service
never calls Android notification or foreground-service APIs. Owner teardown
releases the binding; native stop runs off the main thread.


## DNS, counters and LAN sharing

Psiphon's SOCKS proxy accepts TCP CONNECT, not UDP ASSOCIATE. In TUN mode,
FCAE intercepts UDP/53 and sends wire-format DNS over HTTPS to Cloudflare
(`https://cloudflare-dns.com/dns-query`, bootstrap IP `1.1.1.1:443`) **through
the Psiphon SOCKS exit**. TLS certificate verification stays enabled; there
is no direct-network or system-resolver fallback. This replaces the resolver
selected in the TUN DNS fields for these intercepted queries. Tor-only keeps
its separate DNS-over-TCP path. Chained sessions select the DNS policy from
the actual exit backend, not just the requested protocol.

This avoids depending on exit-server permission to forward TCP/53. A
`port forward failures` counter is not proof of DNS failure: destination
blocking or a broken exit can still prevent ordinary web traffic. Strict
Android Private DNS uses TLS/853, which is not intercepted by this UDP/53
path and may also be refused by an exit server. HTTP/SOCKS proxy-mode clients
should send hostnames to the proxy (SOCKS remote DNS), not resolve them locally.

The existing LAN switch sets Psiphon's `ListenInterface` to `any` (IPv4
`0.0.0.0`) or the loopback-only default on both Android and desktop. These
listeners have no authentication: enable sharing only on trusted networks,
and restrict inbound access with the host firewall where applicable. Wi-Fi
client isolation or a firewall may prevent other LAN devices connecting.

Both Android notification owners consume the same session-tagged Psiphon
byte-count broadcasts as the activity. The Psiphon process creates no
notification. Its actual bound ports are shown instead of inactive
Aether/Tor listeners or a configured auto-port value of zero.

Device checks (not run as part of this patch):
- Psiphon-only TUN: load uncached domains with Android Private DNS off/automatic;
  verify DNS succeeds even when the exit rejects TCP/53.
- Repeat with Psiphon as the chained exit; compare foreground/background
  notification totals against the UI after a download.
- Toggle LAN sharing between sessions; test HTTP and SOCKS remote-DNS clients
  from a second Wi-Fi device, and confirm LAN access is closed when disabled.
- Switch between Tor-only, Aether and Psiphon; check that the shown endpoints
  belong to the current backend and that old stats disappear on reconnect.

## In-proxy diagnostics

Auto permits tunnel-core's full protocol selection, including server-tactics
choices of `INPROXY-WEBRTC-*`. `InproxyEnableProxy=false` only prevents
volunteering this device as a proxy for other clients. The former
`InproxyEnabled` field was not recognized; `InproxyAllowClient` is a
server-side parameter, not a client-side opt-out. These were not effective
controls for disabling client WebRTC/STUN dialing. This patch does not
remove transports, disable tactics, or filter upstream diagnostics.

“in-proxy protocol preferred”, selection rate limits and skipped candidates
are connection-selection diagnostics, not by themselves a failed tunnel.
WebRTC offer states and STUN/mux warnings concern Psiphon's transport, not
proof of a browser WebRTC leak. Cancellation/exiting notices after an
explicit stop normally describe teardown; an unexpected stop still needs
its preceding service/network events investigated. Internal DNS metrics
do not verify Android applications' DNS or browsing path.

UI regression checks (require builds/devices; not run here):
- Desktop: fill the 200-line ring, continue logging (including repeated
  identical lines), click/double-click/copy a line, and verify following
  reaches the true last row. Wheel/drag upward pauses following; returning
  to the bottom or toggling Auto-scroll off/on resumes. Clear during logging.
- Android: tap logs, long-press/select/copy, release selection, and continue
  receiving both native and AAR logs. Following must use the padded viewport
  after layout; dragging upward pauses it and reaching the bottom resumes.
  Verify the inner log pane scrolls rather than the outer settings pane.
- WARP/WARP-in-WARP: live validation RTT is published once, not replaced
  seconds later with a different HTTP measurement. MASQUE/MASQUE-in-MASQUE
  remains unknown until its first successful HTTP probe, then retains that
  value; failed probes do not publish an RTT. A genuine reconnect is a new
  measurement. This does not claim reproduction of two simultaneous RTT
  labels; both UIs currently contain a single telemetry RTT field.
