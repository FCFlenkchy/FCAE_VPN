# Android Psiphon (official AAR)

**CI builds `libs/ca.psiphon.aar` from the pinned `core/psiphon` submodule
(workflow step "build psiphon AAR from submodule") and `:app` consumes it
directly via `implementation(files("../psiphon/libs/ca.psiphon.aar"))`.**
This directory is deliberately NOT a Gradle library module any more: AGP
refuses to build a library AAR that has a direct local .aar file dependency
(`:psiphon:bundleReleaseAar` → "Direct local .aar file dependencies are not
supported when building an AAR"), and the wrapped classes/resources/jni
would never have been merged anyway. Wrapping it is also unnecessary —
process isolation below is done with `android:process=":psiphon"` in the
app manifest, not with a Gradle module.

Reference: Maven `ca.psiphon:psiphontunnel:2.0.41` from
https://github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library
(the raw.maven repo in settings.gradle.kts remains as a documentation
pointer; the build never resolves it).

The AAR ships `libgojni.so` (a Go runtime). tun2socks ships
`libfcae_go_bridge.so` (another Go runtime). Loading both in one process
SIGSEGVs at `dlopen`.

`PsiphonTunnelService` therefore runs in process `:psiphon`, binds that
process to the underlying network, and broadcasts the local SOCKS port.
The UI process then points tun2socks at `127.0.0.1:<port>` (TUN) or the
user points clients at it (proxy).

Do not compile `MobileLibrary/psi` into `libfcae_go_bridge.so`.
`ClientLibrary` has no `BindToDevice` and cannot work on Android.

## Server-entry sources (required)

The sponsor/propagation IDs in `getPsiphonConfig()` ship **no** server
entries, so at least one source must exist. In priority order:

1. The in-app Psiphon fields (sent to the service as `psiphonRemoteUrl` +
   `psiphonRemoteKey` and `psiphonEmbeddedListFile` extras on
   `ACTION_START`, and persisted across service restarts).
2. The optional bundled asset `assets/psiphon_servers.txt` (see below;
   absent by default).
3. The built-in legacy public remote server list — automatic fallback, so
   an unprovisioned build connects out of the box.

### Optional: bundling entries as psiphon_servers.txt

No asset ships with the repo — add `assets/psiphon_servers.txt` yourself if
you want entries bundled into the APK. Put entries you are **entitled to
distribute** there — from servers you run yourself (the psiphon-tunnel-core
submodule includes the server code) or from provisioning Psiphon-Labs issued
to you. Do **not** commit or ship entries extracted from other clients:
redistributing the Psiphon network's server addresses without provisioning
is exactly what gets repositories taken down.

The embedded list is passed to `startTunneling()`; the remote list goes
into the config JSON as `RemoteServerListUrl` +
`RemoteServerListSignaturePublicKey`.

## Upstream proxy ("Psiphon through the tunnel")

The `upstreamProxy` extra (e.g. `socks5://127.0.0.1:1819` — Aether's local
SOCKS, started first) is injected into the config as `UpstreamProxyURL`, so
**all** of Psiphon's own dials ride Aether. It used to be logged and then
dropped, which silently degraded the chain to plain Psiphon. Accepted
schemes are `socks5://`, `socks4a://` and `http://`; a bare `socks://` is
normalised to `socks5://`.
