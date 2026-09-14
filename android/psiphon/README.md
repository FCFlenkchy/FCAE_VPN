# Android Psiphon (official AAR)

Maven `ca.psiphon:psiphontunnel:2.0.41` from
https://github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library

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
entries. Without one of the sources below the controller stalls on
`CandidateServers: {"count":0}` forever (and logs the misleading
`untunneled DSL fetch failed ... no broker specs` — broker specs are
derived from server entries). Configured in this priority order:

1. Intent extras on `ACTION_START`: `psiphonEmbeddedListFile` (path to an
   encoded server-entry list), `psiphonRemoteUrl` + `psiphonRemoteKey`
   (remote server list).
2. `filesDir/psiphon_settings.json` — the push-without-rebuild path
   (`adb shell run-as com.fc.fcaevpn` on a debug build):
   `{"RemoteServerListUrl": "https://.../server_list",
   "RemoteServerListSignaturePublicKey": "base64 key",
   "EmbeddedServerEntryListFile": "/path/to/entries"}`
3. `filesDir/psiphon_server_list.txt` (raw encoded entries), then the
   bundled asset `assets/psiphon_server_list.txt`.

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
