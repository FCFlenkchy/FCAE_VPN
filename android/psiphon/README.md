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
