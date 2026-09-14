# Psiphon Go shim (desktop)

C-ABI wrapper around `MobileLibrary/psi`. Built as its **own** Go module so
it does not share a runtime with tun2socks.

| Platform | How Psiphon runs |
| --- | --- |
| Android | Official `.aar` (`android/psiphon`). **Not this directory.** |
| Desktop | This module, `-buildmode=c-shared` (`force_shared`) as `libfcae_psiphon`, when `psiphon-live` is on. |
| Desktop (CLI) | `cmd/fcae-psiphon-console` — the same psi code path driven by a plain binary, no GUI. |

Do not compile psi into `libfcae_go_bridge.so`. Two Go runtimes in one
Android process crash at `dlopen`. Two static Go archives in one desktop
binary fail the link. `ClientLibrary` has no `BindToDevice` and cannot
work on Android.

## Server entries (read this first)

tunnel-core learns its **first** server entries from exactly one of:

1. the embedded server entry list (the `embedded` parameter of
   `psi_start` — the body of an encoded `server_list` payload),
2. `RemoteServerListUrl` + `RemoteServerListSignaturePublicKey` in the
   config JSON (a Psiphon-Network-provided remote server list), or
3. `ObfuscatedServerListRootURL(s)` (obfuscated server lists).

The sponsor/propagation IDs ship **no** entries by themselves. With none of
the three, the controller stalls forever on:

```
Info: awaiting embedded server entry list import
Warning: tactics request aborted: no capable servers
Error: untunneled DSL fetch failed: ... no broker specs
CandidateServers: {"count":0, ...}
```

`no broker specs` is a downstream symptom, not the cause: the untunneled
DSL fetcher rides in-proxy broker clients, and broker specs are derived
from server entries — of which there are none. Both the Rust bridge
(`validate`) and this shim now print an explicit startup warning when no
source is configured.

## Upstream proxy (chaining behind Aether)

`UpstreamProxyURL` in the config JSON routes **all** of Psiphon's own dials
through a proxy. Point it at Aether's local SOCKS to chain:

```
{"UpstreamProxyURL": "socks5://127.0.0.1:1819"}
```

tunnel-core's `upstreamproxy` package accepts the `socks5://`,
`socks4a://` and `http://` schemes (the bare `socks://` from older cores is
gone — the Android service normalises it to `socks5://`).

## Console binary

```sh
cd core/fcae-ffi/bridges/psiphon/go
go build -o fcae-psiphon-console ./cmd/fcae-psiphon-console

./fcae-psiphon-console -config psiphon_config.json \
    -embedded server_entries.txt \
    -upstream socks5://127.0.0.1:1819 \
    -socks 1080 -wait 90s
```

Flags inject `DataRootDirectory`, `EgressRegion`, `LocalSocksProxyPort`,
`LocalHttpProxyPort` and `UpstreamProxyURL` into the config, so a minimal
sponsor/propagation JSON is enough. Exit codes: 0 connected / clean
Ctrl-C, 1 usage, 2 start failure, 3 no tunnel within `-wait`.
