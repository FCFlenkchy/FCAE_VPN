# qpack

A Go module override. `core/fcae-ffi/gomods/` is where a dependency the archive
links by `replace` lives instead of by version; this is the only one.

Upstream `github.com/quic-go/qpack` v0.6.0, unmodified except for one file:
`legacy_api.go` keeps the two entry points 0.6 replaced — `NewDecoder(emitFunc)`
and `Decoder.DecodeFull` — next to the current ones.

The archive links three quic-go forks at once, as distinct module paths:

| fork | used by | qpack API it calls |
| --- | --- | --- |
| `github.com/Psiphon-Labs/quic-go` | Psiphon (QUIC/Conjure) | pre-0.6 |
| `github.com/sagernet/quic-go` | sing-box | 0.6 |
| `github.com/apernet/quic-go` | Xray-core (Hysteria, SplitHTTP) | 0.6 |

The forks coexist because their import paths differ, but all three import
`github.com/quic-go/qpack`, and a module graph resolves one path to exactly one
version. No published version serves both callers: 0.5.1 and below have only the
old API, 0.6.0 only the new one. MVS picks 0.6.0, which Psiphon's fork does not
compile against. This copy is 0.6.0 with both generations, so the `replace` in
`libfcae_go_bridge`'s `build.rs` keeps the graph lawful instead of pinning a
version half the archive cannot build against. That `replace` is injected only
when Psiphon is built next to an Xray or sing-box core.

Upstream: `github.com/quic-go/qpack@v0.6.0`, MIT (see `LICENSE.md`).
Tests are omitted; they are upstream's and depend on `testify`.
