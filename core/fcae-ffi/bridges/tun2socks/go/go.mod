// Bridge module for the in-process tun2socks c-archive.
//
// It is a separate module from core/tun2socks so the upstream submodule stays
// pristine (no local edits to rebase when it is updated). The `replace`
// directive points at the submodule checkout, so the exact pinned commit is
// what gets compiled — no network fetch of tun2socks itself.
module github.com/FCFlenkchy/FCAE_VPN/core/fcae-ffi/bridges/tun2socks

// Must be >= the `go` directive in core/tun2socks/go.mod (currently 1.26.3):
// Go refuses to build a dependency that requires a newer language version than
// the main module declares. Bump this whenever the submodule is updated.
go 1.26.3

require github.com/xjasonlyu/tun2socks/v2 v2.6.0

// Always build against the submodule at core/tun2socks.
replace github.com/xjasonlyu/tun2socks/v2 => ../../../../tun2socks
