// Bridge module for the in-process tun2socks c-archive.
//
// It is a separate module from core/tun2socks so the upstream submodule stays
// pristine (no local edits to rebase when it is updated). The `replace`
// directive points at the submodule checkout, so the exact pinned commit is
// what gets compiled — no network fetch of tun2socks itself.
module github.com/FCFlenkchy/FCAE_VPN/core/fcae-ffi/bridges/tun2socks

go 1.22

require github.com/xjasonlyu/tun2socks/v2 v2.6.0

// Always build against the submodule at core/tun2socks.
replace github.com/xjasonlyu/tun2socks/v2 => ../../../../tun2socks
