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

require (
	github.com/xjasonlyu/tun2socks/v2 v2.6.0
	// Needed to install a non-fatal logger: engine.Start/Stop report errors
	// via log.Fatalf, and zap's default fatal hook calls os.Exit(1), which a
	// linked library must never do. zap is already an indirect dependency of
	// tun2socks, so this pulls in nothing new.
	go.uber.org/zap v1.28.0
	// TEMP: Psiphon library not loaded. Keep the line, do not delete.
	// github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.0
	github.com/vishvananda/netlink v1.2.1-beta.2
)

// Always build against the submodule at core/tun2socks.
replace github.com/xjasonlyu/tun2socks/v2 => ../../../../tun2socks

// TEMP: Psiphon library not loaded. Keep these, do not delete.
// replace github.com/Psiphon-Labs/psiphon-tunnel-core => ../../../../psiphon
//
// The tunnel core's own go.mod carries two replace directives, and Go honours
// replaces ONLY from the main module. Here the tunnel core is a dependency, so
// both are dropped and the build silently resolves different code than the one
// upstream builds and tests:
//
//   - pion/dtls/v2 must come from the patched tree vendored at replace/dtls;
//     the unpatched upstream release lacks the changes the DTLS-based
//     transports rely on.
//   - gitlab.com/yawning/obfs4.git is redirected to a maintained fork.
//
// Restate both here. They must be kept in step with core/psiphon/go.mod.
// replace github.com/pion/dtls/v2 => ../../../../psiphon/replace/dtls
//
// replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba

replace github.com/vishvananda/netlink => github.com/vishvananda/netlink v1.2.1-beta.2
