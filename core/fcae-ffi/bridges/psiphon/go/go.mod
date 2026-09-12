// Bridge module for the in-process Psiphon c-archive.
//
// Separate from core/psiphon so the upstream submodule stays pristine (no
// local edits to rebase when it is bumped). The `replace` directive points at
// the submodule checkout, so the exact pinned commit is what gets compiled and
// nothing is fetched over the network.
//
// NEVER delete the replace directive: without it Go resolves psiphon-tunnel-core
// from the proxy and the build silently stops matching the submodule.
module github.com/FCFlenkchy/FCAE_VPN/core/fcae-ffi/bridges/psiphon

// Must be >= the `go` directive in core/psiphon/go.mod (currently 1.26.0):
// Go refuses to build a dependency that requires a newer language version
// than the main module declares. Bump this whenever the submodule is updated.
go 1.26.0

// The version is irrelevant in practice -- the replace directive below pins
// the build to the submodule checkout -- but it must parse.
require github.com/Psiphon-Labs/psiphon-tunnel-core v2.0.28+incompatible

// Always build against the submodule at core/psiphon.
replace github.com/Psiphon-Labs/psiphon-tunnel-core => ../../../../psiphon
