// Desktop Psiphon Go module — a separate runtime from tun2socks.
//
// Android does not build this. The official path is the Psiphon AAR
// (android/psiphon), not a c-shared stuffed into libfcae_go_bridge.so.
// This module is not compiled unless fcae-bridge-psiphon/enabled is on
// (desktop psiphon-live builds turn it on; Android stays on the AAR).
module github.com/FCFlenkchy/FCAE_VPN/core/fcae-ffi/bridges/psiphon

go 1.26.0

toolchain go1.26.8

require github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.0

// Always build against the submodule at core/psiphon.
replace github.com/Psiphon-Labs/psiphon-tunnel-core => ../../../../psiphon

// The tunnel core's own go.mod carries two replace directives, and Go honours
// replaces ONLY from the main module. Restate both here; keep in step with
// core/psiphon/go.mod.
replace github.com/pion/dtls/v2 => ../../../../psiphon/replace/dtls

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba
