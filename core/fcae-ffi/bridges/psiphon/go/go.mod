// Dependency template for the Psiphon shim in the generated combined module.
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
