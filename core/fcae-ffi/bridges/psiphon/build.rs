//! Builds the Psiphon Go bridge as a c-archive and links it statically.
//!
//! ## Why a hand-written shim now
//!
//! The first version compiled upstream's `ClientLibrary` package directly,
//! because it already exports a cgo C ABI. That cannot work on Android: its
//! `PsiphonProvider` has no `BindToDevice`, so Psiphon's own sockets get
//! captured by our TUN and the tunnel tries to reach the internet through
//! itself.
//!
//! `MobileLibrary/psi` does expose `BindToDevice`, but it is a gobind package
//! with no C surface, so `go/bridge.go` wraps it. One shim serves both
//! platforms — desktop simply passes `useDeviceBinder=false`.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(psiphon_linked)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");

    if !cfg!(feature = "enabled") {
        return;
    }

    let submodule = fcae_build::repo_root().join("core/psiphon");
    if !submodule.join("go.mod").is_file() {
        panic!(
            "the `enabled` feature is on but the Psiphon submodule is missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    // The shim imports MobileLibrary/psi, so fail early and clearly if the
    // submodule layout ever changes under us.
    let mobile_library = submodule.join("MobileLibrary/psi");
    if !mobile_library.join("psi.go").is_file() {
        panic!(
            "{} does not contain psi.go — the upstream layout changed",
            mobile_library.display()
        );
    }

    // The Go bridge is built once by fcae-bridge-tun2socks. It contains both
    // tun2socks and Psiphon exports, so never build a second Go runtime here.
    println!("cargo:rustc-cfg=psiphon_linked");
    fcae_build::note("Psiphon uses the combined fcae_go_bridge Go runtime");
    return;
}
