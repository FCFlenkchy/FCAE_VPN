//! Psiphon Go bridge — **not compiled**.
//!
//! The `enabled` feature is off. This build script never invokes `go`.
//!
//! ## Split from tun2socks
//!
//! Psiphon is its own Go module (`go/`). It must not be linked into
//! tun2socks' `libfcae_go_bridge`. Two Go runtimes in one Android process
//! SIGSEGV at `dlopen`; stuffing psi into the tun2socks c-shared was the
//! load crash.
//!
//! ## Android
//!
//! Official path: the Psiphon AAR (`android/psiphon`, not in the Gradle
//! graph). `ClientLibrary` has no `BindToDevice` and cannot work on Android.
//! This crate never compiles `psi` into a `.so` on Android, even if
//! `enabled` is turned on later.
//!
//! ## Desktop (later)
//!
//! When `enabled` is on, build `go/` as `libfcae_psiphon` with
//! `CArchive::force_shared` so the second Go runtime is a dynamic library.
//! That path is not wired here yet so a default cargo/cmake pass never
//! compiles Psiphon.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(psiphon_linked)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");
    fcae_build::rerun_if_changed("go/bridge.go");
    fcae_build::rerun_if_changed("go/go.mod");

    if !cfg!(feature = "enabled") {
        return;
    }

    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "android" {
        // Do not compile. Do not set psiphon_linked — that would make Rust
        // expect psi_* symbols that no Go archive provides.
        fcae_build::note(
            "Android Psiphon is the official AAR (android/psiphon); \
             not compiling psi into a Go runtime",
        );
        return;
    }

    fcae_build::note(
        "Psiphon desktop Go module is not compiled (enabled is on, build skipped)",
    );
}
