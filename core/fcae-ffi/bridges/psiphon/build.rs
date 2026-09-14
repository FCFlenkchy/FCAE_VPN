//! Psiphon Go bridge.
//!
//! ## Split from tun2socks
//!
//! Psiphon is its own Go module (`go/`). It must not be linked into
//! tun2socks' `libfcae_go_bridge`. Two Go runtimes in one Android process
//! SIGSEGV at `dlopen`; stuffing psi into the tun2socks c-shared was the
//! load crash. Two static Go c-archives in one desktop binary also fail
//! (duplicate `_cgo_topofstack` / `crosscall2`). Desktop therefore builds
//! this module as `libfcae_psiphon` with `force_shared`.
//!
//! ## Android
//!
//! Official path: the Psiphon AAR (`android/psiphon`). `ClientLibrary` has
//! no `BindToDevice` and cannot work on Android. This crate never compiles
//! `psi` into a `.so` on Android, even if `enabled` is on.
//!
//! ## Desktop
//!
//! When `enabled` is on (the `psiphon-live` feature), `go/` is built as
//! `libfcae_psiphon` (`c-shared` `.so` / `.dll` / `.dylib`) and staged next
//! to the cargo artifacts so CMake can package it beside the executable.

use std::path::PathBuf;

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

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    let submodule = fcae_build::repo_root().join("core/psiphon");
    if !submodule.join("go.mod").is_file() {
        panic!(
            "psiphon submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    fcae_build::go::track_sources(&go_dir);
    fcae_build::rerun_if_changed(submodule.join("go.mod"));

    let target = fcae_build::target::Target::from_cargo_env();
    let mut archive = fcae_build::go::CArchive::new(&go_dir, ".", "libfcae_psiphon");
    archive.target = target;
    // Second Go runtime in the process: must be dynamic.
    archive.force_shared = true;

    match archive.build() {
        Ok(built) => {
            if let Err(e) = built.stage_desktop_shared(target) {
                panic!("failed to stage libfcae_psiphon next to the artifacts: {e}");
            }
            built.emit_link_directives("libfcae_psiphon", target);
            println!("cargo:rustc-cfg=psiphon_linked");
            println!(
                "cargo:rustc-env=FCAE_PSIPHON_HEADER={}",
                built.header.display()
            );
            fcae_build::note(
                "desktop Psiphon linked as libfcae_psiphon (force_shared; not in tun2socks)",
            );
        }
        Err(e) => panic!(
            "failed to build the desktop Psiphon Go bridge: {e}\n\
             Install Go 1.26.3+ and a C toolchain for the target, or omit \
             `--features psiphon-live`."
        ),
    }
}
