//! Builds the tun2socks Go bridge as a c-archive and links it statically.
//!
//! All the heavy lifting lives in `fcae-build`; this stays readable.

use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_linked)");
    println!("cargo::rustc-check-cfg=cfg(wintun_staged)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");

    let target = fcae_build::target::Target::from_cargo_env();

    // Windows still needs wintun.dll at runtime for the TUN device itself
    // (that is a driver, not a process), so stage it next to the library.
    if let Some(dll) = fcae_build::wintun::stage(target) {
        println!("cargo:rustc-cfg=wintun_staged");
        println!("cargo:rustc-env=FCAE_WINTUN_DLL={}", dll.display());
    }

    if cfg!(feature = "stub") {
        fcae_build::note("fcae-bridge-tun2socks: `stub` feature enabled — Go bridge NOT built");
        return;
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    let submodule = fcae_build::repo_root().join("core/tun2socks");

    if !submodule.join("go.mod").is_file() {
        panic!(
            "tun2socks submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    fcae_build::go::track_sources(&go_dir);
    fcae_build::rerun_if_changed(submodule.join("go.mod"));

    let mut archive = fcae_build::go::CArchive::new(&go_dir, ".", "libtun2socks_bridge");
    archive.target = target;

    match archive.build() {
        Ok(built) => {
            // Android builds a c-shared .so (Go rejects c-archive there), so
            // it has to land in jniLibs/<abi>/ for the loader. No-op elsewhere.
            if let Err(e) = built.stage_android_so(&fcae_build::repo_root(), target) {
                panic!("failed to stage the tun2socks bridge for Android: {e}");
            }
            built.emit_link_directives("libtun2socks_bridge", target);
            println!("cargo:rustc-cfg=tun2socks_linked");
            println!(
                "cargo:rustc-env=FCAE_TUN2SOCKS_HEADER={}",
                built.header.display()
            );
            fcae_build::note("tun2socks linked in-process (no subprocess, no embedded binary)");
        }
        Err(e) => panic!(
            "failed to build the in-process tun2socks bridge: {e}\n\
             Install Go 1.26.3+ (matching core/tun2socks/go.mod) and a C \
             toolchain for the target, or build with \
             `--features fcae-bridge-tun2socks/stub` to skip TUN support."
        ),
    }
}
