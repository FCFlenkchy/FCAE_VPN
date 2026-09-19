//! Builds the hev-socks5-tunnel C engine as a static library and links it.
//!
//! The engine is built with its own Makefile outside the cargo graph (similar
//! to how zeptun is built with Zig). The static archive is then linked into
//! libfcae_ffi.
//!
//! Build locations:
//! * desktop → `make -C core/hev-socks5-tunnel static` (lands in `core/hev-socks5-tunnel/bin/`)
//! * android → cross-compile with NDK (lands in `core/hev-socks5-tunnel/bin/`)
//!
//! `FCAE_HEV_LIBDIR=<dir>` overrides the search path.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hev_linked)");
    fcae_build::rerun_if_env_changed("FCAE_HEV_LIBDIR");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");

    let target = fcae_build::target::Target::from_cargo_env();

    if cfg!(feature = "stub") {
        fcae_build::note("fcae-bridge-hev-socks5-tunnel: `stub` feature enabled — engine NOT linked");
        return;
    }

    let submodule = fcae_build::repo_root().join("core/hev-socks5-tunnel");
    let header = submodule.join("include/hev-socks5-tunnel.h");
    if !header.is_file() {
        panic!(
            "hev-socks5-tunnel submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }
    fcae_build::rerun_if_changed(&header);

    // Track key source directories for rebuild triggers
    let src_dir = submodule.join("src");
    if src_dir.is_dir() {
        fcae_build::rerun_if_changed(&src_dir);
    }
    let third_part_dir = submodule.join("third-part");
    if third_part_dir.is_dir() {
        fcae_build::rerun_if_changed(&third_part_dir);
    }

    let lib_dir = locate_lib_dir(&submodule, target);
    let archive = lib_dir.join("libhev-socks5-tunnel.a");
    if !archive.is_file() {
        panic!(
            "libhev-socks5-tunnel.a not found in {}.\n\
             Build with: `make -C core/hev-socks5-tunnel static`\n\
             Or set FCAE_HEV_LIBDIR to a directory containing the archive,\n\
             or build with `--features fcae-bridge-hev-socks5-tunnel/stub` to skip.",
            lib_dir.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=hev-socks5-tunnel");

    // Link dependencies required by hev-socks5-tunnel
    if target.os == fcae_build::target::Os::Windows {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
    }
    println!("cargo:rustc-link-lib=pthread");

    println!("cargo:rustc-cfg=hev_linked");
    println!("cargo:rustc-env=FCAE_HEV_HEADER={}", header.display());
    fcae_build::note(format!(
        "hev-socks5-tunnel linked in-process from {} (no subprocess, no embedded binary)",
        archive.display()
    ));
}

fn locate_lib_dir(submodule: &Path, _target: fcae_build::target::Target) -> PathBuf {
    if let Ok(dir) = std::env::var("FCAE_HEV_LIBDIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    submodule.join("bin")
}
