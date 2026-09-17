//! Locates the prebuilt zeptun engine (libzeptun.a) and links it statically.
//!
//! Unlike the Go bridges, this deliberately does NOT invoke `zig build` from
//! the cargo graph: Zig's per-target invocations (cross SDKs, NDK toolchains,
//! `-Dtarget` triples) are zeptun's own concern and it already ships the
//! entry points — `make` / `zig build android` / `scripts/build_android.sh`.
//! This build script just consumes the artifacts:
//!
//! | target  | produced by                            | consumed from                                   |
//! |---------|----------------------------------------|-------------------------------------------------|
//! | desktop | `make -C core/zeptun`                  | `core/zeptun/zig-out/lib/libzeptun.a`           |
//! | android | `sh core/zeptun/scripts/build_android.sh` | `core/zeptun/zig-out/android/prebuilt/<abi>/libzeptun.a` |
//!
//! `FCAE_ZEPTUN_LIBDIR=/path/to/dir` overrides both. On Android the static
//! archive links straight into libfcae_ffi — no jniLibs staging, unlike the
//! Go bridge, which is forced into c-shared there.
//!
//! All the heavy lifting lives in `fcae-build`; this stays readable.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(zeptun_linked)");
    println!("cargo::rustc-check-cfg=cfg(wintun_staged)");
    fcae_build::rerun_if_env_changed("FCAE_ZEPTUN_LIBDIR");

    let target = fcae_build::target::Target::from_cargo_env();

    // Windows still needs wintun.dll at runtime for the TUN device itself
    // (that is a driver, not a process), so stage it next to the library.
    // zeptun dynamically LoadLibraryExW's the stock "wintun.dll" (pool
    // "Wintun") from the application directory or System32.
    if let Some(dll) = fcae_build::wintun::stage(target) {
        println!("cargo:rustc-cfg=wintun_staged");
        println!("cargo:rustc-env=FCAE_WINTUN_DLL={}", dll.display());
    }

    if cfg!(feature = "stub") {
        fcae_build::note("fcae-bridge-zeptun: `stub` feature enabled — zeptun engine NOT linked");
        return;
    }

    let submodule = fcae_build::repo_root().join("core/zeptun");
    let header = submodule.join("include/zeptun.h");
    if !header.is_file() {
        panic!(
            "zeptun submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }
    fcae_build::rerun_if_changed(&header);

    let lib_dir = locate_lib_dir(&submodule, target);
    let archive = lib_dir.join("libzeptun.a");
    if !archive.is_file() {
        panic!(
            "libzeptun.a not found in {}.\n\
             Desktop: `make -C core/zeptun`\n\
             Android: `sh core/zeptun/scripts/build_android.sh` (needs ANDROID_NDK_HOME)\n\
             Or set FCAE_ZEPTUN_LIBDIR to a directory containing libzeptun.a,\n\
             or build with `--features fcae-bridge-zeptun/stub` to skip.",
            lib_dir.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=zeptun");
    println!("cargo:rustc-cfg=zeptun_linked");
    println!("cargo:rustc-env=FCAE_ZEPTUN_HEADER={}", header.display());
    fcae_build::note(format!(
        "zeptun linked in-process from {} (no subprocess, no embedded binary)",
        archive.display()
    ));
}

/// Resolution order: explicit override, platform-conventional output dir.
fn locate_lib_dir(submodule: &Path, target: fcae_build::target::Target) -> PathBuf {
    if let Ok(dir) = std::env::var("FCAE_ZEPTUN_LIBDIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if target.os == fcae_build::target::Os::Android {
        submodule
            .join("zig-out/android/prebuilt")
            .join(android_abi_dir(target.arch))
    } else {
        submodule.join("zig-out/lib")
    }
}

/// Rust arch -> the subdirectory names in zeptun's `zig build android` output.
fn android_abi_dir(arch: fcae_build::target::Arch) -> &'static str {
    match arch {
        fcae_build::target::Arch::Aarch64 => "arm64-v8a",
        fcae_build::target::Arch::Arm => "armeabi-v7a",
        fcae_build::target::Arch::X86_64 => "x86_64",
        fcae_build::target::Arch::X86 => "x86",
        _ => panic!("unsupported Android arch for zeptun: {arch:?}"),
    }
}
