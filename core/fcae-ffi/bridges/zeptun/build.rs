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

    // Features reach build scripts as CARGO_FEATURE_* env, never as cfg().
    if std::env::var_os("CARGO_FEATURE_STUB").is_some() {
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
    let archive = resolve_zeptun_archive(&lib_dir);
    if !archive.is_file() {
        panic!(
            "libzeptun.a / zeptun.lib not found in {}.\n\
             Desktop: `make -C core/zeptun`\n\
             Android: `sh core/zeptun/scripts/build_android.sh` (needs ANDROID_NDK_HOME)\n\
             Or set FCAE_ZEPTUN_LIBDIR to a directory containing libzeptun.a,\n\
             or build with `--features fcae-bridge-zeptun/stub` to skip.",
            lib_dir.display()
        );
    }

    fcae_build::rerun_if_changed(&archive);

    // Link from a directory holding only the static archive. The build output
    // also contains the shared library and its import library, and on
    // Windows-gnu the import library wins `-lzeptun` resolution — the final
    // binary then imports zeptun.dll instead of linking the engine statically.
    let search_dir = isolate_static_archive(&archive);

    println!("cargo:rustc-link-search=native={}", search_dir.display());
    // Force the Windows GNU linker to consume the staged archive itself.
    // Without the mode switch, a DLL import archive can still win resolution
    // and leave zeptun.dll in the final executable's PE imports.
    if target.os == fcae_build::target::Os::Windows {
        println!("cargo:rustc-link-arg=-Wl,-Bstatic");
    }
    // On Windows GNU, name the exact staged archive. `-lfoo` still permits
    // the linker to consider import-library variants; `-l:filename` cannot.
    if target.os == fcae_build::target::Os::Windows {
        println!("cargo:rustc-link-arg=-Wl,-l:libfcae_zeptun_static.a");
        println!("cargo:rustc-link-arg=-Wl,-Bdynamic");
    } else {
        println!("cargo:rustc-link-lib=static=fcae_zeptun_static");
    }
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

/// Zig names the static archive `libzeptun.a` on POSIX and MinGW targets and
/// `zeptun_static.lib` on MSVC, where `zeptun.lib` is the import library.
/// Accept `zeptun.lib` last for static-only MSVC build trees.
fn resolve_zeptun_archive(lib_dir: &Path) -> PathBuf {
    let posix = lib_dir.join("libzeptun.a");
    if posix.is_file() {
        return posix;
    }
    let msvc = lib_dir.join("zeptun_static.lib");
    if msvc.is_file() {
        return msvc;
    }
    let windows = lib_dir.join("zeptun.lib");
    if windows.is_file() {
        return windows;
    }
    posix
}

/// Stage the static archive into a dedicated directory and link from there, so
/// a sibling shared/import library can never shadow `-lzeptun`.
fn isolate_static_archive(archive: &Path) -> PathBuf {
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo always sets OUT_DIR"))
        .join("zeptun_static");
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    // Do not stage the archive as libzeptun.a: that name can collide with a
    // DLL import archive in the final linker command.
    let staged = dir.join("libfcae_zeptun_static.a");
    std::fs::copy(archive, &staged)
        .unwrap_or_else(|e| panic!("cannot stage {}: {e}", archive.display()));
    dir
}
