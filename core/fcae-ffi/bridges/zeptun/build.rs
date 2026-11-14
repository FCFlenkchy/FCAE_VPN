//! Locates — or builds — the zeptun engine archive (libzeptun.a) and links it
//! statically.
//!
//! The archive is produced by the Zig build that lives beside this script, in
//! `zig/`, so the bridge owns the whole story: recipe, invocation and link. That
//! build is Windows-only by design (zeptun's own build links its TLS-backed SMP
//! allocator, which a Windows host cannot provide), and it is the same file the
//! CI step used to run from `core/`.
//!
//! Resolution order:
//!
//! 1. `FCAE_ZEPTUN_LIBDIR` — explicit directory holding the archive.
//! 2. The conventional output directory: `core/zeptun/zig-out/lib` on desktop,
//!    `core/zeptun/zig-out/android/prebuilt/<abi>` on Android.
//! 3. When neither has it and `zig` is on PATH, `zig build` runs here for
//!    Windows targets (`FCAE_ZEPTUN_NO_BUILD=1` disables that).
//!
//! Android and the other desktops are deliberately not built from the cargo
//! graph: they need the NDK sysroot or zeptun's own `make`, which its scripts
//! (`core/zeptun/scripts/build_android.sh`, `make -C core/zeptun`) already drive
//! correctly for their target.
//!
//! All the heavy lifting in the link path lives in `fcae-build`; this stays
//! readable.

use std::path::{Path, PathBuf};
use std::process::Command;

use fcae_build::target::{Arch, Os, Target};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(zeptun_linked)");
    fcae_build::rerun_if_env_changed("FCAE_ZEPTUN_LIBDIR");
    fcae_build::rerun_if_env_changed("FCAE_ZEPTUN_NO_BUILD");
    fcae_build::rerun_if_env_changed("FCAE_ZIG");

    let target = Target::from_cargo_env();

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
    if !resolve_zeptun_archive(&lib_dir).is_file() {
        build_archive(&submodule, target);
    }
    let archive = resolve_zeptun_archive(&lib_dir);
    if !archive.is_file() {
        panic!(
            "libzeptun.a / zeptun.lib not found in {}.\n\
             Windows: install Zig and re-run (this bridge builds it), or run\n\
             `zig build -Dtarget=x86_64-windows-gnu` in {}\n\
             Android: `sh core/zeptun/scripts/build_android.sh` (needs ANDROID_NDK_HOME)\n\
             Other desktops: `make -C core/zeptun`\n\
             Or set FCAE_ZEPTUN_LIBDIR to a directory containing libzeptun.a,\n\
             or build with `--features fcae-bridge-zeptun/stub` to skip.",
            lib_dir.display(),
            zig_build_dir().display(),
        );
    }
    fcae_build::rerun_if_changed(&archive);

    // Link from a directory holding only the static archive. The build output
    // also contains the shared library and its import library, and on
    // Windows-gnu the import library wins `-lzeptun` resolution — the final
    // binary then imports zeptun.dll instead of linking the engine statically.
    let search_dir = isolate_static_archive(&archive);

    println!("cargo:rustc-link-search=native={}", search_dir.display());
    println!("cargo:rustc-link-lib=static=fcae_zeptun_static");
    println!("cargo:rustc-cfg=zeptun_linked");
    println!("cargo:rustc-env=FCAE_ZEPTUN_HEADER={}", header.display());
    fcae_build::note(format!(
        "zeptun linked in-process from {} (no subprocess, no embedded binary)",
        archive.display()
    ));
}

/// The Zig recipe that produces the Windows archive, beside this script.
fn zig_build_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("zig")
}

/// Build the archive with the recipe beside this script when the toolchain is
/// available. Silent no-op for platforms whose build needs more than cargo can
/// supply (NDK sysroot, Apple SDK): those keep their own documented steps.
fn build_archive(submodule: &Path, target: Target) {
    // Only Windows has a recipe cargo can drive; everything else needs an NDK
    // sysroot or the Apple SDK and keeps its own documented step.
    let zig_target = match (target.os, target.arch) {
        (Os::Windows, Arch::X86_64) => "x86_64-windows-gnu",
        (Os::Windows, Arch::Aarch64) => "aarch64-windows-gnu",
        _ => return,
    };
    if std::env::var_os("FCAE_ZEPTUN_NO_BUILD").is_some() {
        fcae_build::note("fcae-bridge-zeptun: FCAE_ZEPTUN_NO_BUILD is set — not building the archive");
        return;
    }
    let Some(zig) = zig_binary() else {
        fcae_build::note(
            "fcae-bridge-zeptun: no zeptun archive and no `zig` on PATH; set FCAE_ZIG or build it manually",
        );
        return;
    };

    let zig_dir = zig_build_dir();
    fcae_build::rerun_if_changed(zig_dir.join("build.zig"));
    fcae_build::rerun_if_changed(zig_dir.join("build.zig.zon"));

    // The install prefix is zeptun's own output directory, so the archive lands
    // exactly where `locate_lib_dir` looks and CI and local builds agree.
    let prefix = submodule.join("zig-out");
    let mut command = Command::new(&zig);
    command
        .current_dir(&zig_dir)
        .args(["build", "-Doptimize=small"])
        .arg(format!("-Dtarget={zig_target}"))
        .arg("--prefix")
        .arg(&prefix);
    // CI keeps the Zig cache out of the workspace so a restored cache cannot
    // smuggle a stale archive into the link.
    if let Some(cache) = std::env::var_os("FCAE_ZIG_CACHE") {
        command.arg("--cache-dir").arg(cache);
    }
    fcae_build::note(format!(
        "fcae-bridge-zeptun: building the zeptun archive with {zig:?} for {zig_target}"
    ));
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot run {zig:?}: {error}"));
    if !output.status.success() {
        panic!(
            "`zig build` for the zeptun archive failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// `FCAE_ZIG` first (a CI-image toolchain is rarely on PATH), then PATH.
fn zig_binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("FCAE_ZIG") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }
    let name = if cfg!(windows) { "zig.exe" } else { "zig" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

/// Resolution order: explicit override, platform-conventional output dir.
fn locate_lib_dir(submodule: &Path, target: Target) -> PathBuf {
    if let Ok(dir) = std::env::var("FCAE_ZEPTUN_LIBDIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if target.os == Os::Android {
        submodule
            .join("zig-out/android/prebuilt")
            .join(android_abi_dir(target.arch))
    } else {
        submodule.join("zig-out/lib")
    }
}

/// Rust arch -> the subdirectory names in zeptun's `zig build android` output.
fn android_abi_dir(arch: Arch) -> &'static str {
    match arch {
        Arch::Aarch64 => "arm64-v8a",
        Arch::Arm => "armeabi-v7a",
        Arch::X86_64 => "x86_64",
        Arch::X86 => "x86",
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
