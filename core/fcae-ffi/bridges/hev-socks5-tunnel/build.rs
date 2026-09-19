//! Wires the hev-socks5-tunnel engine into the crate.
//!
//! Two backends, one per platform family:
//!
//! * **In-process** (Linux, macOS, Android): the engine is built with its own
//!   Makefile outside the cargo graph — `make -C core/hev-socks5-tunnel static`,
//!   cross-compiled with the NDK on Android — and the archive is linked into
//!   libfcae_ffi. `FCAE_HEV_LIBDIR=<dir>` overrides the search path.
//! * **Sidecar** (Windows): the engine has no native Windows port (its Windows
//!   backend is `__MSYS__`-only and needs the MSYS runtime to own the process),
//!   so the app ships upstream's `hev-socks5-tunnel.exe`, built by the Windows
//!   leg of `build_all.yml` (MSYS2 running under Wine) and installed beside it.
//!   `FCAE_HEV_SIDECAR_EXE=<path>` says that executable is part of the install,
//!   which is what makes the crate compile the sidecar backend and report the
//!   engine as available. Without it a Windows build must use `stub`.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hev_linked)");
    println!("cargo::rustc-check-cfg=cfg(wintun_staged)");
    println!("cargo::rustc-check-cfg=cfg(hev_sidecar)");
    fcae_build::rerun_if_env_changed("FCAE_HEV_LIBDIR");
    fcae_build::rerun_if_env_changed("FCAE_HEV_SIDECAR_EXE");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");

    // Checked before anything else: a stub build links no engine, so it must
    // not require the submodule, the archive, or the Wintun driver. Cargo hands
    // the features of the crate being built to this script as `CARGO_FEATURE_*`
    // environment variables — `cfg!` would be evaluated for the script's own
    // compilation, where every feature is off.
    if std::env::var_os("CARGO_FEATURE_STUB").is_some() {
        fcae_build::note("fcae-bridge-hev-socks5-tunnel: `stub` feature enabled — engine NOT linked");
        return;
    }

    let target = fcae_build::target::Target::from_cargo_env();

    // Windows: the engine cannot be linked at all, so the executable ships
    // beside the app and runs as a child process. Staging it is a packaging
    // step; all this needs to know is that it will be there.
    if target.os == fcae_build::target::Os::Windows && !msys_target() {
        let staged = std::env::var("FCAE_HEV_SIDECAR_EXE").unwrap_or_default();
        let staged = staged.trim();
        if !staged.is_empty() && Path::new(staged).is_file() {
            fcae_build::rerun_if_changed(staged);
            println!("cargo:rustc-cfg=hev_sidecar");
            fcae_build::note(format!(
                "hev-socks5-tunnel runs as a sidecar process on Windows ({staged})"
            ));
            return;
        }
        panic!(
            "the hev-socks5-tunnel engine has no native Windows port (its Windows backend is \
             MSYS-only and links the MSYS runtime), so Windows runs it as a sidecar process.\n\
             `make -C core/hev-socks5-tunnel` inside MSYS2 builds it (the Windows leg of \
             build_all.yml does that with MSYS2 running under Wine); point FCAE_HEV_SIDECAR_EXE \
             at the resulting hev-socks5-tunnel.exe, or build with \
             `--features fcae-bridge-hev-socks5-tunnel/stub`; the engine then reports itself \
             unavailable in the UI."
        );
    }

    // Windows still needs wintun.dll at runtime for the TUN device itself
    // (that is a driver, not a process), so stage it next to the library.
    // hev-socks5-tunnel dynamically LoadLibraryExW's the stock "wintun.dll"
    // (pool "Wintun") from the application directory or System32.
    if let Some(dll) = fcae_build::wintun::stage(target) {
        println!("cargo:rustc-cfg=wintun_staged");
        println!("cargo:rustc-env=FCAE_HEV_WINTUN_DLL={}", dll.display());
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

    // `make static` archives only the engine's own objects: lwip, yaml and
    // hev-task-system keep their own archives (upstream merges the four the same
    // way for its Apple xcframework), and nothing else links them. Look next to
    // the engine first -- the Android staging copies them per ABI -- then in the
    // submodule's own output directories.
    for name in ["yaml", "lwip", "hev-task-system"] {
        let file = format!("lib{name}.a");
        let staged = lib_dir.join(&file);
        let dependency = if staged.is_file() {
            staged
        } else {
            submodule.join("third-part").join(name).join("bin").join(&file)
        };
        if !dependency.is_file() {
            panic!(
                "hev-socks5-tunnel's {name} archive is missing ({} is not a file).\n\
                 Build with: `make -C core/hev-socks5-tunnel static`",
                dependency.display()
            );
        }
        fcae_build::rerun_if_changed(&dependency);
        if let Some(dir) = dependency.parent() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
        println!("cargo:rustc-link-lib=static={name}");
    }

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

/// `x86_64-pc-msys` is the only Windows target whose C ABI matches the
/// engine's Windows backend; cargo passes it as `TARGET` to build scripts.
fn msys_target() -> bool {
    std::env::var("TARGET").is_ok_and(|triple| triple.contains("msys"))
}

fn locate_lib_dir(submodule: &Path, target: fcae_build::target::Target) -> PathBuf {
    if let Ok(dir) = std::env::var("FCAE_HEV_LIBDIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if target.os == fcae_build::target::Os::Android {
        submodule.join("bin/android").join(android_abi_dir(target.arch))
    } else {
        submodule.join("bin")
    }
}

fn android_abi_dir(arch: fcae_build::target::Arch) -> &'static str {
    match arch {
        fcae_build::target::Arch::Aarch64 => "arm64-v8a",
        fcae_build::target::Arch::Arm => "armeabi-v7a",
        fcae_build::target::Arch::X86_64 => "x86_64",
        fcae_build::target::Arch::X86 => "x86",
        _ => panic!("unsupported Android arch for hev-socks5-tunnel: {arch:?}"),
    }
}
