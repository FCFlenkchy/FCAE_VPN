//! Link the HEV archives built outside Cargo on all supported platforms.
//! FCAE_HEV_LIBDIR may point at a directory containing all four archives.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hev_linked)");
    fcae_build::rerun_if_env_changed("FCAE_HEV_LIBDIR");
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

    let submodule = fcae_build::repo_root().join("core/hev-socks5-tunnel");
    let header = submodule.join("src").join("hev-main.h");
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

    fcae_build::rerun_if_changed(&archive);
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

    if target.os == fcae_build::target::Os::Windows {
        for lib in ["ws2_32", "iphlpapi", "advapi32"] {
            println!("cargo:rustc-link-lib={lib}");
        }
    } else {
        println!("cargo:rustc-link-lib=pthread");
    }

    println!("cargo:rustc-cfg=hev_linked");
    println!("cargo:rustc-env=FCAE_HEV_HEADER={}", header.display());
    fcae_build::note(format!(
        "hev-socks5-tunnel linked in-process from {} (no subprocess, no embedded binary)",
        archive.display()
    ));
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
    } else if target.os == fcae_build::target::Os::Windows {
        submodule.join("bin/fcae-windows")
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
