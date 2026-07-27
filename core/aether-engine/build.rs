// Build script for aether-engine
//
// Embeds tun2socks (https://github.com/xjasonlyu/tun2socks) binary
// directly into the compiled executable at build time.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_available)");
    println!("cargo:rustc-cfg=tun2socks_available");

    #[cfg(target_os = "android")]
    {
        println!("cargo:warning=Android build: tun2socks not used (uses tun.rs)");
    }

    #[cfg(not(target_os = "android"))]
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = PathBuf::from(&manifest_dir);
        let workspace_root = manifest_path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_path);

        #[cfg(target_os = "windows")]
        let bin_name = "tun2socks.exe";
        #[cfg(not(target_os = "windows"))]
        let bin_name = "tun2socks";

        // Check TUN2SOCKS_BIN env var first
        let env_path = env::var("TUN2SOCKS_BIN").ok();
        let bin_paths: &[PathBuf] = if let Some(ref p) = env_path {
            // Use a slice pointing to static storage via leak (safe in build script)
            &[PathBuf::from(p)]
        } else {
            &[
                workspace_root.join("target/release").join(bin_name),
                workspace_root.join("target/debug").join(bin_name),
                workspace_root.join(bin_name),
                manifest_path.join(bin_name),
            ]
        };

        let found = bin_paths.iter().find(|p| p.exists());

        if let Some(path) = found {
            let out_dir = env::var("OUT_DIR").unwrap();
            let embedded_path = PathBuf::from(&out_dir).join(bin_name);
            fs::copy(path, &embedded_path)
                .expect("Failed to copy tun2socks binary to OUT_DIR");

            println!("cargo:rustc-env=TUN2SOCKS_EMBEDDED={}", embedded_path.display());
            println!("cargo:warning=tun2socks embedded from: {}", path.display());
        } else {
            panic!(
                "tun2socks binary not found at target/release/{}!\
\
                 Set TUN2SOCKS_BIN env var or download from: https://github.com/xjasonlyu/tun2socks/releases",
                bin_name
            );
        }
    }
}
