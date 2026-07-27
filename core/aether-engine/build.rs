// Build script for aether-engine
//
// Builds tun2socks from source (Go) and embeds the binary
// into the compiled executable at build time.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_available)");
    println!("cargo:rustc-cfg=tun2socks_available");

    #[cfg(target_os = "android")]
    {
        println!("cargo:warning=Android build: tun2socks not used (uses tun.rs)");
        return;
    }

    #[cfg(not(target_os = "android"))]
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = PathBuf::from(&manifest_dir);
        let workspace_root = manifest_path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_path)
            .to_path_buf();

        let tun2socks_src = workspace_root.join("tun2socks");

        if !tun2socks_src.join("main.go").exists() {
            panic!("tun2socks submodule not found at {}! Run: git submodule update --init --recursive", tun2socks_src.display());
        }

        #[cfg(target_os = "windows")]
        let bin_name = "tun2socks.exe";
        #[cfg(not(target_os = "windows"))]
        let bin_name = "tun2socks";

        let out_dir = env::var("OUT_DIR").unwrap();
        let bin_path = PathBuf::from(&out_dir).join(bin_name);

        // Check if binary already exists (from a previous build)
        // and if go.mod hasn't changed, skip rebuild
        let go_mod = tun2socks_src.join("go.mod");
        let needs_build = if bin_path.exists() {
            let bin_meta = fs::metadata(&bin_path).ok();
            let mod_meta = fs::metadata(&go_mod).ok();
            match (bin_meta, mod_meta) {
                (Some(b), Some(m)) => {
                    b.modified().ok() > m.modified().ok()
                }
                _ => true,
            }
        } else {
            true
        };

        if needs_build {
            println!("cargo:warning=Building tun2socks from source...");

            let status = Command::new("go")
                .args(["build", "-o"])
                .arg(&bin_path)
                .args(["-trimpath", "-ldflags=-s -w"])
                .current_dir(&tun2socks_src)
                .status();

            match status {
                Ok(s) if s.success() => {
                    println!("cargo:warning=tun2socks built successfully");
                }
                Ok(s) => {
                    panic!("go build tun2socks failed with exit code: {:?}", s.code());
                }
                Err(e) => {
                    // If go is not available, try pre-built binary
                    println!("cargo:warning=go not found ({e}), checking for pre-built binary...");
                    let prebuilt = workspace_root.join("target/release").join(bin_name);
                    if prebuilt.exists() {
                        fs::copy(&prebuilt, &bin_path)
                            .expect("Failed to copy pre-built tun2socks");
                        println!("cargo:warning=Using pre-built tun2socks from: {}", prebuilt.display());
                    } else {
                        panic!(
                            "Cannot build tun2socks: go not found and no pre-built binary at {}.\
\
                             Install Go or place the binary at that path.",
                            prebuilt.display()
                        );
                    }
                }
            }
        }

        println!("cargo:rustc-env=TUN2SOCKS_EMBEDDED={}", bin_path.display());
        println!("cargo:warning=tun2socks embedded at: {}", bin_path.display());
    }
}
