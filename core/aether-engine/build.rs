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

    // Android doesn't need tun2socks — it uses tun.rs natively
    #[cfg(target_os = "android")]
    {
        println!("cargo:warning=Android build: tun2socks not used (uses tun.rs)");
        return;
    }

    println!("cargo:rustc-cfg=tun2socks_available");

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

        // Determine binary name based on TARGET OS (not host)
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| String::from("unknown"));
        let bin_name = if target_os == "windows" { "tun2socks.exe" } else { "tun2socks" };

        let out_dir = env::var("OUT_DIR").unwrap();
        let bin_path = PathBuf::from(&out_dir).join(bin_name);

        // Also check workspace target/release for pre-built binary
        let prebuilt_path = workspace_root.join("target").join("release").join(bin_name);

        // Check if binary already exists (from a previous build)
        // and if go.mod hasn't changed, skip rebuild
        let go_mod = tun2socks_src.join("go.mod");
        let needs_build = if bin_path.exists() {
            let bin_meta = fs::metadata(&bin_path).ok();
            let mod_meta = fs::metadata(&go_mod).ok();
            match (bin_meta, mod_meta) {
                (Some(b), Some(m)) => {
                    match (b.modified(), m.modified()) {
                        (Ok(bin_time), Ok(mod_time)) => {
                            // Rebuild if go.mod is newer than the binary (source changed)
                            mod_time > bin_time
                        }
                        _ => true,
                    }
                }
                _ => true,
            }
        } else {
            true
        };

        if needs_build {
            // First check if pre-built binary exists in target/release
            if prebuilt_path.exists() {
                println!("cargo:warning=Copying pre-built tun2socks from: {}", prebuilt_path.display());
                fs::copy(&prebuilt_path, &bin_path)
                    .expect("Failed to copy pre-built tun2socks");
                println!("cargo:warning=tun2socks copied successfully");
            } else {
                // Use Cargo target env vars (NOT cfg!() which reflects the host)
                // This ensures cross-compilation works correctly
                // e.g., when building for x86_64-pc-windows-gnu on a Linux runner
                // target_os already read above for bin_name, re-read for clarity
                let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| String::from("unknown"));
                let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| String::from("unknown"));

                // Map Rust target_os to GOOS
                let goos = match target_os.as_str() {
                    "windows" => "windows",
                    "linux" => "linux",
                    "macos" => "darwin",
                    "android" => {
                        // Android builds should have returned early above,
                        // but handle gracefully just in case
                        println!("cargo:warning=Android target detected; tun2socks not needed");
                        return;
                    }
                    other => {
                        println!("cargo:warning=Unknown target_os '{}', defaulting to linux", other);
                        "linux"
                    }
                };

                // Map Rust target_arch to GOARCH — always 64-bit
                let goarch = match target_arch.as_str() {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => {
                        println!("cargo:warning=Unknown target_arch '{}', defaulting to amd64", other);
                        "amd64"
                    }
                };

                println!("cargo:warning=Building tun2socks from source ({goos}/{goarch})...");

                let status = Command::new("go")
                    .env("CGO_ENABLED", "0")
                    .env("GOOS", goos)
                    .env("GOARCH", goarch)
                    .args(["build", "-o"])
                    .arg(&bin_path)
                    .args(["-trimpath", "-ldflags=-s -w"])
                    .current_dir(&tun2socks_src)
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        println!("cargo:warning=tun2socks built successfully for {goos}/{goarch}");
                    }
                    Ok(s) => {
                        // If go build failed, try pre-built binary
                        println!("cargo:warning=go build failed with exit code: {:?}", s.code());
                        if prebuilt_path.exists() {
                            println!("cargo:warning=Using pre-built binary from: {}", prebuilt_path.display());
                            fs::copy(&prebuilt_path, &bin_path)
                                .expect("Failed to copy pre-built tun2socks");
                        } else {
                            panic!(
                                "Cannot build tun2socks!\
\
                                 \
\
                                 Build failed with exit code: {:?}\
\
                                 Target: {goos}/{goarch}\
\
                                 \
\
                                 To fix this:\
\
                                 1. Install Go from https://go.dev/dl/\
\
                                 2. Build tun2socks manually:\
\
                                    cd tun2socks && CGO_ENABLED=0 GOOS={goos} GOARCH={goarch} go build -o ../target/release/{bin_name} -trimpath -ldflags=\"-s -w\" .\
\
                                 3. Then run: cargo build --release",
                                s.code()
                            );
                        }
                    }
                    Err(e) => {
                        // If go is not available, check pre-built binary
                        println!("cargo:warning=go not found ({e}), checking for pre-built binary...");
                        if prebuilt_path.exists() {
                            fs::copy(&prebuilt_path, &bin_path)
                                .expect("Failed to copy pre-built tun2socks");
                            println!("cargo:warning=Using pre-built tun2socks from: {}", prebuilt_path.display());
                        } else {
                            panic!(
                                "Cannot build tun2socks: Go is not installed and no pre-built binary found.\
\
                                 \
\
                                 Pre-built path checked: {}\
\
                                 Target: {goos}/{goarch}\
\
                                 \
\
                                 To fix this:\
\
                                 1. Install Go from https://go.dev/dl/\
\
                                 2. Build tun2socks manually:\
\
                                    cd tun2socks && CGO_ENABLED=0 GOOS={goos} GOARCH={goarch} go build -o ../target/release/{bin_name} -trimpath -ldflags=\"-s -w\" .\
\
                                 3. Then run: cargo build --release",
                                prebuilt_path.display()
                            );
                        }
                    }
                }
            }
        }

        println!("cargo:rustc-env=TUN2SOCKS_EMBEDDED={}", bin_path.display());
        println!("cargo:warning=tun2socks embedded at: {}", bin_path.display());
    }
}
