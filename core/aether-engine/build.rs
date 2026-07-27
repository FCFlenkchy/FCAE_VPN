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

        #[cfg(target_os = "windows")]
        let bin_name = "tun2socks.exe";
        #[cfg(not(target_os = "windows"))]
        let bin_name = "tun2socks";

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
                // Detect target OS for cross-compilation or native builds
                let goos = if cfg!(target_os = "windows") {
                    "windows"
                } else if cfg!(target_os = "linux") {
                    "linux"
                } else if cfg!(target_os = "macos") {
                    "darwin"
                } else {
                    "linux" // fallback
                };

                // Detect target architecture — always 64-bit
                let goarch = if cfg!(target_arch = "x86_64") {
                    "amd64"
                } else if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    "amd64" // fallback to 64-bit
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
