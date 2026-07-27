// Build script for aether-engine
//
// Builds tun2socks from source (Go) and embeds the binary
// into the compiled executable at build time.
//
// On Windows, also embeds wintun.dll which is required by tun2socks
// for TUN device creation via the WireGuard wintun package.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_available)");
    println!("cargo::rustc-check-cfg=cfg(wintun_embedded)");

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
                let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| String::from("unknown"));
                let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| String::from("unknown"));

                let goos = match target_os.as_str() {
                    "windows" => "windows",
                    "linux" => "linux",
                    "macos" => "darwin",
                    "android" => {
                        println!("cargo:warning=Android target detected; tun2socks not needed");
                        return;
                    }
                    other => {
                        println!("cargo:warning=Unknown target_os '{}', defaulting to linux", other);
                        "linux"
                    }
                };

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
                        println!("cargo:warning=go build failed with exit code: {:?}", s.code());
                        if prebuilt_path.exists() {
                            println!("cargo:warning=Using pre-built binary from: {}", prebuilt_path.display());
                            fs::copy(&prebuilt_path, &bin_path)
                                .expect("Failed to copy pre-built tun2socks");
                        } else {
                            panic!(
                                "Cannot build tun2socks!\
                                 Build failed with exit code: {:?}\
                                 Target: {goos}/{goarch}\
                                 To fix this:\
                                 1. Install Go from https://go.dev/dl/\
                                 2. Build tun2socks manually:\
                                    cd tun2socks && CGO_ENABLED=0 GOOS={goos} GOARCH={goarch} go build -o ../target/release/{bin_name} -trimpath -ldflags=\"-s -w\" .\
                                 3. Then run: cargo build --release",
                                s.code()
                            );
                        }
                    }
                    Err(e) => {
                        println!("cargo:warning=go not found ({e}), checking for pre-built binary...");
                        if prebuilt_path.exists() {
                            fs::copy(&prebuilt_path, &bin_path)
                                .expect("Failed to copy pre-built tun2socks");
                            println!("cargo:warning=Using pre-built tun2socks from: {}", prebuilt_path.display());
                        } else {
                            panic!(
                                "Cannot build tun2socks: Go is not installed and no pre-built binary found.\
                                 Pre-built path checked: {}\
                                 Target: {goos}/{goarch}\
                                 To fix this:\
                                 1. Install Go from https://go.dev/dl/\
                                 2. Build tun2socks manually:\
                                    cd tun2socks && CGO_ENABLED=0 GOOS={goos} GOARCH={goarch} go build -o ../target/release/{bin_name} -trimpath -ldflags=\"-s -w\" .\
                                 3. Then run: cargo build --release",
                                prebuilt_path.display()
                            );
                        }
                    }
                }
            }
        }

        // ── Windows: embed wintun.dll ───────────────────────────────────
        #[cfg(target_os = "windows")]
        {
            embed_wintun_dll(&tun2socks_src, &out_dir);
        }

        println!("cargo:rustc-env=TUN2SOCKS_EMBEDDED={}", bin_path.display());
        println!("cargo:warning=tun2socks embedded at: {}", bin_path.display());
    }
}

// ── Windows: wintun.dll embedding ───────────────────────────────────────

/// Locate or download wintun.dll and copy it to the output dir.
#[cfg(target_os = "windows")]
fn embed_wintun_dll(tun2socks_src: &PathBuf, out_dir: &str) {
    let wintun_dll_out = PathBuf::from(out_dir).join("wintun.dll");

    if wintun_dll_out.exists() {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!("cargo:rustc-env=WINTUN_EMBEDDED={}", wintun_dll_out.display());
        println!("cargo:warning=wintun.dll already present at: {}", wintun_dll_out.display());
        return;
    }

    // Strategy 1: Check common locations for an existing wintun.dll
    let candidate_paths = [
        tun2socks_src.join("wintun.dll"),
        tun2socks_src.parent().unwrap_or(tun2socks_src).join("wintun.dll"),
        PathBuf::from("C:\\Windows\\System32\\wintun.dll"),
    ];

    for p in &candidate_paths {
        if p.exists() {
            println!("cargo:warning=Found wintun.dll at: {}", p.display());
            if fs::copy(p, &wintun_dll_out).is_ok() {
                println!("cargo:rustc-cfg=wintun_embedded");
                println!("cargo:rustc-env=WINTUN_EMBEDDED={}", wintun_dll_out.display());
                println!("cargo:warning=wintun.dll copied to: {}", wintun_dll_out.display());
            }
            return;
        }
    }

    // Strategy 2: Try to download wintun.dll from wintun.net
    if download_wintun_dll(&wintun_dll_out) {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!("cargo:rustc-env=WINTUN_EMBEDDED={}", wintun_dll_out.display());
        println!("cargo:warning=wintun.dll downloaded to: {}", wintun_dll_out.display());
        return;
    }

    println!("cargo:warning=wintun.dll NOT found and could not be downloaded — TUN will fail on Windows!");
    println!("cargo:warning=Download manually from https://www.wintun.net/ and place wintun.dll in the tun2socks directory.");
}

/// Download wintun.dll from the official WireGuard wintun releases.
/// Returns true on success.
#[cfg(target_os = "windows")]
fn download_wintun_dll(dest: &PathBuf) -> bool {
    use std::io::Read;

    // wintun 0.14.1 — the stable version used by WireGuard
    let url = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    println!("cargo:warning=Downloading wintun.dll from {url}...");

    // Use a minimal HTTPS fetch via std::process (powershell on Windows is always available)
    let tmp_zip = std::env::temp_dir().join("wintun_build.zip");

    // Try powershell download first (most reliable on Windows CI/dev machines)
    let ps_script = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
        url,
        tmp_zip.display()
    );

    let dl_status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .status();

    match dl_status {
        Ok(s) if s.success() => {}
        _ => {
            // Fallback: try curl if available
            println!("cargo:warning=PowerShell download failed, trying curl...");
            let curl_status = Command::new("curl")
                .args(["-L", "-o"])
                .arg(tmp_zip.to_str().unwrap_or("wintun.zip"))
                .arg(url)
                .status();
            match curl_status {
                Ok(s) if s.success() => {}
                _ => {
                    println!("cargo:warning=Failed to download wintun.zip. Download manually from https://www.wintun.net/");
                    return false;
                }
            }
        }
    }

    if !tmp_zip.exists() {
        println!("cargo:warning=Downloaded wintun.zip not found at {}", tmp_zip.display());
        return false;
    }

    // Extract wintun.dll from the zip using PowerShell
    let extract_script = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
         $dll = Get-ChildItem -Path '{}' -Recurse -Filter 'wintun.dll' | Select-Object -First 1; \
         if ($dll) {{ Copy-Item $dll.FullName '{}' }}",
        tmp_zip.display(),
        std::env::temp_dir().join("wintun_extract").display(),
        std::env::temp_dir().join("wintun_extract").display(),
        dest.display()
    );

    let extract_status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &extract_script])
        .status();

    // Cleanup temp files
    let _ = fs::remove_file(&tmp_zip);
    let _ = fs::remove_dir_all(std::env::temp_dir().join("wintun_extract"));

    match extract_status {
        Ok(s) if s.success() => {
            if dest.exists() {
                println!("cargo:warning=wintun.dll extracted successfully");
                return true;
            }
        }
        _ => {}
    }

    println!("cargo:warning=Failed to extract wintun.dll from zip");
    false
}

// Non-Windows stub
#[cfg(not(target_os = "windows"))]
fn embed_wintun_dll(_tun2socks_src: &PathBuf, _out_dir: &str) {
    // wintun.dll is not needed on non-Windows platforms
}
