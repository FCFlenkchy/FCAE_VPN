// Build script for aether-engine
//
// Builds tun2socks from source (Go) and embeds the binary
// into the compiled executable at build time.
//
// On Windows, also downloads and embeds wintun.dll from wintun.net
// at build time. The DLL is required by tun2socks for TUN device
// creation via the WireGuard wintun package. It is NOT stored in
// the repository — it's fetched fresh during the build.

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
        // Use target_os env var (not cfg!) to detect Windows target when
        // cross-compiling from Linux CI runners.
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| String::from("unknown"));
        if target_os == "windows" {
            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| String::from("x86_64"));
            let wintun_arch = match target_arch.as_str() {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                "x86" => "x86",
                other => {
                    println!("cargo:warning=Unknown target_arch '{}' for wintun, defaulting to amd64", other);
                    "amd64"
                }
            };
            embed_wintun_dll(&tun2socks_src, &out_dir, wintun_arch);
        }

        println!("cargo:rustc-env=TUN2SOCKS_EMBEDDED={}", bin_path.display());
        println!("cargo:warning=tun2socks embedded at: {}", bin_path.display());
    }
}

// ── Windows: wintun.dll embedding ───────────────────────────────────────

/// Download wintun.dll from wintun.net and embed it for the build.
///
/// NOTE: This function is ALWAYS compiled (for all host OS). The decision
/// whether to embed wintun.dll is made at build time based on the TARGET OS
/// (CARGO_CFG_TARGET_OS), not the host OS. This is critical for cross-
/// compilation scenarios, e.g., building for Windows from a Linux CI runner.
///
/// wintun.dll is NO LONGER stored in the tun2socks/ directory — it is
/// downloaded at build time from the official wintun.net release and
/// embedded into the binary. This keeps the repo clean and ensures
/// the correct version is always used.
fn embed_wintun_dll(_tun2socks_src: &PathBuf, out_dir: &str, wintun_arch: &str) {
    let wintun_dll_out = PathBuf::from(out_dir).join("wintun.dll");

    // If already present from a previous build, skip download
    if wintun_dll_out.exists() {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!("cargo:rustc-env=WINTUN_EMBEDDED={}", wintun_dll_out.display());
        println!("cargo:warning=wintun.dll already present at: {}", wintun_dll_out.display());
        return;
    }

    // Download wintun.dll from wintun.net (official WireGuard project)
    if download_wintun_dll(&wintun_dll_out, wintun_arch) {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!("cargo:rustc-env=WINTUN_EMBEDDED={}", wintun_dll_out.display());
        println!("cargo:warning=wintun.dll ({}) downloaded to: {}", wintun_arch, wintun_dll_out.display());
        return;
    }

    println!("cargo:warning=wintun.dll NOT found and could not be downloaded — TUN will fail on Windows!");
    println!("cargo:warning=Download manually from https://www.wintun.net/ and place wintun.dll in the same directory as the built executable.");
}

/// Download wintun.dll from the official WireGuard wintun releases.
///
/// Works on both Windows and Linux hosts:
/// - Windows: tries PowerShell, then curl
/// - Linux/macOS: tries curl, then wget
///
/// Returns true on success.
fn download_wintun_dll(dest: &PathBuf, wintun_arch: &str) -> bool {
    // wintun 0.14.1 — the stable version used by WireGuard
    let url = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    println!("cargo:warning=Downloading wintun.dll ({}) from {url}...", wintun_arch);

    let tmp_zip = std::env::temp_dir().join("wintun_build.zip");
    let extract_dir = std::env::temp_dir().join("wintun_extract");

    // Clean up any leftover files from previous runs
    let _ = fs::remove_file(&tmp_zip);
    let _ = fs::remove_dir_all(&extract_dir);

    let host_os = std::env::consts::OS;

    // ── Download ───────────────────────────────────────────────────
    let dl_success = if host_os == "windows" {
        // Windows: try PowerShell first, then curl
        let ps_script = format!(
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
             Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
            url,
            tmp_zip.display()
        );
        let ps_status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_script])
            .status();
        match ps_status {
            Ok(s) if s.success() => true,
            _ => {
                println!("cargo:warning=PowerShell download failed, trying curl...");
                try_curl_download(url, &tmp_zip)
            }
        }
    } else {
        // Linux/macOS: try curl first, then wget
        if try_curl_download(url, &tmp_zip) {
            true
        } else {
            println!("cargo:warning=curl download failed, trying wget...");
            try_wget_download(url, &tmp_zip)
        }
    };

    if !dl_success {
        println!("cargo:warning=All download methods failed. Download wintun.dll manually from https://www.wintun.net/");
        return false;
    }

    if !tmp_zip.exists() {
        println!("cargo:warning=Downloaded wintun.zip not found at {}", tmp_zip.display());
        return false;
    }

    // ── Extract ────────────────────────────────────────────────────
    let extract_success = extract_wintun_dll(&tmp_zip, &extract_dir, dest, wintun_arch);

    // Cleanup temp files
    let _ = fs::remove_file(&tmp_zip);
    let _ = fs::remove_dir_all(&extract_dir);

    if extract_success {
        if dest.exists() {
            println!("cargo:warning=wintun.dll extracted successfully");
            return true;
        }
    }

    println!("cargo:warning=Failed to extract wintun.dll from zip");
    false
}

/// Try downloading via curl. Returns true on success.
fn try_curl_download(url: &str, dest: &PathBuf) -> bool {
    let status = Command::new("curl")
        .args(["-L", "--fail", "-o"])
        .arg(dest.to_str().unwrap_or("wintun.zip"))
        .arg(url)
        .arg("--connect-timeout")
        .arg("30")
        .arg("--max-time")
        .arg("120")
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Try downloading via wget. Returns true on success.
fn try_wget_download(url: &str, dest: &PathBuf) -> bool {
    let status = Command::new("wget")
        .args(["-q", "-O"])
        .arg(dest.to_str().unwrap_or("wintun.zip"))
        .arg(url)
        .arg("--timeout=30")
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Extract wintun.dll from the downloaded zip archive.
/// Works on both Windows (PowerShell / tar) and Linux (unzip).
/// `wintun_arch` is "amd64", "arm64", or "x86" — the correct
/// architecture-specific DLL inside the zip is selected.
/// Returns true on success.
fn extract_wintun_dll(zip_path: &PathBuf, extract_dir: &PathBuf, dest: &PathBuf, wintun_arch: &str) -> bool {
    let host_os = std::env::consts::OS;

    if host_os == "windows" {
        // Try PowerShell Expand-Archive first
        // Pick the architecture-specific wintun.dll from wintun/bin/{arch}/wintun.dll
        let ps_script = format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
             $dll = Get-ChildItem -Path '{}' -Recurse -Filter 'wintun.dll' | Where-Object {{ $_.DirectoryName -like '*\\bin\\{}*' }} | Select-Object -First 1; \
             if (-not $dll) {{ $dll = Get-ChildItem -Path '{}' -Recurse -Filter 'wintun.dll' | Select-Object -First 1 }}; \
             if ($dll) {{ Copy-Item $dll.FullName '{}' }}",
            zip_path.display(),
            extract_dir.display(),
            extract_dir.display(),
            wintun_arch,
            extract_dir.display(),
            dest.display()
        );
        let ps_status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_script])
            .status();
        if matches!(ps_status, Ok(s) if s.success()) && dest.exists() {
            return true;
        }
        // Fallback: try tar (Windows 10+ has tar built-in)
        println!("cargo:warning=PowerShell extraction failed, trying tar...");
        let _ = fs::create_dir_all(extract_dir);
        let tar_status = Command::new("tar")
            .args(["-xf"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg("-C")
            .arg(extract_dir.to_str().unwrap_or(""))
            .status();
        if matches!(tar_status, Ok(s) if s.success()) {
            // Find wintun.dll preferring the correct architecture
            if let Some(found) = find_wintun_in_dir(extract_dir, wintun_arch) {
                return fs::copy(&found, dest).is_ok();
            }
        }
    } else {
        // Linux/macOS: use unzip
        let _ = fs::create_dir_all(extract_dir);
        let unzip_status = Command::new("unzip")
            .args(["-o"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg("-d")
            .arg(extract_dir.to_str().unwrap_or(""))
            .status();
        if matches!(unzip_status, Ok(s) if s.success()) {
            if let Some(found) = find_wintun_in_dir(extract_dir, wintun_arch) {
                return fs::copy(&found, dest).is_ok();
            }
        }
        // Fallback: try 7z if available
        println!("cargo:warning=unzip failed, trying 7z...");
        let _ = fs::create_dir_all(extract_dir);
        let sz_status = Command::new("7z")
            .args(["x"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg(format!("-o{}", extract_dir.display()))
            .arg("-y")
            .status();
        if matches!(sz_status, Ok(s) if s.success()) {
            if let Some(found) = find_wintun_in_dir(extract_dir, wintun_arch) {
                return fs::copy(&found, dest).is_ok();
            }
        }
    }

    false
}

/// Recursively search for wintun.dll, preferring the architecture-specific
/// path (e.g., wintun/bin/amd64/wintun.dll). Falls back to any wintun.dll
/// if the architecture-specific one isn't found.
fn find_wintun_in_dir(dir: &PathBuf, wintun_arch: &str) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }

    // First pass: look for architecture-specific path pattern
    // wintun-0.14.1.zip extracts as: wintun/bin/{arch}/wintun.dll
    let arch_path = dir.join("wintun").join("bin").join(wintun_arch).join("wintun.dll");
    if arch_path.exists() {
        return Some(arch_path);
    }

    // Second pass: fallback — any wintun.dll
    find_any_file(dir, "wintun.dll")
}

/// Recursively search a directory for a file with the given name.
/// Returns the full path if found.
fn find_any_file(dir: &PathBuf, filename: &str) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(found) = find_any_file(&path, filename) {
                        return Some(found);
                    }
                } else if path.file_name().map_or(false, |n| n == filename) {
                    return Some(path);
                }
            }
        }
        Err(_) => {}
    }
    None
}
