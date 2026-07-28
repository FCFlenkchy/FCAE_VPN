// Build script for aether-engine
//
// Builds hev-socks5-tunnel from source (C) and embeds the binary
// into the compiled executable at build time.
//
// On Windows, also embeds wintun.dll which is required for
// TUN device creation via the WireGuard wintun package.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(hevsocks5_available)");
    println!("cargo::rustc-check-cfg=cfg(wintun_embedded)");

    // Determine target OS at runtime (CARGO_CFG_TARGET_OS tells us what we're building FOR)
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| String::from("unknown"));

    // ── Android: hev-socks5-tunnel is NOT needed ───────────────────────
    // Android uses tun.rs natively — no C tunnel binary to build or embed.
    // Skip ALL hev-socks5-tunnel logic: no clone check, no build, no embed,
    // and crucially do NOT set hevsocks5_available cfg.
    if target_os == "android" {
        println!("cargo:warning=Android target: hev-socks5-tunnel not built or embedded (uses tun.rs natively)");
        return;
    }

    // ── Windows & Linux only: build/embed hev-socks5-tunnel ────────────
    // hev-socks5-tunnel is only used on Windows and Linux targets.
    // Other targets (macOS, iOS, etc.) also skip the C tunnel for now.
    if target_os != "windows" && target_os != "linux" {
        println!(
            "cargo:warning=Target '{}' does not use hev-socks5-tunnel — skipping build/embed",
            target_os
        );
        return;
    }

    // At this point we're building for Windows or Linux — enable the cfg flag
    println!("cargo:rustc-cfg=hevsocks5_available");

    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = PathBuf::from(&manifest_dir);
        let workspace_root = manifest_path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_path)
            .to_path_buf();

        let hev_src = workspace_root.join("hev-socks5-tunnel");

        // hev-socks5-tunnel is included in-tree.
        // It must be cloned with --recursive to pull in submodules:
        //   git clone --depth 1 --recursive https://github.com/heiher/hev-socks5-tunnel.git
        if !hev_src.join("src").join("hev-main.c").exists() {
            panic!(
                "hev-socks5-tunnel not found at {}!\n\
                 Clone it into the repo root:\n\
                 git clone --depth 1 --recursive https://github.com/heiher/hev-socks5-tunnel.git {}",
                hev_src.display(),
                hev_src.display()
            );
        }

        // Ensure hev-socks5-tunnel submodules are initialized.
        // hev-socks5-tunnel has its own .gitmodules for third-party deps
        // (hev-task-system, yaml, lwip, hev-socks5-core).
        // If these directories are empty stubs, the cmake build will fail.
        if hev_src.join(".gitmodules").exists() {
            // Check if submodule dirs are empty (missing files)
            let task_sys_header = hev_src.join(
                "third-part/hev-task-system/src/lib/misc/hev-compiler.h"
            );
            if !task_sys_header.exists() {
                println!("cargo:warning=hev-socks5-tunnel submodules missing — initializing...");
                // Try git submodule init (works if hev-socks5-tunnel is a git repo or part of one)
                let s = Command::new("git")
                    .args(["submodule", "update", "--init", "--recursive", "--depth", "1"])
                    .current_dir(&hev_src)
                    .status();
                if s.is_err() || s.unwrap().success() {
                    // git might not be available or succeeded — check again
                }
                if !task_sys_header.exists() {
                    // If still missing, try running git from workspace root
                    let s2 = Command::new("git")
                        .args(["-C", hev_src.to_str().unwrap_or("."), "submodule", "update", "--init", "--recursive", "--depth", "1"])
                        .current_dir(&workspace_root)
                        .status();
                    if s2.is_ok() && !s2.unwrap().success() {
                        println!("cargo:warning=Failed to init hev-socks5-tunnel submodules via git");
                    }
                }
            }
        }

        // Determine binary name based on TARGET OS (not host)
        let bin_name = if target_os == "windows" {
            "hev-socks5-tunnel.exe"
        } else {
            "hev-socks5-tunnel"
        };

        let out_dir = env::var("OUT_DIR").unwrap();
        let bin_path = PathBuf::from(&out_dir).join(bin_name);

        // Also check workspace target/release for pre-built binary
        let prebuilt_path = workspace_root.join("target").join("release").join(bin_name);

        // Check if binary already exists (from a previous build)
        // and if CMakeLists.txt hasn't changed, skip rebuild
        let cmake_file = hev_src.join("CMakeLists.txt");
        let needs_build = if bin_path.exists() {
            let bin_meta = fs::metadata(&bin_path).ok();
            let cmake_meta = fs::metadata(&cmake_file).ok();
            match (bin_meta, cmake_meta) {
                (Some(b), Some(c)) => match (b.modified(), c.modified()) {
                    (Ok(bin_time), Ok(cmake_time)) => cmake_time > bin_time,
                    _ => true,
                },
                _ => true,
            }
        } else {
            true
        };

        if needs_build {
            // First check if pre-built binary exists in target/release
            if prebuilt_path.exists() {
                println!(
                    "cargo:warning=Copying pre-built hev-socks5-tunnel from: {}",
                    prebuilt_path.display()
                );
                fs::copy(&prebuilt_path, &bin_path)
                    .expect("Failed to copy pre-built hev-socks5-tunnel");
                println!("cargo:warning=hev-socks5-tunnel copied successfully");
            } else {
                // Build from source using cmake + make
                match target_os.as_str() {
                    "windows" => {
                        println!(
                            "cargo:warning=Building hev-socks5-tunnel for Windows (MinGW)..."
                        );
                        build_hev_windows(&hev_src, &bin_path, &out_dir);
                    }
                    "linux" => {
                        println!("cargo:warning=Building hev-socks5-tunnel for Linux...");
                        build_hev_linux(&hev_src, &bin_path, &out_dir);
                    }
                    _ => {
                        // Already filtered to windows/linux above, unreachable here
                        unreachable!("hev-socks5-tunnel build called for unsupported target: {target_os}");
                    }
                }

                if !bin_path.exists() {
                    if prebuilt_path.exists() {
                        println!(
                            "cargo:warning=Build failed, falling back to pre-built: {}",
                            prebuilt_path.display()
                        );
                        fs::copy(&prebuilt_path, &bin_path)
                            .expect("Failed to copy pre-built hev-socks5-tunnel");
                    } else {
                        panic!(
                            "Cannot build hev-socks5-tunnel!\n\
                             Build failed for target: {target_os}\n\
                             To fix this:\n\
                             1. Install cmake and a C compiler (gcc/clang)\n\
                             2. Build manually:\n\
                                cd {} && mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .\n\
                             3. Copy hev-socks5-tunnel to ../target/release/{bin_name}\n\
                             4. Then run: cargo build --release",
                            hev_src.display()
                        );
                    }
                }
            }
        }

        // ── Windows: embed wintun.dll ───────────────────────────────────
        if target_os == "windows" {
            embed_wintun_dll(&hev_src, &out_dir);
        }

        println!("cargo:rustc-env=HEVSOCKS5_EMBEDDED={}", bin_path.display());
        println!(
            "cargo:warning=hev-socks5-tunnel embedded at: {}",
            bin_path.display()
        );
    }
}

// ── Build: Linux ──────────────────────────────────────────────────────

fn build_hev_linux(src: &PathBuf, dest: &PathBuf, _out_dir: &str) {
    let build_dir = src.join("build");
    fs::create_dir_all(&build_dir).expect("Failed to create build dir");

    // cmake
    let status = Command::new("cmake")
        .args(["..", "-DCMAKE_BUILD_TYPE=Release"])
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run cmake");
    if !status.success() {
        panic!("cmake configure failed with exit: {:?}", status.code());
    }

    // make
    let status = Command::new("make")
        .args(["-j", &num_cpus().to_string()])
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run make");
    if !status.success() {
        panic!("make failed with exit: {:?}", status.code());
    }

    // Find the built binary
    let built = build_dir.join("hev-socks5-tunnel");
    if !built.exists() {
        // Check common alternative locations
        let alt = build_dir.join("src").join("hev-socks5-tunnel");
        if alt.exists() {
            fs::copy(&alt, dest).expect("Failed to copy hev-socks5-tunnel binary");
        } else {
            panic!("Built hev-socks5-tunnel not found at {}", built.display());
        }
    } else {
        fs::copy(&built, dest).expect("Failed to copy hev-socks5-tunnel binary");
    }

    // Strip if possible to reduce size
    let _ = Command::new("strip").arg(dest).status();

    println!("cargo:warning=hev-socks5-tunnel built for Linux");
}

// ── Build: Windows (MinGW-w64 cross or native MSVC) ───────────────────

fn build_hev_windows(src: &PathBuf, dest: &PathBuf, _out_dir: &str) {
    let build_dir = src.join("build");

    // Determine if we're cross-compiling (host != Windows)
    let host_os = std::env::consts::OS;
    let is_cross = host_os != "windows";

    if is_cross {
        // Try to find a MinGW cross-compiler
        let mingw_cc = find_mingw_cross_compiler();
        match mingw_cc {
            Some(ref cc) => {
                println!("cargo:warning=Cross-compiling hev-socks5-tunnel with: {cc}");
                build_hev_windows_cross(src, dest, cc, &build_dir);
            }
            None => {
                // No cross-compiler available — skip the C tunnel build.
                // The Rust Windows binary can still use built-in TUN via other means.
                println!("cargo:warning=No MinGW cross-compiler found — skipping hev-socks5-tunnel build for Windows target");
                println!("cargo:warning=Install mingw-w64: sudo apt-get install mingw-w64 g++-mingw-w64-x86-64");
                // Create a stub so the build doesn't panic
                let _ = fs::write(dest, b"");
            }
        }
    } else {
        // Native Windows build — use default cmake
        build_hev_windows_native(src, dest, &build_dir);
    }
}

/// Cross-compile from Linux to Windows using MinGW
fn build_hev_windows_cross(
    src: &PathBuf,
    dest: &PathBuf,
    cc: &str,
    build_dir: &PathBuf,
) {
    fs::create_dir_all(build_dir).expect("Failed to create build dir");

    // Extract the cross-compiler prefix (e.g., "x86_64-w64-mingw32-" from "x86_64-w64-mingw32-gcc")
    let cross_prefix = cc.trim_end_matches("gcc");
    let cross_ar = format!("{cross_prefix}ar");
    let cross_ld = format!("{cross_prefix}ld");
    let cross_ranlib = format!("{cross_prefix}ranlib");

    // Helper to check if a command exists in PATH
    let cmd_exists = |cmd: &str| -> bool {
        Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    // Build CMake arguments for cross-compilation.
    // Key insight: CMake's compiler detection runs a link test that fails
    // because MinGW gcc invokes the host GNU ld (which doesn't understand
    // Windows PE flags like --major-image-version). We fix this by:
    // 1. Forcing the compiler with CMAKE_C_COMPILER_FORCED=1
    // 2. Skipping the broken compile+link test with CMAKE_C_COMPILER_WORKS=1
    // 3. Using TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY to bypass linker test
    // 4. Explicitly setting the cross-linker if available
    // 5. Writing a toolchain file for more robust cross-compilation
    let toolchain_file = build_dir.join("toolchain.cmake");
    let toolchain_content = format!(
        r#"set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER {cc})
set(CMAKE_C_COMPILER_FORCED 1)
set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
"#
    );
    // Add cross-linker, ar, ranlib, and ASM compiler if available
    let toolchain_content = if cmd_exists(&cross_ld) {{
        format!("{toolchain_content}set(CMAKE_LINKER {cross_ld})\n")
    }} else {{
        toolchain_content
    }};
    let toolchain_content = if cmd_exists(&cross_ar) {{
        format!("{toolchain_content}set(CMAKE_AR {cross_ar})\n")
    }} else {{
        toolchain_content
    }};
    // Use the cross gcc also as assembler (for .s files)
    let toolchain_content = format!("{toolchain_content}set(CMAKE_ASM_COMPILER {cc})\nset(CMAKE_ASM_COMPILER_FORCED 1)\nset(CMAKE_ASM_COMPILER_WORKS 1)\n");
    let _ = fs::write(&toolchain_file, toolchain_content);

    let mut cmake_args: Vec<String> = vec![
        "..".to_string(),
        format!("-DCMAKE_TOOLCHAIN_FILE={}", toolchain_file.display()),
        "-DCMAKE_BUILD_TYPE=Release".to_string(),
    ];

    // If the cross-ar and ranlib exist, set them via cmdline too (belt-and-suspenders)
    if cmd_exists(&cross_ar) {
        cmake_args.push("-DCMAKE_AR".to_string());
        cmake_args.push(cross_ar);
    }
    if cmd_exists(&cross_ranlib) {
        cmake_args.push("-DCMAKE_RANLIB".to_string());
        cmake_args.push(cross_ranlib);
    }

    // Convert to &str references for Command::new
    let cmake_args_refs: Vec<&str> = cmake_args.iter().map(|s| s.as_str()).collect();

    let status = Command::new("cmake")
        .args(&cmake_args_refs)
        .current_dir(build_dir)
        .status()
        .expect("Failed to run cmake");
    if !status.success() {
        panic!("cmake configure failed with exit: {:?}", status.code());
    }

    // Use cmake --build which is more portable than raw make
    let status = Command::new("cmake")
        .args(["--build", ".", "--config", "Release", "-j", &num_cpus().to_string()])
        .current_dir(build_dir)
        .status()
        .expect("Failed to run cmake --build");
    if !status.success() {
        // Fallback: try raw make in case cmake --build doesn't work
        println!("cargo:warning=cmake --build failed, trying make directly...");
        let status = Command::new("make")
            .args(["-j", &num_cpus().to_string()])
            .current_dir(build_dir)
            .status()
            .expect("Failed to run make");
        if !status.success() {
            panic!("make failed with exit: {:?}", status.code());
        }
    }

    // The cross-compiler may or may not add .exe extension
    let candidates = [
        build_dir.join("hev-socks5-tunnel.exe"),
        build_dir.join("hev-socks5-tunnel"),
        build_dir.join("Release").join("hev-socks5-tunnel.exe"),
        build_dir.join("src").join("hev-socks5-tunnel.exe"),
    ];
    copy_built_binary(&candidates, dest);
}

/// Native Windows build (MSVC or MinGW on Windows host)
fn build_hev_windows_native(src: &PathBuf, dest: &PathBuf, build_dir: &PathBuf) {
    fs::create_dir_all(build_dir).expect("Failed to create build dir");

    // Try MinGW Makefiles first, then fall back to default
    let status = Command::new("cmake")
        .args([
            "..",
            "-DCMAKE_BUILD_TYPE=Release",
            "-G",
            "MinGW Makefiles",
        ])
        .current_dir(build_dir)
        .status();

    let use_mingw = match &status {
        Ok(s) if s.success() => true,
        _ => {
            println!("cargo:warning=MinGW Makefiles not available, trying default generator...");
            let _ = fs::remove_dir_all(build_dir);
            fs::create_dir_all(build_dir).expect("Failed to create build dir");
            let status = Command::new("cmake")
                .args(["..", "-DCMAKE_BUILD_TYPE=Release"])
                .current_dir(build_dir)
                .status()
                .expect("Failed to run cmake");
            if !status.success() {
                panic!("cmake configure failed with exit: {:?}", status.code());
            }
            false
        }
    };

    let make_cmd = if use_mingw { "mingw32-make" } else { "cmake" };
    let num_cpus_str = num_cpus().to_string();
    let make_args: Vec<&str> = if use_mingw {
        vec!["-j", &num_cpus_str]
    } else {
        vec!["--build", ".", "--config", "Release"]
    };

    let status = Command::new(make_cmd)
        .args(&make_args)
        .current_dir(build_dir)
        .status()
        .expect("Failed to run make/cmake --build");
    if !status.success() {
        panic!("build failed with exit: {:?}", status.code());
    }

    let candidates = [
        build_dir.join("hev-socks5-tunnel.exe"),
        build_dir.join("Release").join("hev-socks5-tunnel.exe"),
        build_dir.join("src").join("hev-socks5-tunnel.exe"),
    ];
    copy_built_binary(&candidates, dest);
}

/// Try to locate a MinGW-w64 cross-compiler
fn find_mingw_cross_compiler() -> Option<String> {
    let candidates = [
        "x86_64-w64-mingw32-gcc",
        "x86_64-w64-mingw32-gcc-posix",
        "x86_64-w64-mingw32-gcc-win32",
    ];
    for cc in &candidates {
        let status = Command::new(cc).arg("--version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        if matches!(status, Ok(s) if s.success()) {
            return Some(cc.to_string());
        }
    }
    None
}

/// Copy the first existing candidate binary to dest
fn copy_built_binary(candidates: &[PathBuf], dest: &PathBuf) {
    for c in candidates {
        if c.exists() {
            fs::copy(c, dest)
                .unwrap_or_else(|e| panic!("Failed to copy {} to {}: {e}", c.display(), dest.display()));
            return;
        }
    }
    panic!(
        "Built hev-socks5-tunnel not found. Searched: {:?}",
        candidates
    );
}

// ── Helpers ────────────────────────────────────────────────────────────

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// ── Windows: wintun.dll embedding ───────────────────────────────────────

/// Locate or download wintun.dll and copy it to the output dir.
fn embed_wintun_dll(hev_src: &PathBuf, out_dir: &str) {
    let wintun_dll_out = PathBuf::from(out_dir).join("wintun.dll");

    if wintun_dll_out.exists() {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!(
            "cargo:rustc-env=WINTUN_EMBEDDED={}",
            wintun_dll_out.display()
        );
        println!(
            "cargo:warning=wintun.dll already present at: {}",
            wintun_dll_out.display()
        );
        return;
    }

    // Strategy 1: Check common locations for an existing wintun.dll
    let host_os = std::env::consts::OS;
    let candidate_paths: Vec<PathBuf> = if host_os == "windows" {
        vec![
            hev_src.join("wintun.dll"),
            hev_src
                .parent()
                .unwrap_or(hev_src)
                .join("wintun.dll"),
            PathBuf::from("C:\\Windows\\System32\\wintun.dll"),
        ]
    } else {
        vec![
            hev_src.join("wintun.dll"),
            hev_src
                .parent()
                .unwrap_or(hev_src)
                .join("wintun.dll"),
        ]
    };

    for p in &candidate_paths {
        if p.exists() {
            println!("cargo:warning=Found wintun.dll at: {}", p.display());
            match fs::copy(p, &wintun_dll_out) {
                Ok(_) => {
                    println!("cargo:rustc-cfg=wintun_embedded");
                    println!(
                        "cargo:rustc-env=WINTUN_EMBEDDED={}",
                        wintun_dll_out.display()
                    );
                    println!(
                        "cargo:warning=wintun.dll copied to: {}",
                        wintun_dll_out.display()
                    );
                }
                Err(e) => {
                    println!(
                        "cargo:warning=Failed to copy wintun.dll from {}: {e}",
                        p.display()
                    );
                    continue;
                }
            }
            return;
        }
    }

    // Strategy 2: Try to download wintun.dll from wintun.net
    if download_wintun_dll(&wintun_dll_out) {
        println!("cargo:rustc-cfg=wintun_embedded");
        println!(
            "cargo:rustc-env=WINTUN_EMBEDDED={}",
            wintun_dll_out.display()
        );
        println!(
            "cargo:warning=wintun.dll downloaded to: {}",
            wintun_dll_out.display()
        );
        return;
    }

    println!("cargo:warning=wintun.dll NOT found and could not be downloaded — TUN will fail on Windows!");
    println!("cargo:warning=Download manually from https://www.wintun.net/ and place wintun.dll in the hev-socks5-tunnel directory.");
}

/// Download wintun.dll from the official WireGuard wintun releases.
fn download_wintun_dll(dest: &PathBuf) -> bool {
    let url = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    println!("cargo:warning=Downloading wintun.dll from {url}...");

    let tmp_zip = std::env::temp_dir().join("wintun_build.zip");
    let extract_dir = std::env::temp_dir().join("wintun_extract");

    let _ = fs::remove_file(&tmp_zip);
    let _ = fs::remove_dir_all(&extract_dir);

    let host_os = std::env::consts::OS;

    let dl_success = if host_os == "windows" {
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
        if try_curl_download(url, &tmp_zip) {
            true
        } else {
            println!("cargo:warning=curl download failed, trying wget...");
            try_wget_download(url, &tmp_zip)
        }
    };

    if !dl_success {
        println!("cargo:warning=All download methods failed.");
        return false;
    }

    if !tmp_zip.exists() {
        return false;
    }

    let extract_success = extract_wintun_dll(&tmp_zip, &extract_dir, dest);

    let _ = fs::remove_file(&tmp_zip);
    let _ = fs::remove_dir_all(&extract_dir);

    if extract_success && dest.exists() {
        println!("cargo:warning=wintun.dll extracted successfully");
        return true;
    }

    false
}

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

fn try_wget_download(url: &str, dest: &PathBuf) -> bool {
    let status = Command::new("wget")
        .args(["-q", "-O"])
        .arg(dest.to_str().unwrap_or("wintun.zip"))
        .arg(url)
        .arg("--timeout=30")
        .status();
    matches!(status, Ok(s) if s.success())
}

fn extract_wintun_dll(zip_path: &PathBuf, extract_dir: &PathBuf, dest: &PathBuf) -> bool {
    let host_os = std::env::consts::OS;

    if host_os == "windows" {
        let ps_script = format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
             $dll = Get-ChildItem -Path '{}' -Recurse -Filter 'wintun.dll' | Select-Object -First 1; \
             if ($dll) {{ Copy-Item $dll.FullName '{}' }}",
            zip_path.display(),
            extract_dir.display(),
            extract_dir.display(),
            dest.display()
        );
        let ps_status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_script])
            .status();
        if matches!(ps_status, Ok(s) if s.success()) && dest.exists() {
            return true;
        }
        println!("cargo:warning=PowerShell extraction failed, trying tar...");
        let _ = fs::create_dir_all(extract_dir);
        let tar_status = Command::new("tar")
            .args(["-xf"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg("-C")
            .arg(extract_dir.to_str().unwrap_or(""))
            .status();
        if matches!(tar_status, Ok(s) if s.success()) {
            if let Some(found) = find_file_in_dir(extract_dir, "wintun.dll") {
                return fs::copy(&found, dest).is_ok();
            }
        }
    } else {
        let _ = fs::create_dir_all(extract_dir);
        let unzip_status = Command::new("unzip")
            .args(["-o"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg("-d")
            .arg(extract_dir.to_str().unwrap_or(""))
            .status();
        if matches!(unzip_status, Ok(s) if s.success()) {
            if let Some(found) = find_file_in_dir(extract_dir, "wintun.dll") {
                return fs::copy(&found, dest).is_ok();
            }
        }
        println!("cargo:warning=unzip failed, trying 7z...");
        let _ = fs::create_dir_all(extract_dir);
        let sz_status = Command::new("7z")
            .args(["x"])
            .arg(zip_path.to_str().unwrap_or(""))
            .arg(format!("-o{}", extract_dir.display()))
            .arg("-y")
            .status();
        if matches!(sz_status, Ok(s) if s.success()) {
            if let Some(found) = find_file_in_dir(extract_dir, "wintun.dll") {
                return fs::copy(&found, dest).is_ok();
            }
        }
    }

    false
}

fn find_file_in_dir(dir: &PathBuf, filename: &str) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(found) = find_file_in_dir(&path, filename) {
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
