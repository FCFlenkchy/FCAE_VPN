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

    // At this point we're building for Windows or Linux.
    // The cfg flag will be set ONLY if the binary is actually built/available.

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
                "hev-socks5-tunnel not found at {}!\
\
                 Clone it into the repo root:\
\
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
                if s.is_ok() && s.unwrap().success() {
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

        // Remove any stale dummy/empty file from previous failed builds
        if bin_path.exists() {
            if let Ok(meta) = fs::metadata(&bin_path) {
                if meta.len() == 0 {
                    let _ = fs::remove_file(&bin_path);
                }
            }
        }

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
            let mut prebuilt_valid = false;
            if prebuilt_path.exists() {
                // Validate the pre-built binary before using it
                let pe_ok = if target_os == "windows" {
                    is_valid_pe(&prebuilt_path)
                } else {
                    true // On Linux, no PE check needed
                };
                if pe_ok {
                    println!(
                        "cargo:warning=Copying pre-built hev-socks5-tunnel from: {}",
                        prebuilt_path.display()
                    );
                    match fs::copy(&prebuilt_path, &bin_path) {
                        Ok(_) => {
                            println!("cargo:warning=hev-socks5-tunnel copied successfully");
                            prebuilt_valid = true;
                        }
                        Err(e) => {
                            println!("cargo:warning=Failed to copy pre-built binary: {e}");
                        }
                    }
                } else {
                    println!("cargo:warning=Pre-built binary is NOT a valid Windows PE — ignoring");
                }
            }

            if !prebuilt_valid {
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
                    // Build produced no binary. Try the pre-built fallback one more time
                    // but only if it's a valid binary.
                    if prebuilt_path.exists() {
                        let pe_ok = if target_os == "windows" {
                            is_valid_pe(&prebuilt_path)
                        } else {
                            true
                        };
                        if pe_ok {
                            println!(
                                "cargo:warning=Build failed, falling back to pre-built: {}",
                                prebuilt_path.display()
                            );
                            let _ = fs::copy(&prebuilt_path, &bin_path);
                        } else {
                            println!("cargo:warning=Build failed and pre-built binary is invalid — skipping");
                        }
                    } else {
                        // Build failed and no pre-built fallback.
                        // Skip embedding — the Rust TUN implementation will be used instead.
                        println!("cargo:warning=hev-socks5-tunnel build failed. The Rust TUN implementation will be used instead.");
                        println!("cargo:warning=To enable C tunnel: build hev-socks5-tunnel manually and place it in target/release/{}", bin_name);
                    }
                }
            }
        }

        // Only set cfg and embed if the binary actually exists, is non-empty,
        // and (for Windows targets) is a valid PE executable.
        let mut valid_binary = false;
        if bin_path.exists() {
            if let Ok(meta) = fs::metadata(&bin_path) {
                if meta.len() > 0 {
                    // On Windows target, validate the binary is a real PE
                    if target_os == "windows" && !is_valid_pe(&bin_path) {
                        println!("cargo:warning=hev-socks5-tunnel binary is NOT a valid Windows PE — discarding and using Rust TUN fallback");
                        let _ = fs::remove_file(&bin_path);
                    } else {
                        valid_binary = true;
                    }
                } else {
                    println!("cargo:warning=hev-socks5-tunnel binary is empty — skipping embed");
                    let _ = fs::remove_file(&bin_path);
                }
            }
        }

        if valid_binary {
            println!("cargo:rustc-cfg=hevsocks5_available");
            println!("cargo:rustc-env=HEVSOCKS5_EMBEDDED={}", bin_path.display());
            println!(
                "cargo:warning=hev-socks5-tunnel embedded at: {}",
                bin_path.display()
            );
        } else {
            println!("cargo:warning=hev-socks5-tunnel not available — Rust TUN will be used");
        }

        // ── Windows: embed wintun.dll ───────────────────────────────────
        if target_os == "windows" {
            embed_wintun_dll(&hev_src, &out_dir);
        }
    }
}

// ── Build: Linux ──────────────────────────────────────────────────────

fn build_hev_linux(src: &PathBuf, dest: &PathBuf, _out_dir: &str) {
    let build_dir = src.join("build");
    fs::create_dir_all(&build_dir).expect("Failed to create build dir");

    // cmake configure
    let status = Command::new("cmake")
        .args(["..", "-DCMAKE_BUILD_TYPE=Release"])
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run cmake");
    if !status.success() {
        println!("cargo:warning=cmake configure failed — skipping hev-socks5-tunnel build");
        let _ = fs::remove_dir_all(build_dir);
        return;
    }

    // Use cmake --build (more portable than raw make)
    let status = Command::new("cmake")
        .args(["--build", ".", "--config", "Release", "-j", &num_cpus().to_string()])
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run cmake --build");
    if !status.success() {
        // Fallback: try raw make
        println!("cargo:warning=cmake --build failed, trying make directly...");
        let status = Command::new("make")
            .args(["-j", &num_cpus().to_string()])
            .current_dir(&build_dir)
            .status()
            .expect("Failed to run make");
        if !status.success() {
            // Build failed — don't panic. The Rust binary may still work without the C tunnel.
            println!("cargo:warning=hev-socks5-tunnel build failed. Rust TUN will be used instead.");
            let _ = fs::remove_dir_all(build_dir);
            return;
        }
    }

    // Find the built binary (search multiple possible locations)
    let candidates = [
        build_dir.join("hev-socks5-tunnel"),
        build_dir.join("src").join("hev-socks5-tunnel"),
        build_dir.join("Release").join("hev-socks5-tunnel"),
    ];
    copy_built_binary(&candidates, dest);

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
                // Don't create an empty stub. Just return — the caller handles missing binary.
            }
        }
    } else {
        // Native Windows build — use default cmake
        build_hev_windows_native(src, dest, &build_dir);
    }
}

/// Cross-compile from Linux to Windows using MinGW
fn build_hev_windows_cross(
    _src: &PathBuf,
    dest: &PathBuf,
    cc: &str,
    build_dir: &PathBuf,
) {
    fs::create_dir_all(build_dir).expect("Failed to create build dir");

    // Extract the cross-compiler prefix (e.g., "x86_64-w64-mingw32-" from "x86_64-w64-mingw32-gcc")
    let cross_prefix = cc.trim_end_matches("gcc");
    let cross_gpp = format!("{cross_prefix}g++");
    let cross_ar = format!("{cross_prefix}ar");
    let cross_ranlib = format!("{cross_prefix}ranlib");
    let cross_dlltool = format!("{cross_prefix}dlltool");
    let cross_windres = format!("{cross_prefix}windres");

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

    // ── Find the MinGW sysroot (includes + libs) ────────────────────────
    // MinGW-w64 on Linux CI runners installs to /usr/x86_64-w64-mingw32/
    // but the compiler doesn't always auto-detect its sysroot.
    // We locate it by asking gcc for its search paths.
    let mut mingw_sysroot = String::new();
    let mut mingw_include = String::new();
    let mut mingw_lib = String::new();

    // Try to extract sysroot from gcc's built-in search paths
    if let Ok(output) = Command::new(cc)
        .args(["-print-sysroot"])
        .output()
    {
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sysroot.is_empty() && std::path::PathBuf::from(&sysroot).exists() {
            mingw_sysroot = sysroot;
            mingw_include = format!("{}/include", mingw_sysroot);
            mingw_lib = format!("{}/lib", mingw_sysroot);
            println!("cargo:warning=MinGW sysroot (from gcc): {}", mingw_sysroot);
        }
    }

    // If gcc didn't report a sysroot, search common locations.
    // Must verify BOTH include/winsock2.h AND lib/libws2_32.a exist.
    if mingw_sysroot.is_empty() {
        let sysroot_candidates: &[(&str, &[&str])] = &[
            // (prefix path, possible lib subdirectories)
            (&"/usr/x86_64-w64-mingw32", &["lib"] as &[&str]),
            (&"/usr/share/mingw-w64", &["lib", "../x86_64-w64-mingw32/lib"]),
        ];
        for (candidate, lib_subdirs) in sysroot_candidates {
            let include_path = std::path::PathBuf::from(candidate).join("include");
            if !include_path.join("winsock2.h").exists() {
                continue;
            }
            // Find a valid lib directory
            let mut found_lib = String::new();
            for subdir in *lib_subdirs {
                let lib_path = std::path::PathBuf::from(candidate).join(subdir);
                if lib_path.join("libws2_32.a").exists() || lib_path.join("libws2_32.dll.a").exists() {
                    found_lib = lib_path.to_string_lossy().to_string();
                    break;
                }
            }
            // Also check if lib is at /usr/x86_64-w64-mingw32/lib while headers are elsewhere
            if found_lib.is_empty() {
                let alt_lib = std::path::PathBuf::from("/usr/x86_64-w64-mingw32/lib");
                if alt_lib.join("libws2_32.a").exists() || alt_lib.join("libws2_32.dll.a").exists() {
                    found_lib = alt_lib.to_string_lossy().to_string();
                }
            }
            if !found_lib.is_empty() {
                mingw_sysroot = candidate.to_string();
                mingw_include = include_path.to_string_lossy().to_string();
                mingw_lib = found_lib;
                println!("cargo:warning=MinGW sysroot (found): sysroot={}, lib={}", mingw_sysroot, mingw_lib);
                break;
            }
        }
    }

    // Also search for the mingw CRT includes (stddef.h, stdarg.h, etc.)
    // which are in a gcc-version-specific directory
    let mut gcc_include = String::new();
    if let Ok(output) = Command::new(cc)
        .args(["-E", "-x", "c", "-", "-v"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Parse the "#include <...> search starts here:" section
        let mut in_search_list = false;
        for line in stderr.lines() {
            if line.contains("search starts here") {
                in_search_list = true;
                continue;
            }
            if in_search_list && line.contains("End of search list") {
                break;
            }
            if in_search_list {
                let path = line.trim();
                // Look for a gcc-version-specific include dir
                if path.contains("/lib/gcc/") && path.ends_with("/include") {
                    gcc_include = path.to_string();
                    break;
                }
            }
        }
    }

    // If we still couldn't find the sysroot, try additional candidate paths
    if mingw_sysroot.is_empty() {
        // Brute-force search common locations for winsock2.h AND libws2_32.a
        let include_candidates = [
            "/usr/x86_64-w64-mingw32/include",
            "/usr/share/mingw-w64/include",
        ];
        let lib_candidates = [
            "/usr/x86_64-w64-mingw32/lib",
        ];
        for inc in &include_candidates {
            let test_path = std::path::PathBuf::from(inc).join("winsock2.h");
            if test_path.exists() {
                mingw_include = inc.to_string();
                break;
            }
        }
        for lib in &lib_candidates {
            let lib_path = std::path::PathBuf::from(lib);
            if lib_path.join("libws2_32.a").exists() || lib_path.join("libws2_32.dll.a").exists() {
                mingw_lib = lib.to_string();
                break;
            }
        }
        if !mingw_include.is_empty() && !mingw_lib.is_empty() {
            mingw_sysroot = mingw_include.trim_end_matches("/include").to_string();
            println!("cargo:warning=MinGW headers found at: {}, lib at: {}", mingw_include, mingw_lib);
        }
    }

    // Build the full include flags: sysroot include + gcc built-in includes
    let mut extra_cflags = String::new();
    if !mingw_include.is_empty() {
        extra_cflags.push_str(&format!("-I{}", mingw_include));
    }
    if !gcc_include.is_empty() {
        extra_cflags.push_str(&format!(" -I{}", gcc_include));
    }

    // Build library search path flags
    let mut extra_ldflags = String::new();
    if !mingw_lib.is_empty() {
        extra_ldflags.push_str(&format!("-L{}", mingw_lib));
    }

    // ── Verify the toolchain works: try compiling a real Windows program ──
    let test_c = build_dir.join("_cross_test.c");
    let test_exe = build_dir.join("_cross_test.exe");
    let _ = fs::write(&test_c, r#"#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    WSACleanup();
    return 0;
}
"#);
    let mut test_cmd = Command::new(cc);
    test_cmd.args([test_c.to_str().unwrap_or(""), "-o", test_exe.to_str().unwrap_or("")]);
    if !extra_cflags.is_empty() {
        test_cmd.arg(&extra_cflags);
    }
    if !extra_ldflags.is_empty() {
        test_cmd.arg(&extra_ldflags);
    }
    test_cmd.arg("-lws2_32").arg("-static");
    let test_ok = test_cmd.status().map(|s| s.success()).unwrap_or(false);

    // Verify the output is a valid PE
    let pe_ok = if test_ok && test_exe.exists() {
        is_valid_pe(&test_exe)
    } else {
        false
    };

    // Clean up test artifacts
    let _ = fs::remove_file(&test_c);
    let _ = fs::remove_file(&test_exe);

    if !test_ok || !pe_ok {
        println!("cargo:warning=MinGW cross-compiler failed to produce a valid Windows PE binary.");
        println!("cargo:warning=Install full MinGW-w64: sudo apt-get install mingw-w64 g++-mingw-w64-x86-64");
        println!("cargo:warning=hev-socks5-tunnel not built (cross-compiler broken).");
        let _ = fs::remove_dir_all(build_dir);
        return;
    }
    println!("cargo:warning=MinGW cross-compiler verified — produces valid Windows PE");

    // ── Create a robust toolchain file ───────────────────────────────────
    // The key difference from the broken approach: we do NOT set
    // CMAKE_C_COMPILER_WORKS=1 which bypasses all detection.
    // Instead, we provide enough information for CMake's detection to succeed.
    let toolchain_file = build_dir.join("toolchain.cmake");
    let mut toolchain = String::new();
    toolchain.push_str(&format!(
        r#"# Cross-compilation toolchain for Windows via MinGW-w64
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER {cc})
set(CMAKE_CXX_COMPILER {cross_gpp})
"#
    ));

    // Set sysroot if we found one
    if !mingw_sysroot.is_empty() {
        toolchain.push_str(&format!("set(CMAKE_SYSROOT {mingw_sysroot})\n"));
        toolchain.push_str(&format!("set(CMAKE_FIND_ROOT_PATH {mingw_sysroot})\n"));
    }

    // Set cross-tools explicitly
    if cmd_exists(&cross_ar) {
        toolchain.push_str(&format!("set(CMAKE_AR {cross_ar})\n"));
    }
    if cmd_exists(&cross_ranlib) {
        toolchain.push_str(&format!("set(CMAKE_RANLIB {cross_ranlib})\n"));
    }
    if cmd_exists(&cross_dlltool) {
        toolchain.push_str(&format!("set(CMAKE_DLLTOOL {cross_dlltool})\n"));
    }
    if cmd_exists(&cross_windres) {
        toolchain.push_str(&format!("set(CMAKE_RC_COMPILER {cross_windres})\n"));
    }

    // Use the cross gcc also as assembler (for .s files in hev-task-system)
    toolchain.push_str(&format!(
        r#"set(CMAKE_ASM_COMPILER {cc})
"#
    ));

    // Set find mode to ONLY search in the sysroot (cross-compilation safety)
    toolchain.push_str(r#"set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
"#);

    // Add C flags: static link, include paths, define WIN32
    let mut cflags = "-static -DWIN32 -D_WIN32 -D__MSYS__".to_string();
    if !extra_cflags.is_empty() {
        cflags.push_str(&format!(" {}", extra_cflags));
    }
    toolchain.push_str(&format!("set(CMAKE_C_FLAGS_INIT \"{cflags}\")\n"));

    // Add linker flags
    let mut ldflags = "-static -lws2_32 -liphlpapi".to_string();
    if !extra_ldflags.is_empty() {
        ldflags.push_str(&format!(" {}", extra_ldflags));
    }
    toolchain.push_str(&format!("set(CMAKE_EXE_LINKER_FLAGS_INIT \"{ldflags}\")\n"));

    let _ = fs::write(&toolchain_file, &toolchain);
    println!("cargo:warning=Toolchain file written with sysroot={mingw_sysroot}");

    // ── Run cmake configure ─────────────────────────────────────────────
    let cmake_args: Vec<String> = vec![
        "..".to_string(),
        format!("-DCMAKE_TOOLCHAIN_FILE={}", toolchain_file.display()),
        "-DCMAKE_BUILD_TYPE=Release".to_string(),
    ];
    let cmake_args_refs: Vec<&str> = cmake_args.iter().map(|s| s.as_str()).collect();

    let status = Command::new("cmake")
        .args(&cmake_args_refs)
        .current_dir(build_dir)
        .status();
    match status {
        Ok(s) if s.success() => {},
        Ok(s) => {
            println!("cargo:warning=cmake configure failed with exit {:?} — skipping hev-socks5-tunnel build", s.code());
            let _ = fs::remove_dir_all(build_dir);
            return;
        }
        Err(e) => {
            println!("cargo:warning=Failed to run cmake: {e} — skipping hev-socks5-tunnel build");
            let _ = fs::remove_dir_all(build_dir);
            return;
        }
    }

    // ── Build using cmake --build (do NOT fallback to raw make) ──────────
    let status = Command::new("cmake")
        .args(["--build", ".", "--config", "Release", "-j", &num_cpus().to_string()])
        .current_dir(build_dir)
        .status();

    let build_ok = match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            println!("cargo:warning=cmake --build failed with exit {:?}", s.code());
            false
        }
        Err(e) => {
            println!("cargo:warning=cmake --build error: {e}");
            false
        }
    };

    if !build_ok {
        // Cross-compilation failed. Clean up and return.
        println!("cargo:warning=Cross-compilation of hev-socks5-tunnel failed.");
        println!("cargo:warning=Install full MinGW-w64: sudo apt-get install mingw-w64 g++-mingw-w64-x86-64");
        let _ = fs::remove_dir_all(build_dir);
        return;
    }

    // ── Find the built binary ───────────────────────────────────────────
    let candidates = [
        build_dir.join("hev-socks5-tunnel.exe"),
        build_dir.join("hev-socks5-tunnel"),
        build_dir.join("Release").join("hev-socks5-tunnel.exe"),
        build_dir.join("src").join("hev-socks5-tunnel.exe"),
    ];

    // Find the first existing candidate
    let mut found_binary: Option<PathBuf> = None;
    for c in &candidates {
        if c.exists() {
            if let Ok(meta) = fs::metadata(c) {
                if meta.len() > 0 {
                    found_binary = Some(c.clone());
                    break;
                }
            }
        }
    }

    match found_binary {
        Some(ref built) => {
            // Validate it's a real Windows PE before copying
            if !is_valid_pe(built) {
                println!("cargo:warning=Built binary is NOT a valid Windows PE — discarding");
                println!("cargo:warning=Cross-compilation produced an invalid binary (likely host ELF).");
                let _ = fs::remove_dir_all(build_dir);
                return;
            }
            fs::copy(built, dest)
                .unwrap_or_else(|e| panic!("Failed to copy {} to {}: {e}", built.display(), dest.display()));
            println!("cargo:warning=hev-socks5-tunnel cross-compiled successfully (valid PE)");
        }
        None => {
            println!("cargo:warning=hev-socks5-tunnel built but binary not found. Searched: {:?}", candidates);
            let _ = fs::remove_dir_all(build_dir);
        }
    }
}

/// Check if a file is a valid Windows PE (Portable Executable) binary.
/// PE files start with "MZ" magic bytes.
fn is_valid_pe(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    match fs::read(path) {
        Ok(bytes) if bytes.len() >= 2 => {
            // PE files start with MZ (0x4D 0x5A)
            bytes[0] == 0x4D && bytes[1] == 0x5A
        }
        _ => false,
    }
}

/// Native Windows build (MSVC or MinGW on Windows host)
fn build_hev_windows_native(_src: &PathBuf, dest: &PathBuf, build_dir: &PathBuf) {
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

    // Build using cmake --build (portable) or mingw32-make
    if use_mingw {
        let status = Command::new("mingw32-make")
            .args(["-j", &num_cpus().to_string()])
            .current_dir(build_dir)
            .status()
            .expect("Failed to run mingw32-make");
        if !status.success() {
            panic!("mingw32-make failed with exit: {:?}", status.code());
        }
    } else {
        let status = Command::new("cmake")
            .args(["--build", ".", "--config", "Release", "-j", &num_cpus().to_string()])
            .current_dir(build_dir)
            .status()
            .expect("Failed to run cmake --build");
        if !status.success() {
            // Fallback: try raw make if cmake --build fails
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
