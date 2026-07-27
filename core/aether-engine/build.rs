// Build script for aether-engine
// This compiles hev-socks5-tunnel as a static library and links it

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build hev-socks5-tunnel on non-Android platforms
    #[cfg(not(target_os = "android"))]
    {
        build_hev_socks5_tunnel();
    }
    
    #[cfg(target_os = "android")]
    {
        // On Android, we don't build hev-socks5-tunnel
        // The Android implementation uses the existing tun.rs
        println!("cargo:warning=Android build: skipping hev-socks5-tunnel compilation");
    }
}

#[cfg(not(target_os = "android"))]
fn build_hev_socks5_tunnel() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = PathBuf::from(&manifest_dir);
    let workspace_root = manifest_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf(); // core/aether-engine -> core -> FCAE-VPN
    
    let hev_src = workspace_root.join("hev-socks5-tunnel");
    
    if !hev_src.exists() {
        println!("cargo:warning=hev-socks5-tunnel source not found at {:?}", hev_src);
        println!("cargo:warning=Please ensure the submodule is initialized: git submodule update --init");
        return;
    }
    
    let out_dir = env::var("OUT_DIR").unwrap();
    let build_dir = PathBuf::from(&out_dir).join("hev-socks5-tunnel-build");
    
    // Create build directory if it doesn't exist
    if !build_dir.exists() {
        std::fs::create_dir_all(&build_dir).unwrap();
    }
    
    // Determine the target OS
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    
    // Build static library - don't fail if it doesn't build
    let status = Command::new("make")
        .current_dir(&hev_src)
        .arg("static")
        .env("BUILD_DIR", build_dir.as_os_str())
        .status();
    
    if let Ok(status) = status {
        if !status.success() {
            println!("cargo:warning=Failed to build hev-socks5-tunnel static library");
            println!("cargo:warning=Make sure you have the required build dependencies:");
            println!("cargo:warning=  - make, gcc/clang");
            println!("cargo:warning=  - libevent development headers");
            println!("cargo:warning=  - For Linux: libevent-dev");
            println!("cargo:warning=  - For Windows: MSYS2 or WSL");
            println!("cargo:warning=hev-socks5-tunnel will be disabled");
            return;
        }
    } else {
        println!("cargo:warning=Failed to execute make for hev-socks5-tunnel");
        println!("cargo:warning=hev-socks5-tunnel will be disabled");
        return;
    }
    
    // Link the static library
    let lib_name = if target_os == "windows" {
        "hev-socks5-tunnel"
    } else {
        "hev-socks5-tunnel"
    };
    
    // Find the library file
    let lib_path = build_dir.join("lib");
    let lib_file = if target_os == "windows" {
        lib_path.join("hev-socks5-tunnel.lib")
    } else {
        lib_path.join("libhev-socks5-tunnel.a")
    };
    
    if lib_file.exists() {
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=static={}", lib_name);
        println!("cargo:warning=Linked hev-socks5-tunnel static library from {:?}", lib_file);
    } else {
        println!("cargo:warning=hev-socks5-tunnel library not found at {:?}", lib_file);
        println!("cargo:warning=The TUN feature may not work correctly");
    }
    
    // Additional system libraries needed
    #[cfg(target_os = "linux")]
    {
        // Linux needs these system libraries
        println!("cargo:rustc-link-lib=event");
        println!("cargo:rustc-link-lib=event_core");
        println!("cargo:rustc-link-lib=event_extra");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }
    
    #[cfg(target_os = "windows")]
    {
        // Windows needs these libraries
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=userenv");
    }
    
    // Tell cargo to rerun this build script if the hev source changes
    println!("cargo:rerun-if-changed={}", hev_src.display());
    println!("cargo:rerun-if-changed={}/Makefile", hev_src.display());
    println!("cargo:rerun-if-changed={}/src", hev_src.display());
    
    // Include directories
    let hev_include = hev_src.join("include");
    if hev_include.exists() {
        println!("cargo:rustc-cfg=hev_tun_available");
        // The include path is passed via the compiler wrapper
        // or we can use cxx or bindgen
    }
}
