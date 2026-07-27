// Build script for aether-engine
// 
// For hev-socks5-tunnel, we embed the pre-built binary as a resource
// at build time. The binary is copied from the workspace.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Declare the hev_tun_available cfg option
    println!("cargo::rustc-check-cfg=cfg(hev_tun_available)");
    
    // We always mark hev_tun_available as true since we use embedded binaries
    // The actual availability will be checked at runtime
    println!("cargo:rustc-cfg=hev_tun_available");
    
    #[cfg(target_os = "android")]
    {
        // On Android, we don't use hev-socks5-tunnel
        // The Android implementation uses the existing tun.rs
        println!("cargo:warning=Android build: hev-socks5-tunnel not used (uses tun.rs)");
    }
    
    #[cfg(not(target_os = "android"))]
    {
        // Check if hev-socks5-tunnel binary exists in the workspace
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_path = PathBuf::from(&manifest_dir);
        
        // Try to find hev-socks5-tunnel binary
        let workspace_root = manifest_path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(&manifest_path);
        
        let hev_src = workspace_root.join("hev-socks5-tunnel");
        
        // Determine the library name based on platform
        #[cfg(target_os = "windows")]
        let lib_name = "hev-socks5-tunnel.dll";
        #[cfg(target_os = "linux")]
        let lib_name = "libhev-socks5-tunnel.so";
        #[cfg(target_os = "macos")]
        let lib_name = "libhev-socks5-tunnel.dylib";
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        let lib_name = "";
        
        // Check if the library exists in the workspace
        let lib_paths = [
            workspace_root.join("target/release").join(lib_name),
            workspace_root.join("target/debug").join(lib_name),
            workspace_root.join(lib_name),
            hev_src.join(lib_name),
            hev_src.join("src").join(lib_name),
        ];
        
        let found_path = lib_paths.iter().find(|p| p.exists());
        
        if let Some(path) = found_path {
            println!("cargo:warning=hev-socks5-tunnel library found at: {}", path.display());
            
            // Copy the library to the output directory so it can be embedded
            let out_dir = env::var("OUT_DIR").unwrap();
            let dest_path = PathBuf::from(&out_dir).join(lib_name);
            
            if let Err(e) = fs::copy(path, &dest_path) {
                println!("cargo:warning=Failed to copy hev-socks5-tunnel library: {}", e);
            } else {
                println!("cargo:warning=Copied hev-socks5-tunnel library to output directory");
                // Tell cargo to include this file
                println!("cargo:rustc-env=HEV_LIB_PATH={}", dest_path.display());
                
                // Also copy to the target directory where the executable will be
                let target_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
                    .parent().unwrap().parent().unwrap()
                    .join("target/release");
                if let Err(e) = fs::copy(path, target_dir.join(lib_name)) {
                    println!("cargo:warning=Failed to copy to target/release: {}", e);
                } else {
                    println!("cargo:warning=Also copied to target/release/");
                }
            }
        } else {
            println!("cargo:warning=hev-socks5-tunnel library not found in workspace");
            println!("cargo:warning=Please build it with: scripts/build-hev-library.sh");
            println!("cargo:warning=or for Windows: scripts/embed-hev-resources.ps1");
            println!("cargo:warning=TUN feature will be disabled at runtime");
        }
    }
}
