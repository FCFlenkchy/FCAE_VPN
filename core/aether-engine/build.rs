// Build script for aether-engine
// 
// For tun2socks (https://github.com/xjasonlyu/tun2socks),
// we check for the binary at build time and set env vars.
// The binary is downloaded/installed separately.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Declare the tun2socks_available cfg option
    println!("cargo::rustc-check-cfg=cfg(tun2socks_available)");
    
    // We always mark tun2socks_available as true since we check at runtime
    println!("cargo:rustc-cfg=tun2socks_available");
    
    #[cfg(target_os = "android")]
    {
        // On Android, we don't use tun2socks
        // The Android implementation uses the existing tun.rs
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
        
        // Determine the binary name based on platform
        #[cfg(target_os = "windows")]
        let bin_name = "tun2socks.exe";
        #[cfg(not(target_os = "windows"))]
        let bin_name = "tun2socks";
        
        // Check if the binary exists in common locations
        let bin_paths = [
            workspace_root.join("target/release").join(bin_name),
            workspace_root.join("target/debug").join(bin_name),
            workspace_root.join(bin_name),
            workspace_root.join("tun2socks").join(bin_name),
            manifest_path.join(bin_name),
        ];
        
        let found_path = bin_paths.iter().find(|p| p.exists());
        
        if let Some(path) = found_path {
            println!("cargo:warning=tun2socks binary found at: {}", path.display());
            println!("cargo:rustc-env=TUN2SOCKS_PATH={}", path.display());
            
            // Copy the binary to the output directory
            let out_dir = env::var("OUT_DIR").unwrap();
            let dest_path = PathBuf::from(&out_dir).join(bin_name);
            
            if let Err(e) = fs::copy(path, &dest_path) {
                println!("cargo:warning=Failed to copy tun2socks binary: {}", e);
            } else {
                println!("cargo:warning=Copied tun2socks binary to output directory");
            }
            
            // Also copy to the target directory where the executable will be
            let target_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
                .parent().unwrap().parent().unwrap()
                .join("target/release");
            if let Err(e) = fs::copy(path, target_dir.join(bin_name)) {
                println!("cargo:warning=Failed to copy to target/release: {}", e);
            } else {
                println!("cargo:warning=Also copied to target/release/");
            }
        } else {
            println!("cargo:warning=tun2socks binary not found in workspace");
            println!("cargo:warning=Install it from: https://github.com/xjasonlyu/tun2socks");
            println!("cargo:warning=Or set TUN2SOCKS_BIN env var at runtime");
        }
    }
}
