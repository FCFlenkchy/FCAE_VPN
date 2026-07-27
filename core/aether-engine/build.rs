// Build script for aether-engine
// 
// For hev-socks5-tunnel, we use pre-built binaries as embedded resources
// rather than compiling from source. This avoids build dependencies like libevent.

use std::env;

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
        println!("cargo:warning=Using embedded hev-socks5-tunnel resources (pre-built binaries)");
        println!("cargo:warning=Runtime loading will check for available binaries");
    }
}
