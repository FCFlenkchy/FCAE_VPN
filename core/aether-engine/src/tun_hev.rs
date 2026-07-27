//! TUN implementation using hev-socks5-tunnel as the engine
//! 
//! This module uses pre-built hev-socks5-tunnel binaries as embedded resources.
//! The library is loaded dynamically at runtime.
//! 
//! Flow: hev-socks5-tunnel (TUN) → Engine (SOCKS5 proxy) → Internet
//! 
//! The Android implementation in tun.rs remains untouched.

use std::os::raw::{c_int, c_uint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::error::{AetherError, Result};

// ============================================================================
// Dynamic FFI Bindings to hev-socks5-tunnel
// ============================================================================

// Function pointers that will be loaded dynamically
type HevMainFn = unsafe extern "C" fn(*const u8, c_uint, c_int) -> c_int;
type HevQuitFn = unsafe extern "C" fn();
type HevStatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);

// Global function pointers
static mut HEV_MAIN: Option<HevMainFn> = None;
static mut HEV_QUIT: Option<HevQuitFn> = None;
static mut HEV_STATS: Option<HevStatsFn> = None;
static LIB_LOADED: AtomicBool = AtomicBool::new(false);

/// Try to load the hev-socks5-tunnel library dynamically
fn load_hev_library() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::ffi::CString;
        
        // Try different library names
        let lib_names = [
            "libhev-socks5-tunnel.so",
            "libhev-socks5-tunnel.so.1",
            "hev-socks5-tunnel.so",
            "libhev-socks5-tunnel.a",
        ];
        
        for name in lib_names.iter() {
            let c_name = match CString::new(*name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW) };
            if !handle.is_null() {
                unsafe {
                    HEV_MAIN = Some(std::mem::transmute(
                        libc::dlsym(handle, b"hev_socks5_tunnel_main_from_str\0".as_ptr() as *const _)
                    ));
                    HEV_QUIT = Some(std::mem::transmute(
                        libc::dlsym(handle, b"hev_socks5_tunnel_quit\0".as_ptr() as *const _)
                    ));
                    HEV_STATS = Some(std::mem::transmute(
                        libc::dlsym(handle, b"hev_socks5_tunnel_stats\0".as_ptr() as *const _)
                    ));
                }
                
                // Check if functions were loaded - use unsafe to access static mut
                let loaded = unsafe {
                    HEV_MAIN.is_some() && HEV_QUIT.is_some()
                };
                if loaded {
                    LIB_LOADED.store(true, Ordering::SeqCst);
                    log::info!("[tun_hev] Loaded hev-socks5-tunnel library: {}", name);
                    return true;
                }
            }
        }
        
        log::warn!("[tun_hev] Could not load hev-socks5-tunnel library");
        false
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::ffi::CString;
        
        // Windows API functions
        #[link(name = "kernel32")]
        extern "system" {
            fn LoadLibraryA(lpFileName: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
            fn GetProcAddress(hModule: *mut std::os::raw::c_void, lpProcName: *const std::os::raw::c_char) -> *mut std::os::raw::c_void;
        }
        
        let lib_names = [
            "hev-socks5-tunnel.dll",
            "hev-socks5-tunnel",
        ];
        
        for name in lib_names.iter() {
            let c_name = match CString::new(*name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let handle = unsafe { LoadLibraryA(c_name.as_ptr()) };
            if !handle.is_null() {
                unsafe {
                    HEV_MAIN = Some(std::mem::transmute(
                        GetProcAddress(handle, b"hev_socks5_tunnel_main_from_str\0".as_ptr() as *const _)
                    ));
                    HEV_QUIT = Some(std::mem::transmute(
                        GetProcAddress(handle, b"hev_socks5_tunnel_quit\0".as_ptr() as *const _)
                    ));
                    HEV_STATS = Some(std::mem::transmute(
                        GetProcAddress(handle, b"hev_socks5_tunnel_stats\0".as_ptr() as *const _)
                    ));
                }
                
                let loaded = unsafe {
                    HEV_MAIN.is_some() && HEV_QUIT.is_some()
                };
                if loaded {
                    LIB_LOADED.store(true, Ordering::SeqCst);
                    log::info!("[tun_hev] Loaded hev-socks5-tunnel library: {}", name);
                    return true;
                }
            }
        }
        
        log::warn!("[tun_hev] Could not load hev-socks5-tunnel library");
        false
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
    {
        log::warn!("[tun_hev] Platform not supported for hev-socks5-tunnel");
        false
    }
}

// ============================================================================
// Platform-specific TUN device creation (simplified)
// ============================================================================

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::raw::c_uint;

    const TUNSETIFF: c_uint = 0x400454ca;
    const IFF_TUN: CShort = 0x0001;
    const IFF_NO_PI: CShort = 0x1000;

    type CShort = std::os::raw::c_short;

    #[repr(C)]
    struct IfReq {
        ifrn_name: [u8; 16],
        ifru_flags: CShort,
        pad: [u8; 18],
    }

    /// Create a TUN device on Linux using /dev/net/tun
    pub fn create_tun(name: &str) -> Result<RawFd> {
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| AetherError::Other(format!("Failed to open /dev/net/tun: {e}")))?;

        let fd = dev.as_raw_fd();

        let mut ifr = IfReq {
            ifrn_name: [0u8; 16],
            ifru_flags: IFF_TUN | IFF_NO_PI,
            pad: [0u8; 18],
        };

        // Copy interface name
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifrn_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe {
            libc::ioctl(fd, TUNSETIFF as u64, &ifr as *const IfReq)
        };

        if ret < 0 {
            return Err(AetherError::Other(format!(
                "ioctl TUNSETIFF failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Duplicate the fd so we can pass it to hev-socks5-tunnel
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(AetherError::Other(format!(
                "Failed to dup TUN fd: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set non-blocking
        let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL, 0) };
        if flags < 0 {
            unsafe { libc::close(dup_fd) };
            return Err(AetherError::Other(format!(
                "fcntl F_GETFL failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let ret = unsafe { libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe { libc::close(dup_fd) };
            return Err(AetherError::Other(format!(
                "fcntl F_SETFL failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        log::info!("[tun_hev] Linux TUN device '{}' created (fd={})", name, dup_fd);
        Ok(dup_fd)
    }

    /// Configure TUN interface (bring up, assign IP)
    pub fn configure_tun(fd: RawFd, ipv4: &str, ipv6: Option<&str>) -> Result<()> {
        use std::process::Command;

        // Get interface name from fd
        let ifr = IfReq {
            ifrn_name: [0u8; 16],
            ifru_flags: 0,
            pad: [0u8; 18],
        };
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF as u64, &ifr as *const IfReq) };
        if ret < 0 {
            log::warn!("[tun_hev] Failed to get interface name from fd");
            return Err(AetherError::Other("Failed to get interface name".into()));
        }
        let name = String::from_utf8_lossy(&ifr.ifrn_name)
            .trim_matches('\0')
            .to_string();

        log::info!("[tun_hev] Configuring interface '{}' with IP {}", name, ipv4);

        // Bring interface up and assign IP
        let status = Command::new("ip")
            .args(["addr", "add", ipv4, "dev", &name])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::warn!("[tun_hev] Failed to assign IPv4 to {}: {:?}", name, status);
            }
        }

        if let Some(ipv6_addr) = ipv6 {
            let status = Command::new("ip")
                .args(["-6", "addr", "add", ipv6_addr, "dev", &name])
                .status();
            if let Ok(status) = status {
                if !status.success() {
                    log::warn!("[tun_hev] Failed to assign IPv6 to {}: {:?}", name, status);
                }
            }
        }

        let status = Command::new("ip")
            .args(["link", "set", &name, "up"])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::warn!("[tun_hev] Failed to bring up {}: {:?}", name, status);
            }
        }

        // Disable reverse path filter
        let status = Command::new("sysctl")
            .args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", name)])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::debug!("[tun_hev] Failed to disable rp_filter for {}", name);
            }
        }

        Ok(())
    }

    pub fn cleanup_tun(fd: RawFd) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
            log::debug!("[tun_hev] Closed TUN fd {}", fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    use std::os::raw::c_int;

    pub fn create_tun(_name: &str) -> Result<c_int> {
        Err(AetherError::Other(
            format!(
                "TUN not supported on this platform: {}",
                std::env::consts::OS
            )
        ))
    }

    pub fn configure_tun(_fd: c_int, _ipv4: &str, _ipv6: Option<&str>) -> Result<()> {
        Err(AetherError::Other("TUN not supported on this platform".into()))
    }

    pub fn cleanup_tun(_fd: c_int) {}
}

// ============================================================================
// Public API
// ============================================================================

/// Configuration for the TUN device
#[derive(Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u32,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub socks_port: u16,
    pub socks_host: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "aether-tun0".to_string(),
            mtu: 1500,
            ipv4: "198.18.0.1/24".to_string(),
            ipv6: None,
            socks_port: 1080,
            socks_host: "127.0.0.1".to_string(),
            username: None,
            password: None,
        }
    }
}

/// Build hev-socks5-tunnel YAML configuration string
fn build_hev_config(cfg: &TunConfig) -> String {
    let mut yaml = format!(
        r#"tunnel:
  name: {}
  mtu: {}
  multi-queue: false
  ipv4: {}
  icmp: 'off'

socks5:
  port: {}
  address: {}
  udp: 'udp'
"#,
        cfg.name, cfg.mtu, cfg.ipv4, cfg.socks_port, cfg.socks_host
    );

    if let Some(ipv6) = &cfg.ipv6 {
        yaml.push_str(&format!("  ipv6: '{}'\n", ipv6));
    }

    if let Some(username) = &cfg.username {
        yaml.push_str(&format!("  username: '{}'\n", username));
    }

    if let Some(password) = &cfg.password {
        yaml.push_str(&format!("  password: '{}'\n", password));
    }

    yaml
}

/// Run the TUN with hev-socks5-tunnel
pub async fn run_hev_tun(cfg: TunConfig, shutdown: oneshot::Receiver<()>) -> Result<()> {
    log::info!("[tun_hev] Starting TUN with hev-socks5-tunnel");
    log::info!("[tun_hev] Config: name={}, ipv4={}, socks={}:{}",
        cfg.name, cfg.ipv4, cfg.socks_host, cfg.socks_port
    );

    // Try to load the hev library
    if !load_hev_library() {
        return Err(AetherError::Other(
            "hev-socks5-tunnel library not available. Please install the library.".into()
        ));
    }

    // Create TUN device
    let tun_fd = platform::create_tun(&cfg.name)?;

    // Configure TUN interface
    if let Err(e) = platform::configure_tun(tun_fd, &cfg.ipv4, cfg.ipv6.as_deref()) {
        log::warn!("[tun_hev] Failed to configure TUN: {}", e);
    }

    // Build config
    let config_yaml = build_hev_config(&cfg);
    log::debug!("[tun_hev] hev-socks5-tunnel config:\n{}", config_yaml);

    let config_bytes = config_yaml.into_bytes();
    let fd = tun_fd;

    // Launch hev-socks5-tunnel in a blocking thread
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Get function pointers
    let hev_main = unsafe {
        HEV_MAIN.ok_or_else(|| AetherError::Other("hev_main function not loaded".into()))?
    };
    let hev_quit = unsafe {
        HEV_QUIT.ok_or_else(|| AetherError::Other("hev_quit function not loaded".into()))?
    };

    let handle = tokio::task::spawn_blocking(move || {
        let result = unsafe {
            hev_main(
                config_bytes.as_ptr(),
                config_bytes.len() as u32,
                fd,
            )
        };
        running_clone.store(false, Ordering::SeqCst);
        result
    });

    // Pin the handle
    tokio::pin!(handle);

    // Wait for shutdown signal or tunnel exit
    tokio::select! {
        _ = shutdown => {
            log::info!("[tun_hev] Shutting down hev-socks5-tunnel");
            unsafe { hev_quit(); }
            let _ = handle.await;
        }
        result = &mut handle => {
            match result {
                Ok(0) => {
                    log::info!("[tun_hev] hev-socks5-tunnel exited normally");
                }
                Ok(code) => {
                    log::warn!("[tun_hev] hev-socks5-tunnel exited with code {}", code);
                    return Err(AetherError::Other(format!(
                        "hev-socks5-tunnel exited with code {}", code
                    )));
                }
                Err(e) => {
                    log::error!("[tun_hev] hev-socks5-tunnel task failed: {}", e);
                    return Err(AetherError::Other(format!(
                        "hev-socks5-tunnel task failed: {}", e
                    )));
                }
            }
        }
    }

    // Cleanup
    platform::cleanup_tun(tun_fd);
    log::info!("[tun_hev] TUN shut down");
    Ok(())
}

/// Check if hev-socks5-tunnel library is available
pub fn is_available() -> bool {
    // Try to load the library if not already loaded
    let loaded = LIB_LOADED.load(Ordering::SeqCst);
    if !loaded {
        return load_hev_library();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_config() {
        let cfg = TunConfig {
            name: "test-tun".to_string(),
            mtu: 1400,
            ipv4: "10.0.0.1/24".to_string(),
            ipv6: Some("fe80::1/64".to_string()),
            socks_port: 1080,
            socks_host: "127.0.0.1".to_string(),
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
        };

        let yaml = build_hev_config(&cfg);
        assert!(yaml.contains("name: test-tun"));
        assert!(yaml.contains("mtu: 1400"));
        assert!(yaml.contains("ipv4: 10.0.0.1/24"));
        assert!(yaml.contains("ipv6: 'fe80::1/64'"));
        assert!(yaml.contains("port: 1080"));
        assert!(yaml.contains("address: 127.0.0.1"));
        assert!(yaml.contains("username: 'testuser'"));
        assert!(yaml.contains("password: 'testpass'"));
    }
}
