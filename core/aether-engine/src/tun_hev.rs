//! TUN implementation using hev-socks5-tunnel as the engine
//! 
//! This module provides platform-specific TUN device creation and management
//! for Windows and Linux, using the hev-socks5-tunnel C library to handle
//! the TUN-to-SOCKS5 proxying.
//! 
//! Flow: hev-socks5-tunnel (TUN) → Engine (SOCKS5 proxy) → Internet
//! 
//! The Android implementation in tun.rs remains untouched.

use std::os::raw::{c_char, c_int, c_uint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

use crate::error::{AetherError, Result};

// ============================================================================
// FFI Bindings to hev-socks5-tunnel
// ============================================================================

#[link(name = "hev-socks5-tunnel")]
extern "C" {
    /// Start the socks5 tunnel with a config file
    fn hev_socks5_tunnel_main_from_file(
        config_path: *const c_char,
        tun_fd: c_int,
    ) -> c_int;

    /// Start the socks5 tunnel with a config string (YAML)
    fn hev_socks5_tunnel_main_from_str(
        config_str: *const u8,
        config_len: c_uint,
        tun_fd: c_int,
    ) -> c_int;

    /// Stop the socks5 tunnel
    fn hev_socks5_tunnel_quit();

    /// Get tunnel statistics
    fn hev_socks5_tunnel_stats(
        tx_packets: *mut usize,
        tx_bytes: *mut usize,
        rx_packets: *mut usize,
        rx_bytes: *mut usize,
    );
}

// ============================================================================
// Platform-specific TUN device creation
// ============================================================================

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};

    const TUNSETIFF: c_uint = 0x400454ca;
    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;

    type c_short = std::os::raw::c_short;

    #[repr(C)]
    struct IfReq {
        ifrn_name: [u8; 16],
        ifru_flags: c_short,
        pad: [u8; 18],
    }

    /// Create a TUN device on Linux using /dev/net/tun
    pub fn create_tun(name: &str) -> Result<RawFd> {
        let dev = std::fs::OpenOptions::new()
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
                io::Error::last_os_error()
            )));
        }

        // Duplicate the fd so we can pass it to hev-socks5-tunnel
        // and keep ownership
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(AetherError::Other(format!(
                "Failed to dup TUN fd: {}",
                io::Error::last_os_error()
            )));
        }

        // Set non-blocking
        let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL, 0) };
        if flags < 0 {
            unsafe { libc::close(dup_fd) };
            return Err(AetherError::Other(format!(
                "fcntl F_GETFL failed: {}",
                io::Error::last_os_error()
            )));
        }
        let ret = unsafe { libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            unsafe { libc::close(dup_fd) };
            return Err(AetherError::Other(format!(
                "fcntl F_SETFL failed: {}",
                io::Error::last_os_error()
            )));
        }

        log::info!("[tun_hev] Linux TUN device '{}' created (fd={})", name, dup_fd);
        Ok(dup_fd)
    }

    /// Bring the TUN interface up and assign IP address
    pub fn configure_tun(fd: RawFd, ipv4: &str, ipv6: Option<&str>) -> Result<()> {
        // Use shell commands to configure the interface
        // This is simpler than doing all the ioctl calls
        use std::process::Command;

        // Get interface name from fd
        let mut ifr = IfReq {
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

        // Disable reverse path filter for the interface
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

    /// Clean up TUN interface
    pub fn cleanup_tun(fd: RawFd) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
            log::debug!("[tun_hev] Closed TUN fd {}", fd);
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::os::raw::c_int;

    // Windows TUN support via wintun or other mechanism
    // For now, we'll implement a placeholder that returns an error
    // since Windows TUN support requires additional libraries

    pub fn create_tun(_name: &str) -> Result<c_int> {
        Err(AetherError::Other(
            "Windows TUN support not yet implemented. Please use Linux or Android.".into(),
        ))
    }

    pub fn configure_tun(_fd: c_int, _ipv4: &str, _ipv6: Option<&str>) -> Result<()> {
        Err(AetherError::Other(
            "Windows TUN support not yet implemented.".into(),
        ))
    }

    pub fn cleanup_tun(_fd: c_int) {
        // No-op
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
/// 
/// This function:
/// 1. Creates a TUN device (platform-specific)
/// 2. Configures the TUN interface
/// 3. Starts hev-socks5-tunnel with the TUN fd and SOCKS5 config
/// 4. Blocks until the tunnel stops or an error occurs
pub async fn run_hev_tun(cfg: TunConfig, shutdown: oneshot::Receiver<()>) -> Result<()> {
    log::info!("[tun_hev] Starting TUN with hev-socks5-tunnel");
    log::info!("[tun_hev] Config: name={}, ipv4={}, socks={}:{}",
        cfg.name, cfg.ipv4, cfg.socks_host, cfg.socks_port
    );

    // Create TUN device
    let tun_fd = platform::create_tun(&cfg.name)?;

    // Configure TUN interface (bring up, assign IP)
    if let Err(e) = platform::configure_tun(tun_fd, &cfg.ipv4, cfg.ipv6.as_deref()) {
        log::warn!("[tun_hev] Failed to configure TUN: {}", e);
        // Continue anyway - hev-socks5-tunnel will handle it
    }

    // Build hev-socks5-tunnel config
    let config_yaml = build_hev_config(&cfg);
    log::debug!("[tun_hev] hev-socks5-tunnel config:\n{}", config_yaml);

    // Launch hev-socks5-tunnel in a blocking thread
    let config_bytes = config_yaml.into_bytes();
    let fd = tun_fd;

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let handle = tokio::task::spawn_blocking(move || {
        let result = unsafe {
            hev_socks5_tunnel_main_from_str(
                config_bytes.as_ptr(),
                config_bytes.len() as u32,
                fd,
            )
        };
        running_clone.store(false, Ordering::SeqCst);
        result
    });

    // Wait for shutdown signal or tunnel exit using a different approach
    let result = tokio::select! {
        _ = shutdown => {
            log::info!("[tun_hev] Shutting down hev-socks5-tunnel");
            unsafe { hev_socks5_tunnel_quit(); }
            // Wait for the task to complete after shutdown
            Some(handle.await)
        }
        result = handle => {
            Some(result)
        }
    };

    if let Some(result) = result {
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

    // Cleanup
    platform::cleanup_tun(tun_fd);
    log::info!("[tun_hev] TUN shut down");
    Ok(())
}

/// Check if hev-socks5-tunnel library is available
pub fn is_available() -> bool {
    // Check if the cfg flag is set by build.rs
    #[cfg(hev_tun_available)]
    {
        true
    }
    #[cfg(not(hev_tun_available))]
    {
        false
    }
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
