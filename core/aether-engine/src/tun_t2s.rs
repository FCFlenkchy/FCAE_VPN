//! TUN implementation using tun2socks (https://github.com/xjasonlyu/tun2socks) as the engine
//! 
//! tun2socks is invoked as a subprocess with appropriate configuration.
//! 
//! Flow: tun2socks (TUN) → Engine (SOCKS5 proxy) → Internet
//! 
//! The Android implementation in tun.rs remains untouched.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::error::{AetherError, Result};

// ============================================================================
// Platform-specific TUN device creation
// ============================================================================

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::raw::c_uint;
    use std::os::fd::RawFd;

    pub fn create_tun(name: &str) -> Result<RawFd> {
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;

        const TUNSETIFF: c_uint = 0x400454ca;
        const IFF_TUN: std::os::raw::c_short = 0x0001;
        const IFF_NO_PI: std::os::raw::c_short = 0x1000;

        #[repr(C)]
        struct IfReq {
            ifrn_name: [u8; 16],
            ifru_flags: std::os::raw::c_short,
            pad: [u8; 18],
        }

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

        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(AetherError::Other(format!(
                "Failed to dup TUN fd: {}",
                std::io::Error::last_os_error()
            )));
        }

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

        log::info!("[tun_t2s] Linux TUN device '{}' created (fd={})", name, dup_fd);
        Ok(dup_fd)
    }

    pub fn configure_tun(fd: RawFd, ipv4: &str, ipv6: Option<&str>) -> Result<()> {
        use std::process::Command as StdCommand;

        let ifr = super::IfReq {
            ifrn_name: [0u8; 16],
            ifru_flags: 0,
            pad: [0u8; 18],
        };
        let ret = unsafe { libc::ioctl(fd, 0x400454ca, &ifr as *const super::IfReq) };
        if ret < 0 {
            log::warn!("[tun_t2s] Failed to get interface name from fd");
            return Err(AetherError::Other("Failed to get interface name".into()));
        }
        let name = String::from_utf8_lossy(&ifr.ifrn_name)
            .trim_matches('\0')
            .to_string();

        log::info!("[tun_t2s] Configuring interface '{}' with IP {}", name, ipv4);

        let status = StdCommand::new("ip")
            .args(["addr", "add", ipv4, "dev", &name])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::warn!("[tun_t2s] Failed to assign IPv4 to {}: {:?}", name, status);
            }
        }

        if let Some(ipv6_addr) = ipv6 {
            let status = StdCommand::new("ip")
                .args(["-6", "addr", "add", ipv6_addr, "dev", &name])
                .status();
            if let Ok(status) = status {
                if !status.success() {
                    log::warn!("[tun_t2s] Failed to assign IPv6 to {}: {:?}", name, status);
                }
            }
        }

        let status = StdCommand::new("ip")
            .args(["link", "set", &name, "up"])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::warn!("[tun_t2s] Failed to bring up {}: {:?}", name, status);
            }
        }

        let status = StdCommand::new("sysctl")
            .args(["-w", &format!("net.ipv4.conf.{}.rp_filter=0", name)])
            .status();
        if let Ok(status) = status {
            if !status.success() {
                log::debug!("[tun_t2s] Failed to disable rp_filter for {}", name);
            }
        }

        Ok(())
    }

    pub fn cleanup_tun(fd: RawFd) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
            log::debug!("[tun_t2s] Closed TUN fd {}", fd);
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
// Helper struct for ioctl (used in platform::configure_tun above)
// ============================================================================

#[repr(C)]
struct IfReq {
    ifrn_name: [u8; 16],
    ifru_flags: std::os::raw::c_short,
    pad: [u8; 18],
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

/// Find the tun2socks binary
fn find_tun2socks_binary() -> Option<std::path::PathBuf> {
    // Check environment variable first
    if let Ok(path) = std::env::var("TUN2SOCKS_BIN") {
        let p = std::path::PathBuf::from(&path);
        if p.exists() {
            log::info!("[tun_t2s] Found tun2socks via TUN2SOCKS_BIN: {}", p.display());
            return Some(p);
        }
    }

    // Check executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            #[cfg(target_os = "windows")]
            let names = ["tun2socks.exe"];
            #[cfg(not(target_os = "windows"))]
            let names = ["tun2socks"];

            for name in names.iter() {
                let p = dir.join(name);
                if p.exists() {
                    log::info!("[tun_t2s] Found tun2socks at: {}", p.display());
                    return Some(p);
                }
            }
        }
    }

    // Try PATH
    #[cfg(target_os = "windows")]
    let bin_name = "tun2socks.exe";
    #[cfg(not(target_os = "windows"))]
    let bin_name = "tun2socks";

    if let Ok(path) = which::which(bin_name) {
        log::info!("[tun_t2s] Found tun2socks in PATH: {}", path.display());
        return Some(path);
    }

    log::warn!("[tun_t2s] tun2socks binary not found");
    None
}

/// Check if tun2socks is available
pub fn is_available() -> bool {
    find_tun2socks_binary().is_some()
}

/// Run the TUN with tun2socks as a subprocess
pub async fn run_tun2socks(cfg: TunConfig, shutdown: oneshot::Receiver<()>) -> Result<()> {
    log::info!("[tun_t2s] Starting TUN with tun2socks");
    log::info!("[tun_t2s] Config: name={}, ipv4={}, socks={}:{}",
        cfg.name, cfg.ipv4, cfg.socks_host, cfg.socks_port
    );

    // Find tun2socks binary
    let t2s_path = find_tun2socks_binary()
        .ok_or_else(|| AetherError::Other(
            "tun2socks binary not found. Please install tun2socks or set TUN2SOCKS_BIN env var.".into()
        ))?;

    // Parse the IPv4 address (strip prefix)
    let ipv4_addr = cfg.ipv4.split('/').next().unwrap_or(&cfg.ipv4);

    // Build tun2socks arguments
    // tun2socks -device tun://<name> -proxy socks5://<host>:<port> -loglevel info
    let device = format!("tun://{}", cfg.name);
    let proxy = if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        format!("socks5://{}:{}@{}:{}", user, pass, cfg.socks_host, cfg.socks_port)
    } else {
        format!("socks5://{}:{}", cfg.socks_host, cfg.socks_port)
    };

    let mut cmd = Command::new(&t2s_path);
    cmd.arg("-device").arg(&device)
       .arg("-proxy").arg(&proxy)
       .arg("-loglevel").arg("info")
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    // Set MTU if not default
    if cfg.mtu != 1500 {
        cmd.arg("-mtu").arg(cfg.mtu.to_string());
    }

    log::debug!("[tun_t2s] Command: {:?}", cmd);

    let mut child = cmd.spawn()
        .map_err(|e| AetherError::Other(format!("Failed to spawn tun2socks: {e}")))?;

    let pid = child.id();
    log::info!("[tun_t2s] tun2socks started (pid: {:?})", pid);

    // Spawn a task to capture output
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let reader = tokio::io::BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log::info!("[tun2socks stdout] {}", line);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let reader = tokio::io::BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log::info!("[tun2socks stderr] {}", line);
            }
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Wait for shutdown signal or process exit
    tokio::select! {
        _ = shutdown => {
            log::info!("[tun_t2s] Shutting down tun2socks");
            running_clone.store(false, Ordering::SeqCst);
            // Send SIGTERM to the process
            if let Some(id) = pid {
                #[cfg(target_os = "windows")]
                {
                    let _ = std::process::Command::new("taskkill")
                        .args(["/PID", &id.to_string(), "/F"])
                        .status();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    unsafe { libc::kill(id as i32, libc::SIGTERM); }
                }
            }
            // Wait for process to exit with timeout
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                child.wait()
            ).await;
            // Force kill if still running
            let _ = child.kill().await;
        }
        status = child.wait() => {
            match status {
                Ok(s) if s.success() => {
                    log::info!("[tun_t2s] tun2socks exited normally");
                }
                Ok(s) => {
                    log::warn!("[tun_t2s] tun2socks exited with: {:?}", s.code());
                    return Err(AetherError::Other(format!(
                        "tun2socks exited with code {:?}", s.code()
                    )));
                }
                Err(e) => {
                    log::error!("[tun_t2s] tun2socks process error: {}", e);
                    return Err(AetherError::Other(format!(
                        "tun2socks process error: {}", e
                    )));
                }
            }
        }
    }

    log::info!("[tun_t2s] TUN shut down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_defaults() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name, "aether-tun0");
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.ipv4, "198.18.0.1/24");
        assert_eq!(cfg.socks_port, 1080);
        assert_eq!(cfg.socks_host, "127.0.0.1");
    }
}
