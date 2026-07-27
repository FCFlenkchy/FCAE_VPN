//! TUN implementation using tun2socks (https://github.com/xjasonlyu/tun2socks) as the engine
//! 
//! tun2socks is invoked as a subprocess with appropriate configuration.
//! 
//! Flow: tun2socks (TUN) → Engine (SOCKS5 proxy) → Internet
//! 
//! The Android implementation in tun.rs remains untouched.

use std::process::{Command, Stdio};
use tokio::sync::oneshot;

use crate::error::{AetherError, Result};

// Embed tun2socks binary at compile time
#[cfg(not(target_os = "android"))]
static TUN2SOCKS_BYTES: &[u8] = include_bytes!(env!("TUN2SOCKS_EMBEDDED"));

// Embed wintun.dll on Windows
#[cfg(all(not(target_os = "android"), wintun_embedded))]
static WINTUN_DLL_BYTES: &[u8] = include_bytes!(env!("WINTUN_EMBEDDED"));

/// Extract and return path to the embedded tun2socks binary.
/// On first call, writes the binary to a temp file and returns the path.
/// On Windows, also ensures wintun.dll is extracted to the same directory.
#[cfg(not(target_os = "android"))]
fn get_tun2socks_path() -> Result<std::path::PathBuf> {
    use std::io::Write;

    // Check TUN2SOCKS_BIN override first
    if let Ok(path) = std::env::var("TUN2SOCKS_BIN") {
        let p = std::path::PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
    }

    // Use a fixed temp path so we don't recreate every time
    let dir = std::env::temp_dir().join("fcaevpn");
    std::fs::create_dir_all(&dir).ok();

    #[cfg(target_os = "windows")]
    let name = "tun2socks.exe";
    #[cfg(not(target_os = "windows"))]
    let name = "tun2socks";

    let dest = dir.join(name);

    // Only write if not already present (or size mismatch)
    let needs_write = match std::fs::metadata(&dest) {
        Ok(m) => m.len() != TUN2SOCKS_BYTES.len() as u64,
        Err(_) => true,
    };

    if needs_write {
        let mut f = std::fs::File::create(&dest)
            .map_err(|e| AetherError::Other(format!("Failed to create tun2socks binary: {e}")))?;
        f.write_all(TUN2SOCKS_BYTES)
            .map_err(|e| AetherError::Other(format!("Failed to write tun2socks binary: {e}")))?;

        // Set executable permission on Unix
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)
                .map_err(|e| AetherError::Other(format!("stat: {e}")))?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms).ok();
        }
    }

    // ── Windows: ensure wintun.dll is in the same directory ─────────
    #[cfg(target_os = "windows")]
    {
        let wintun_dest = dir.join("wintun.dll");
        let expected_size = wintun_dll_expected_size();
        let needs_write = match std::fs::metadata(&wintun_dest) {
            Ok(m) => m.len() != expected_size as u64,
            Err(_) => expected_size > 0,
        };
        if needs_write {
            #[cfg(wintun_embedded)]
            {
                let mut f = std::fs::File::create(&wintun_dest)
                    .map_err(|e| AetherError::Other(format!("Failed to create wintun.dll: {e}")))?;
                f.write_all(WINTUN_DLL_BYTES)
                    .map_err(|e| AetherError::Other(format!("Failed to write wintun.dll: {e}")))?;
                log::info!("[tun_t2s] wintun.dll extracted (embedded) to: {}", wintun_dest.display());
            }
            #[cfg(not(wintun_embedded))]
            {
                // Fallback: try to find wintun.dll from common locations at runtime
                let mut found = false;
                let candidate_paths = [
                    std::path::PathBuf::from("C:\\Windows\\System32\\wintun.dll"),
                    std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new(".")).join("wintun.dll"),
                    std::path::PathBuf::from("wintun.dll"),
                ];
                for candidate in &candidate_paths {
                    if candidate.exists() {
                        log::info!("[tun_t2s] Found wintun.dll at: {}", candidate.display());
                        match std::fs::copy(candidate, &wintun_dest) {
                            Ok(_) => {
                                log::info!("[tun_t2s] wintun.dll copied from {} to: {}", candidate.display(), wintun_dest.display());
                                found = true;
                                break;
                            }
                            Err(e) => {
                                log::warn!("[tun_t2s] Failed to copy wintun.dll from {}: {}", candidate.display(), e);
                            }
                        }
                    }
                }
                if !found {
                    log::error!("[tun_t2s] wintun.dll NOT found! TUN will fail on Windows. Download wintun.dll from https://www.wintun.net/ and place it in: {}", dir.display());
                    return Err(AetherError::Other(format!(
                        "wintun.dll not found. Please download it from https://www.wintun.net/ and place it in: {}",
                        dir.display()
                    )));
                }
            }
        }
    }

    Ok(dest)
}

/// Returns the expected size of the embedded wintun.dll bytes (0 if not embedded).
#[cfg(target_os = "windows")]
fn wintun_dll_expected_size() -> usize {
    #[cfg(wintun_embedded)]
    { WINTUN_DLL_BYTES.len() }
    #[cfg(not(wintun_embedded))]
    { 0 }
}

#[cfg(target_os = "android")]
fn get_tun2socks_path() -> Result<std::path::PathBuf> {
    Err(AetherError::Other("tun2socks not available on Android".into()))
}

/// Check if tun2socks is available
pub fn is_available() -> bool {
    #[cfg(target_os = "android")]
    return false;

    #[cfg(not(target_os = "android"))]
    get_tun2socks_path().is_ok()
}

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

/// Check if the current process has administrator privileges on Windows.
#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    use std::os::windows::ffi::OsStringExt;
    use std::ffi::OsString;
    
    // Use Win32 CheckTokenMembership to check if running as admin
    // This avoids needing the "windows" crate by using a minimal FFI call
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn OpenProcessToken(process_handle: isize, desired_access: u32, token_handle: *mut isize) -> i32;
        fn GetTokenInformation(token_handle: isize, token_info_class: i32, token_info: *mut u8, token_info_len: u32, return_length: *mut u32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
        fn AllocateAndInitializeSid(
            identifier_authority: *const u8, sub_authority_count: u8,
            sub_authority0: u32, sub_authority1: u32, sub_authority2: u32,
            sub_authority3: u32, sub_authority4: u32, sub_authority5: u32,
            sub_authority6: u32, sub_authority7: u32, sid: *mut isize
        ) -> i32;
        fn CheckTokenMembership(token_handle: isize, sid_to_check: isize, is_member: *mut i32) -> i32;
        fn FreeSid(sid: isize) -> *mut std::ffi::c_void;
    }
    
    const TOKEN_QUERY: u32 = 0x0008;
    const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;
    
    unsafe {
        let process = GetCurrentProcess();
        let mut token: isize = 0;
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        
        let mut admin_sid: isize = 0;
        let result = AllocateAndInitializeSid(
            SECURITY_NT_AUTHORITY.as_ptr(), 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &mut admin_sid
        );
        if result == 0 {
            CloseHandle(token);
            return false;
        }
        
        let mut is_member: i32 = 0;
        let check_result = CheckTokenMembership(0, admin_sid, &mut is_member);
        FreeSid(admin_sid);
        CloseHandle(token);
        
        check_result != 0 && is_member != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn is_admin() -> bool {
    // On Linux/macOS, check if we're root
    unsafe { libc::geteuid() == 0 }
}

/// Run the TUN with tun2socks as a subprocess
pub async fn run_tun2socks(cfg: TunConfig, shutdown: oneshot::Receiver<()>) -> Result<()> {
    log::info!("[tun_t2s] Starting TUN with tun2socks");
    log::info!("[tun_t2s] Config: name={}, ipv4={}, socks={}:{}",
        cfg.name, cfg.ipv4, cfg.socks_host, cfg.socks_port
    );
    
    // Check for admin/root privileges (required to create TUN interface)
    if !is_admin() {
        log::error!("[tun_t2s] TUN requires administrator/root privileges!");
        return Err(AetherError::Other(
            "TUN mode requires administrator privileges. Please run the application as Administrator.\n\
             On Windows: Right-click → 'Run as Administrator'\n\
             On Linux/macOS: Use 'sudo'".into()
        ));
    }

    // Extract embedded binary
    let t2s_path = get_tun2socks_path()?;

    // Build tun2socks arguments
    let device = format!("tun://{}", cfg.name);
    let proxy = if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        format!("socks5://{}:{}@{}:{}", user, pass, cfg.socks_host, cfg.socks_port)
    } else {
        format!("socks5://{}:{}", cfg.socks_host, cfg.socks_port)
    };

    let mut args = vec![
        "--device", &device,
        "--proxy", &proxy,
        "--loglevel", "info",
    ];
    let mtu_str;
    if cfg.mtu != 1500 {
        mtu_str = cfg.mtu.to_string();
        args.push("--mtu");
        args.push(&mtu_str);
    }

    // Set the current directory to the directory containing tun2socks
    // so that it can find wintun.dll (which we extracted there).
    let tun_dir = t2s_path.parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    log::debug!("[tun_t2s] Running: {} {:?} (cwd: {})", t2s_path.display(), args, tun_dir.display());

    let mut child = Command::new(&t2s_path)
        .current_dir(tun_dir)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AetherError::Other(format!("Failed to spawn tun2socks: {e}")))?;

    let pid = child.id();
    log::info!("[tun_t2s] tun2socks started (pid: {})", pid);

    // Read stdout/stderr in background threads
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    log::info!("[tun2socks stdout] {}", line);
                }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    log::info!("[tun2socks stderr] {}", line);
                }
            }
        });
    }

    // Wait for process in a blocking task
    let wait_handle = tokio::task::spawn_blocking(move || child.wait());
    tokio::pin!(wait_handle);

    tokio::select! {
        _ = shutdown => {
            log::info!("[tun_t2s] Shutting down tun2socks");
            // Kill the process
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status();
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            }
            // Wait for process to exit with timeout
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                &mut wait_handle
            ).await;
        }
        result = &mut wait_handle => {
            match result {
                Ok(Ok(s)) if s.success() => {
                    log::info!("[tun_t2s] tun2socks exited normally");
                }
                Ok(Ok(s)) => {
                    log::warn!("[tun_t2s] tun2socks exited with: {:?}", s.code());
                    return Err(AetherError::Other(format!(
                        "tun2socks exited with code {:?}", s.code()
                    )));
                }
                Ok(Err(e)) => {
                    log::error!("[tun_t2s] tun2socks process error: {}", e);
                    return Err(AetherError::Other(format!(
                        "tun2socks process error: {}", e
                    )));
                }
                Err(e) => {
                    log::error!("[tun_t2s] tun2socks task join error: {}", e);
                    return Err(AetherError::Other(format!(
                        "tun2socks task join error: {}", e
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
