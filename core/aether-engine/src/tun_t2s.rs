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
                // Fallback: try to find wintun.dll from system locations at runtime.
                // This should rarely be needed since build.rs downloads and embeds it,
                // but provides a safety net for custom builds.
                let mut found = false;
                let candidate_paths = [
                    std::path::PathBuf::from("C:\\Windows\\System32\\wintun.dll"),
                    std::env::current_exe().unwrap_or_default().parent().unwrap_or(std::path::Path::new(".")).join("wintun.dll"),
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
                        "wintun.dll not found. Download it from https://www.wintun.net/ and place it in: {}",
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

/// Force-kill any running tun2socks processes.
/// This is the emergency cleanup — call from outside the tokio runtime
/// (e.g., from aether_stop / aether_free) to ensure the process is killed
/// even when the runtime is being torn down and can't run async tasks.
/// Does NOT delete the adapter — that's handled by the normal shutdown path.
#[cfg(target_os = "windows")]
pub fn force_cleanup_windows(_name: &str) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Kill all tun2socks processes
    log::info!("[tun_t2s] Force-killing tun2socks processes");
    let mut c = Command::new("taskkill");
    c.creation_flags(CREATE_NO_WINDOW);
    let _ = c.args(["/IM", "tun2socks.exe", "/F", "/T"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(target_os = "windows"))]
pub fn force_cleanup_windows(_name: &str) {
    // No-op on non-Windows
}

/// Quick removal of the default route pointing to a given TUN IP.
/// Fast alternative to full adapter deletion for pre-startup cleanup.
#[cfg(target_os = "windows")]
fn remove_default_route_windows(tun_ip: &str) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut c = Command::new("route");
    c.creation_flags(CREATE_NO_WINDOW);
    let _ = c.args(["DELETE", "0.0.0.0", "MASK", "0.0.0.0", tun_ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Clean up a named TUN adapter — removes routes, resets DNS, deletes interface.
/// Standalone function callable without a TunConfig.
#[cfg(target_os = "windows")]
fn cleanup_adapter_by_name(name: &str) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Fast path: single PowerShell script that removes all adapters matching
    // our name (including hidden/ghost Wintun devices) and deletes routes.
    // This replaces 200+ synchronous netsh calls that took 5-10 seconds.
    let name_hyphen = name.replace('_', "-");
    let name_underscore = name.replace('-', "_");
    // Also strip any numeric suffix for matching (e.g. "FCAE_VPN 2" -> "FCAE_VPN")
    let base_name = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == ' ');

    let ps_script = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         $base = '{0}';\
         $patterns = @(($base + '*'), ('{1}*'), ('{2}*'));\
         Get-NetAdapter -IncludeHidden | ?{{ $_.Name -like ($base + '*') -or $_.Name -like ('{1}*') -or $_.Name -like ('{2}*') }} | Remove-NetAdapter -Confirm:$false;\
         Get-PnpDevice -Class Net | ?{{ ($_.FriendlyName -like ($base + '*') -or $_.FriendlyName -like ('{1}*')) -and $_.InstanceId -like '*WINTUN*' }} | Remove-PnpDevice -Confirm:$false;\
         Get-NetRoute -InterfaceAlias ($base + '*') -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;\
         Get-NetRoute -InterfaceAlias ('{1}*') -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;\
         Write-Host 'cleanup_done'",
        base_name, name_hyphen, name_underscore
    );

    let mut c = Command::new("powershell");
    c.creation_flags(CREATE_NO_WINDOW);
    let output = c.args(["-NoProfile", "-Command", &ps_script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("cleanup_done") {
                log::info!("[tun_t2s] Fast PowerShell cleanup complete for '{}'", name);
            } else if !stdout.trim().is_empty() {
                log::info!("[tun_t2s] PowerShell cleanup: {}", stdout.trim());
            }
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                log::debug!("[tun_t2s] PowerShell stderr: {}", stderr.trim());
            }
        }
        Err(e) => {
            log::warn!("[tun_t2s] PowerShell cleanup failed ({}); falling back to netsh", e);
            // Fallback: quick netsh delete for a few common numbered variants
            let run_silent = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
                let mut c = Command::new(cmd);
                c.creation_flags(CREATE_NO_WINDOW);
                c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
            };
            for i in 1..=10 {
                let numbered = format!("{} {}", name, i);
                let _ = run_silent("netsh", &["interface", "ip", "delete", "interface", &numbered]);
            }
        }
    }

    log::info!("[tun_t2s] TUN adapter cleanup complete for '{}'", name);
}

#[cfg(not(target_os = "windows"))]
fn cleanup_adapter_by_name(_name: &str) {}

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
        // On macOS (and other non-Linux Unix), TUN is created by the tun2socks subprocess.
        // tun2socks uses utun on macOS, which requires no manual fd creation.
        Err(AetherError::Other(
            format!(
                "Direct TUN fd creation not supported on this platform: {}. Use tun2socks subprocess instead.",
                std::env::consts::OS
            )
        ))
    }

    pub fn configure_tun(_fd: c_int, _ipv4: &str, _ipv6: Option<&str>) -> Result<()> {
        Err(AetherError::Other("Direct TUN configuration not supported on this platform".into()))
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
    /// IP of the tunnel endpoint — must be excluded from TUN routes to avoid routing loops
    pub tunnel_peer_ip: Option<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "FCAE_VPN".to_string(),
            mtu: 1500,
            ipv4: "198.18.0.1/24".to_string(),
            ipv6: Some("fc00::1/64".to_string()),
            socks_port: 1819,
            socks_host: "127.0.0.1".to_string(),
            username: None,
            password: None,
            tunnel_peer_ip: None,
        }
    }
}

/// Check if the current process has administrator privileges on Windows.
#[cfg(target_os = "windows")]
fn is_admin() -> bool {
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

// ── Windows TUN adapter route configuration ─────────────────────────────
#[cfg(target_os = "windows")]
fn configure_windows_tun(cfg: &TunConfig) {
    use std::os::windows::process::CommandExt;
    use std::process::Command as StdCommand;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let name = &cfg.name;
    // Extract IP without prefix (e.g., "172.16.0.2" from "172.16.0.2/24")
    let ip = cfg.ipv4.split('/').next().filter(|v| !v.is_empty()).unwrap_or("198.18.0.1");
    let ipv6 = cfg.ipv6.as_deref().and_then(|v| if v.is_empty() { None } else { v.split('/').next() }).unwrap_or("fc00::1");
    let dns = "1.1.1.1";
    let dns2 = "1.0.0.1";
    let dns6 = "2606:4700:4700::1111";
    let dns62 = "2606:4700:4700::1001";

    log::info!("[tun_t2s] Configuring Windows TUN adapter '{}' with IP {} IPv6 {} DNS {}", name, ip, ipv6, dns);

    // Helper to run a command silently (no window popup)
    let run_silent = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut c = StdCommand::new(cmd);
        c.creation_flags(CREATE_NO_WINDOW);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    };

    // tun2socks may create the adapter with hyphens instead of underscores on Windows
    let name_hyphen = name.replace('_', "-");

    // 1. Set the adapter's IP address
    let output = run_silent("netsh", &["interface", "ip", "set", "address", name, "static", ip, "255.255.255.0"]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] netsh set address OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] netsh set address failed: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] netsh set address error: {}", e),
    }

    // 1b. Set IPv6 address on the adapter
    let output = run_silent("netsh", &["interface", "ipv6", "set", "address", name, ipv6]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] netsh set ipv6 address OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] netsh set ipv6 address failed: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] netsh set ipv6 address error: {}", e),
    }

    // 2. Set DNS server on the adapter (dual-stack, with redundancy)
    let output = run_silent("netsh", &["interface", "ip", "set", "dns", name, "static", dns]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] netsh set dns OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] netsh set dns failed: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] netsh set dns error: {}", e),
    }
    // Add secondary IPv4 DNS
    let _ = run_silent("netsh", &["interface", "ip", "add", "dns", name, dns2, "index=2"]);

    // 2b. Set IPv6 DNS server on the adapter (dual-stack, with redundancy)
    let output = run_silent("netsh", &["interface", "ipv6", "set", "dns", name, "static", dns6]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] netsh set ipv6 dns OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] netsh set ipv6 dns failed: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] netsh set ipv6 dns error: {}", e),
    }
    // Add secondary IPv6 DNS
    let _ = run_silent("netsh", &["interface", "ipv6", "add", "dns", name, dns62, "index=2"]);

    // 2c. Save current DNS on ALL adapters to a temp file, then override to Cloudflare.
    // Original DNS is restored from the backup file on cleanup.
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup.json");
    if let Some(parent) = dns_backup_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let dns_backup_str = dns_backup_path.to_string_lossy().replace('\\', "\\\\");
    let ps_override = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         $dns4='{dns}'; $dns42='{dns2}'; $dns6='{dns6}'; $dns62='{dns62}'; $backupFile='{backup}';\
         $adapters = Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.Name -ne '{name}' -and $_.Name -ne '{name_hyphen}' }};\
         $backup = @();\
         foreach ($a in $adapters) {{\
             $v4 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ',';\
             $v6 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses -join ',';\
             $backup += [PSCustomObject]@{{ ifIndex=$a.ifIndex; name=$a.Name; v4=$v4; v6=$v6 }};\
             Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ($dns4,$dns42);\
             Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ServerAddresses ($dns6,$dns62);\
         }};\
         $backup | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding UTF8;\
         Write-Host 'dns_override_done'",
        name = name, name_hyphen = name_hyphen, dns = dns, dns2 = dns2, dns6 = dns6, dns62 = dns62, backup = dns_backup_str
    );
    let output = run_silent("powershell", &["-NoProfile", "-Command", &ps_override]);
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("dns_override_done") {
                log::info!("[tun_t2s] DNS override on all adapters OK (backup: {})", dns_backup_path.display());
            }
        }
        Err(e) => log::warn!("[tun_t2s] DNS override on all adapters error: {}", e),
    }

    // 3. Find the interface index (use CREATE_NO_WINDOW to avoid popup)
    let ifidx = match run_silent("powershell", &["-NoProfile", "-Command",
        &format!("$name = '{}'; $hname = '{}'; $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue; if (-not $adapter) {{ $adapter = Get-NetAdapter -Name $hname -ErrorAction SilentlyContinue }}; if ($adapter) {{ $adapter.ifIndex }}", name, name_hyphen)])
    {
        Ok(o) => {
            let idx_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match idx_str.parse::<u32>() {
                Ok(idx) => Some(idx),
                Err(_) => {
                    log::warn!("[tun_t2s] Could not parse interface index from: '{}'", idx_str);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("[tun_t2s] powershell get ifIndex error: {}", e);
            None
        }
    };

    if let Some(idx) = ifidx {
        log::info!("[tun_t2s] Found adapter '{}' with ifIndex={}", name, idx);

        // 4. Set interface metric low so it becomes the preferred route
        let output = run_silent("netsh", &["interface", "ipv4", "set", "interface", &idx.to_string(), "metric=5"]);
        match output {
            Ok(o) if o.status.success() => log::info!("[tun_t2s] netsh set metric OK"),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                log::warn!("[tun_t2s] netsh set metric failed: {}", stderr.trim());
            }
            Err(e) => log::warn!("[tun_t2s] netsh set metric error: {}", e),
        }

        // 5. Add route: 0.0.0.0/0 -> TUN adapter (redirect all traffic)
        // Use separate METRIC and IF arguments (not combined) for route.exe compatibility
        let output = run_silent("route", &["ADD", "0.0.0.0", "MASK", "0.0.0.0", ip, "METRIC", "5", "IF", &idx.to_string()]);
        match output {
            Ok(o) if o.status.success() => log::info!("[tun_t2s] route ADD 0.0.0.0/0 OK"),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                // "The object already exists" is fine (route already present)
                if stderr.contains("already exists") || stdout.contains("already exists") {
                    log::info!("[tun_t2s] route 0.0.0.0/0 already exists (OK)");
                } else {
                    log::warn!("[tun_t2s] route ADD failed: {} {}", stdout.trim(), stderr.trim());
                }
            }
            Err(e) => log::warn!("[tun_t2s] route ADD error: {}", e),
        }

        // 5b. Add IPv6 route: ::/0 -> TUN adapter (redirect all IPv6 traffic)
        let output = run_silent("route", &["ADD", "::/0", ipv6, "IF", &idx.to_string()]);
        match output {
            Ok(o) if o.status.success() => log::info!("[tun_t2s] route ADD ::/0 OK"),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stderr.contains("already exists") || stdout.contains("already exists") {
                    log::info!("[tun_t2s] route ::/0 already exists (OK)");
                } else {
                    log::warn!("[tun_t2s] route ADD ::/0 failed: {} {}", stdout.trim(), stderr.trim());
                }
            }
            Err(e) => log::warn!("[tun_t2s] route ADD ::/0 error: {}", e),
        }

        // 6. Add route to exclude the tunnel peer from TUN (avoid routing loop)
        if let Some(ref peer_ip) = cfg.tunnel_peer_ip {
            // Get current default gateway to route tunnel peer through it
            if let Ok(gw_output) = run_silent("powershell", &["-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
            {
                let gw = String::from_utf8_lossy(&gw_output.stdout).trim().to_string();
                if !gw.is_empty() {
                    let output = run_silent("route", &["ADD", peer_ip, "MASK", "255.255.255.255", &gw]);
                    match output {
                        Ok(o) if o.status.success() => log::info!("[tun_t2s] route ADD bypass {} via {} OK", peer_ip, gw),
                        Ok(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            if !stderr.contains("already exists") {
                                log::warn!("[tun_t2s] route ADD bypass failed: {}", stderr.trim());
                            }
                        }
                        Err(e) => log::warn!("[tun_t2s] route ADD bypass error: {}", e),
                    }
                }
            }
        }
    } else {
        log::warn!("[tun_t2s] Could not find interface index for '{}'; skipping route configuration", name);
    }
}

// ── macOS TUN adapter route configuration ─────────────────────────────
#[cfg(target_os = "macos")]
fn configure_macos_tun(cfg: &TunConfig) {
    use std::process::Command as StdCommand;

    let name = &cfg.name;
    let ip = cfg.ipv4.split('/').next().filter(|v| !v.is_empty()).unwrap_or("198.18.0.1");
    let ipv6 = cfg.ipv6.as_deref().and_then(|v| if v.is_empty() { None } else { v.split('/').next() }).unwrap_or("fc00::1");
    let netmask = "255.255.255.0"; // hardcoded for /24
    let dns6 = "2606:4700:4700::1111";

    log::info!("[tun_t2s] Configuring macOS TUN adapter '{}' with IP {} IPv6 {} netmask {}", name, ip, ipv6, netmask);

    // Find the utun interface that tun2socks created
    // tun2socks creates utun with the name we specified; on macOS this becomes a utunX device.
    // We need to find the actual utun number assigned.
    let iface = find_macos_utun(name);
    let iface = iface.as_deref().unwrap_or(name);
    log::info!("[tun_t2s] Using macOS interface: {}", iface);

    // 1. Assign IPv4 address to the interface
    let output = StdCommand::new("ifconfig")
        .args([iface, "inet", ip, netmask, ip])
        .output();
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] ifconfig assign IPv4 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] ifconfig assign IPv4: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] ifconfig error: {}", e),
    }

    // 1b. Assign IPv6 address to the interface
    let output = StdCommand::new("ifconfig")
        .args([iface, "inet6", ipv6, "prefixlen", "64"])
        .output();
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] ifconfig assign IPv6 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] ifconfig assign IPv6: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] ifconfig IPv6 error: {}", e),
    }

    // 2. Bring interface up
    let output = StdCommand::new("ifconfig")
        .args([iface, "up"])
        .output();
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] ifconfig up OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            log::warn!("[tun_t2s] ifconfig up: {}", stderr.trim());
        }
        Err(e) => log::warn!("[tun_t2s] ifconfig up error: {}", e),
    }

    // 3. Add default IPv4 route via the TUN interface
    let output = StdCommand::new("route")
        .args(["add", "default", "-interface", iface])
        .output();
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] route add default IPv4 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.contains("already in table") && !stderr.contains("File exists") {
                log::warn!("[tun_t2s] route add default IPv4: {}", stderr.trim());
            } else {
                log::info!("[tun_t2s] default IPv4 route already exists (OK)");
            }
        }
        Err(e) => log::warn!("[tun_t2s] route add IPv4 error: {}", e),
    }

    // 3b. Add default IPv6 route via the TUN interface
    let output = StdCommand::new("route")
        .args(["add", "-inet6", "default", "-interface", iface])
        .output();
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] route add default IPv6 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.contains("already in table") && !stderr.contains("File exists") {
                log::warn!("[tun_t2s] route add default IPv6: {}", stderr.trim());
            } else {
                log::info!("[tun_t2s] default IPv6 route already exists (OK)");
            }
        }
        Err(e) => log::warn!("[tun_t2s] route add IPv6 error: {}", e),
    }

    // 4. Add route to bypass tunnel peer (avoid routing loop)
    if let Some(ref peer_ip) = cfg.tunnel_peer_ip {
        // Get current default gateway to route tunnel peer through it
        if let Ok(gw_output) = StdCommand::new("sh")
            .args(["-c", "route -n get default | grep gateway | head -1 | awk '{print $2}'"])
            .output()
        {
            let gw = String::from_utf8_lossy(&gw_output.stdout).trim().to_string();
            if !gw.is_empty() {
                let output = StdCommand::new("route")
                    .args(["add", peer_ip, &gw])
                    .output();
                match output {
                    Ok(o) if o.status.success() => log::info!("[tun_t2s] route bypass {} via {} OK", peer_ip, gw),
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        if !stderr.contains("already in table") && !stderr.contains("File exists") {
                            log::warn!("[tun_t2s] route bypass failed: {}", stderr.trim());
                        }
                    }
                    Err(e) => log::warn!("[tun_t2s] route bypass error: {}", e),
                }
            }
        }
    }

    // 5. Save original DNS, then set Cloudflare DNS on ALL network services.
    // Original DNS is saved to a temp file and restored on cleanup.
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup_macos.txt");
    if let Some(parent) = dns_backup_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(services_output) = StdCommand::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
    {
        let services = String::from_utf8_lossy(&services_output.stdout);
        let mut backup_lines = Vec::new();
        for service in services.lines().skip(1) {
            let service = service.trim();
            if service.is_empty() || service.starts_with('*') {
                continue;
            }
            // Save current DNS for this service
            if let Ok(dns_out) = StdCommand::new("networksetup")
                .args(["-getdnsservers", service])
                .output()
            {
                let dns_str = String::from_utf8_lossy(&dns_out.stdout).trim().to_string();
                backup_lines.push(format!("{}|{}", service, dns_str));
            }
            // Set Cloudflare DNS
            let output = StdCommand::new("networksetup")
                .args(["-setdnsservers", service, "1.1.1.1", "1.0.0.1", dns6])
                .output();
            match output {
                Ok(o) if o.status.success() => log::info!("[tun_t2s] networksetup DNS OK for '{}'", service),
                Ok(_) => log::debug!("[tun_t2s] networksetup DNS failed for '{}'", service),
                Err(_) => {}
            }
        }
        // Write backup file
        if let Ok(mut f) = std::fs::File::create(&dns_backup_path) {
            use std::io::Write;
            let _ = writeln!(f, "{}", backup_lines.join("\n"));
            log::info!("[tun_t2s] DNS backup saved to {}", dns_backup_path.display());
        }
    }
}

/// Find the actual macOS utun interface name that tun2socks created.
/// tun2socks creates a utun device with a name like "utun3" but we request "FCAE_VPN".
/// We need to find which utun was actually assigned.
#[cfg(target_os = "macos")]
fn find_macos_utun(_requested_name: &str) -> Option<String> {
    use std::process::Command as StdCommand;
    // List all interfaces and find the one with our requested name or the most recent utun
    let output = StdCommand::new("ifconfig")
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for utun interfaces that are up with an inet address (indicates tun2socks configured it)
    let mut current_utun: Option<String> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("utun") {
            let iface = line.split(':').next().unwrap_or("").to_string();
            if !iface.is_empty() {
                current_utun = Some(iface);
            }
        }
        // If this utun has an inet address, it's likely the one tun2socks configured
        if line.starts_with("inet ") && current_utun.is_some() {
            let utun = current_utun.take().unwrap();
            log::info!("[tun_t2s] Found configured utun: {}", utun);
            return Some(utun);
        }
    }

    // Fallback: try common utun names
    for i in 0..20 {
        let name = format!("utun{}", i);
        let output = StdCommand::new("ifconfig")
            .arg(&name)
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("inet ") {
            log::info!("[tun_t2s] Found active utun by scanning: {}", name);
            return Some(name);
        }
    }

    None
}

// ── Linux TUN adapter route configuration ───────────────────────────────
#[cfg(target_os = "linux")]
fn configure_linux_tun(cfg: &TunConfig) {
    use std::process::Command as StdCommand;

    let name = &cfg.name;
    let ip = if cfg.ipv4.is_empty() { "198.18.0.1/24" } else { &cfg.ipv4 };
    let ipv6 = cfg.ipv6.as_deref().and_then(|v| if v.is_empty() { None } else { Some(v) }).unwrap_or("fc00::1/64");
    let dns6 = "2606:4700:4700::1111";

    log::info!("[tun_t2s] Configuring Linux TUN adapter '{}' with IP {} IPv6 {}", name, ip, ipv6);

    // Add IPv4 to interface
    let output = StdCommand::new("ip")
        .args(["addr", "add", ip, "dev", name])
        .status();
    match output {
        Ok(s) if s.success() => log::info!("[tun_t2s] ip addr add IPv4 OK"),
        Ok(s) => log::warn!("[tun_t2s] ip addr add IPv4 failed with status {:?}", s.code()),
        Err(e) => log::warn!("[tun_t2s] ip addr add IPv4 error: {}", e),
    }

    // Add IPv6 to interface
    let output = StdCommand::new("ip")
        .args(["-6", "addr", "add", ipv6, "dev", name])
        .status();
    match output {
        Ok(s) if s.success() => log::info!("[tun_t2s] ip addr add IPv6 OK"),
        Ok(s) => log::warn!("[tun_t2s] ip addr add IPv6 failed with status {:?}", s.code()),
        Err(e) => log::warn!("[tun_t2s] ip addr add IPv6 error: {}", e),
    }

    // Bring interface up
    let output = StdCommand::new("ip")
        .args(["link", "set", name, "up"])
        .status();
    match output {
        Ok(s) if s.success() => log::info!("[tun_t2s] ip link set up OK"),
        Ok(s) => log::warn!("[tun_t2s] ip link set up failed with status {:?}", s.code()),
        Err(e) => log::warn!("[tun_t2s] ip link set up error: {}", e),
    }

    // Add default IPv4 route via TUN (higher metric = lower priority so existing routes stay)
    let output = StdCommand::new("ip")
        .args(["route", "add", "default", "dev", name, "metric", "100"])
        .status();
    match output {
        Ok(s) if s.success() => log::info!("[tun_t2s] ip route add default IPv4 OK"),
        Ok(s) => log::warn!("[tun_t2s] ip route add default IPv4 failed with status {:?}", s.code()),
        Err(e) => log::warn!("[tun_t2s] ip route add default IPv4 error: {}", e),
    }

    // Add default IPv6 route via TUN
    let output = StdCommand::new("ip")
        .args(["-6", "route", "add", "default", "dev", name, "metric", "100"])
        .status();
    match output {
        Ok(s) if s.success() => log::info!("[tun_t2s] ip route add default IPv6 OK"),
        Ok(s) => log::warn!("[tun_t2s] ip route add default IPv6 failed with status {:?}", s.code()),
        Err(e) => log::warn!("[tun_t2s] ip route add default IPv6 error: {}", e),
    }

    // Save current global DNS, then set Cloudflare DNS via resolvectl
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup_linux.txt");
    if let Some(parent) = dns_backup_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Save current global DNS servers
    if let Ok(output) = StdCommand::new("resolvectl")
        .args(["dns"])
        .output()
    {
        let current = String::from_utf8_lossy(&output.stdout).to_string();
        let _ = std::fs::write(&dns_backup_path, &current);
        log::debug!("[tun_t2s] Saved current DNS state to {}", dns_backup_path.display());
    }
    // Per-link DNS on the TUN interface
    if let Ok(output) = StdCommand::new("resolvectl")
        .args(["dns", name, "1.1.1.1", dns6])
        .output()
    {
        if output.status.success() {
            log::info!("[tun_t2s] resolvectl set link DNS OK");
        } else {
            log::debug!("[tun_t2s] resolvectl set link DNS: {}", String::from_utf8_lossy(&output.stderr).trim());
        }
    }
    // Also set global DNS as fallback to override any per-interface DNS leaks
    if let Ok(output) = StdCommand::new("resolvectl")
        .args(["dns", "1.1.1.1", dns6])
        .output()
    {
        if output.status.success() {
            log::info!("[tun_t2s] resolvectl set global DNS OK");
        } else {
            log::debug!("[tun_t2s] resolvectl set global DNS: {}", String::from_utf8_lossy(&output.stderr).trim());
        }
    }
}

// ── Windows TUN cleanup (remove routes, reset DNS, delete adapter) ─────
// On normal shutdown we remove routes, reset DNS, and delete the TUN adapter.
// This ensures a clean slate. On next startup, the pre-startup check will
// create a fresh adapter without conflicts.
#[cfg(target_os = "windows")]
fn cleanup_windows_tun(cfg: &TunConfig) {
    use std::os::windows::process::CommandExt;
    use std::process::Command as StdCommand;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let name = &cfg.name;
    let ip = cfg.ipv4.split('/').next().filter(|v| !v.is_empty()).unwrap_or("198.18.0.1");
    let ipv6 = cfg.ipv6.as_deref().and_then(|v| if v.is_empty() { None } else { v.split('/').next() }).unwrap_or("fc00::1");

    log::info!("[tun_t2s] Cleaning up Windows TUN adapter '{}'", name);

    let run_silent = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut c = StdCommand::new(cmd);
        c.creation_flags(CREATE_NO_WINDOW);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    };

    // Remove default IPv4 route via the TUN adapter
    let output = run_silent("route", &["DELETE", "0.0.0.0", "MASK", "0.0.0.0", ip]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] route DELETE IPv4 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                log::debug!("[tun_t2s] route DELETE IPv4: {}", stderr.trim());
            }
        }
        Err(e) => log::debug!("[tun_t2s] route DELETE IPv4 error: {}", e),
    }

    // Remove default IPv6 route via the TUN adapter
    let output = run_silent("route", &["DELETE", "::/0", ipv6]);
    match output {
        Ok(o) if o.status.success() => log::info!("[tun_t2s] route DELETE ::/0 OK"),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.trim().is_empty() {
                log::debug!("[tun_t2s] route DELETE ::/0: {}", stderr.trim());
            }
        }
        Err(e) => log::debug!("[tun_t2s] route DELETE ::/0 error: {}", e),
    }

    // Reset DNS on the TUN adapter to DHCP
    let name_hyphen = name.replace('_', "-");
    let _ = run_silent("netsh", &["interface", "ip", "set", "dns", name, "dhcp"]);
    let _ = run_silent("netsh", &["interface", "ipv6", "set", "dns", name, "dhcp"]);
    let _ = run_silent("netsh", &["interface", "ip", "set", "dns", &name_hyphen, "dhcp"]);
    let _ = run_silent("netsh", &["interface", "ipv6", "set", "dns", &name_hyphen, "dhcp"]);

    // Restore DNS on all other adapters from the backup file saved during override.
    // We try PowerShell first (handles JSON backup), then fall back to netsh DHCP reset.
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup.json");
    let dns_backup_str = dns_backup_path.to_string_lossy().replace('\\', "\\\\");
    let ps_restore = format!(
        "$ErrorActionPreference='SilentlyContinue';\
         $backupFile='{backup}';\
         if (Test-Path $backupFile) {{\
             $raw = Get-Content $backupFile -Raw;\
             $raw = $raw -replace '^\\uFEFF', '';\
             if ($raw) {{\
                 try {{ $backup = ConvertFrom-Json $raw }} catch {{ $backup = $null }};\
                 if ($backup) {{\
                     foreach ($b in $backup) {{\
                         $idx = $b.ifIndex;\
                         if ($b.v4) {{ Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses ($b.v4 -split ',') -ErrorAction SilentlyContinue }} else {{ Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses -ErrorAction SilentlyContinue }};\
                         if ($b.v6) {{ Set-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ServerAddresses ($b.v6 -split ',') -ErrorAction SilentlyContinue }} else {{ Set-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ResetServerAddresses -ErrorAction SilentlyContinue }};\
                     }};\
                 }};\
             }};\
             Remove-Item $backupFile -Force -ErrorAction SilentlyContinue;\
         }};\
         Write-Host 'dns_restore_done'",
        backup = dns_backup_str
    );
    let output = run_silent("powershell", &["-NoProfile", "-Command", &ps_restore]);
    let mut restored = false;
    match &output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("dns_restore_done") {
                log::info!("[tun_t2s] DNS restore from backup OK");
                restored = true;
            }
        }
        Err(e) => log::warn!("[tun_t2s] DNS restore PowerShell error: {}", e),
    }

    // Fallback: if PowerShell restore didn't confirm, reset DNS on all adapters to DHCP via netsh
    if !restored {
        log::warn!("[tun_t2s] PowerShell DNS restore did not complete; falling back to netsh DHCP reset on all adapters");
        // Get all adapter names except ours and reset them to DHCP
        let netsh_fallback = format!(
            "$ErrorActionPreference='SilentlyContinue';\
             Get-NetAdapter | Where-Object {{ $_.Name -ne '{name}' -and $_.Name -ne '{name_hyphen}' }} | ForEach-Object {{\
                 netsh interface ip set dns $_.Name dhcp;\
                 netsh interface ipv6 set dns $_.Name dhcp;\
             }};\
             Write-Host 'dns_fallback_done'",
            name = name, name_hyphen = name_hyphen
        );
        let fb_output = run_silent("powershell", &["-NoProfile", "-Command", &netsh_fallback]);
        match fb_output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                if stdout.contains("dns_fallback_done") {
                    log::info!("[tun_t2s] DNS fallback reset to DHCP on all adapters OK");
                } else {
                    log::warn!("[tun_t2s] DNS fallback netsh reset may have failed; stdout: {}", stdout.trim());
                }
            }
            Err(e) => log::error!("[tun_t2s] DNS fallback netsh reset error: {}", e),
        }
    }

    // Delete the TUN adapter — full cleanup so next start is fresh
    cleanup_adapter_by_name(name);

    log::info!("[tun_t2s] TUN adapter '{}' deleted", name);
}

#[cfg(target_os = "linux")]
fn cleanup_linux_tun(cfg: &TunConfig) {
    use std::process::Command as StdCommand;
    let name = &cfg.name;
    log::info!("[tun_t2s] Cleaning up Linux TUN routes for '{}'", name);
    let _ = StdCommand::new("ip").args(["route", "del", "default", "dev", name]).status();
    let _ = StdCommand::new("ip").args(["-6", "route", "del", "default", "dev", name]).status();
    let _ = StdCommand::new("ip").args(["link", "set", name, "down"]).status();
    // Restore DNS from backup: revert the link DNS, then restore global from backup
    let _ = StdCommand::new("resolvectl").args(["revert", name]).status();
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup_linux.txt");
    if dns_backup_path.exists() {
        // Parse the backup to find the original global DNS (lines starting with "Global:")
        if let Ok(backup) = std::fs::read_to_string(&dns_backup_path) {
            // Find the line after "Global:" that has the DNS servers
            let mut found_global = false;
            for line in backup.lines() {
                if line.starts_with("Global:") {
                    found_global = true;
                    continue;
                }
                if found_global && !line.is_empty() && !line.starts_with("Link") {
                    let servers: Vec<&str> = line.split_whitespace().collect();
                    if !servers.is_empty() {
                        let mut args = vec!["dns"];
                        args.extend(&servers);
                        let _ = StdCommand::new("resolvectl").args(&args).status();
                    }
                    break;
                }
            }
        }
        let _ = std::fs::remove_file(&dns_backup_path);
    }
}

#[cfg(target_os = "macos")]
fn cleanup_macos_tun(cfg: &TunConfig) {
    use std::process::Command as StdCommand;
    let name = &cfg.name;
    log::info!("[tun_t2s] Cleaning up macOS TUN routes for '{}'", name);

    // Find the actual utun interface
    let iface = find_macos_utun(name);
    let iface = iface.as_deref().unwrap_or(name);

    // Remove default IPv4 route
    let _ = StdCommand::new("route")
        .args(["delete", "default", "-interface", iface])
        .status();

    // Remove default IPv6 route
    let _ = StdCommand::new("route")
        .args(["delete", "-inet6", "default", "-interface", iface])
        .status();

    // Bring interface down
    let _ = StdCommand::new("ifconfig")
        .args([iface, "down"])
        .status();

    // Restore DNS from backup file saved during override
    let dns_backup_path = std::env::temp_dir().join("fcaevpn").join("dns_backup_macos.txt");
    if dns_backup_path.exists() {
        if let Ok(backup_data) = std::fs::read_to_string(&dns_backup_path) {
            for line in backup_data.lines() {
                if let Some((service, dns)) = line.split_once('|') {
                    let dns = dns.trim();
                    if dns.is_empty() || dns.contains("There aren't any") {
                        let _ = StdCommand::new("networksetup")
                            .args(["-setdnsservers", service, "Empty"])
                            .status();
                    } else {
                        let mut args = vec!["-setdnsservers", service];
                        args.extend(dns.split_whitespace());
                        let _ = StdCommand::new("networksetup")
                            .args(&args)
                            .status();
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&dns_backup_path);
        log::info!("[tun_t2s] DNS restored from backup and backup file deleted");
    } else {
        // Fallback: reset all services to Empty if no backup exists
        if let Ok(services_output) = StdCommand::new("networksetup")
            .args(["-listallnetworkservices"])
            .output()
        {
            let services = String::from_utf8_lossy(&services_output.stdout);
            for service in services.lines().skip(1) {
                let service = service.trim();
                if service.is_empty() || service.starts_with('*') {
                    continue;
                }
                let _ = StdCommand::new("networksetup")
                    .args(["-setdnsservers", service, "Empty"])
                    .status();
            }
        }
    }

    log::info!("[tun_t2s] macOS TUN cleanup complete for '{}'", name);
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

    // ── Pre-startup: remove routes from any leftover adapter (fast) ──
    // The persistent GUID ensures tun2socks reuses the same adapter.
    // We just clear stale routes — no need to delete the adapter before start
    // which was slow (PowerShell + netsh loops + 200ms wait).
    #[cfg(target_os = "windows")]
    {
        log::info!("[tun_t2s] Removing any stale routes on '{}'", cfg.name);
        let ip = cfg.ipv4.split('/').next().filter(|v| !v.is_empty()).unwrap_or("198.18.0.1");
        remove_default_route_windows(ip);
    }

    // Extract embedded binary
    let t2s_path = get_tun2socks_path()?;

    // Build tun2socks arguments
    // Use a persistent GUID on Windows so the adapter name doesn't get a
    // numeric suffix on reconnect (FCAE_VPN 2, FCAE_VPN 3, ...).
    #[cfg(target_os = "windows")]
    let device = format!("tun://{}?guid={{24198F4C-7895-434C-AD65-9E29A92DDC61}}", cfg.name);
    #[cfg(not(target_os = "windows"))]
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

    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut c = Command::new(&t2s_path);
        c.creation_flags(CREATE_NO_WINDOW);
        c
    };
    #[cfg(not(target_os = "windows"))]
    let mut cmd = Command::new(&t2s_path);

    let mut child = cmd
        .current_dir(tun_dir)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AetherError::Other(format!("Failed to spawn tun2socks: {e}")))?;

    let pid = child.id();
    log::info!("[tun_t2s] tun2socks started (pid: {})", pid);

    // RAII guard: ensure the child process is killed when this future is
    // dropped (e.g. by tokio task abort).  Without this, the spawn_blocking
    // wait task below would hang forever on drop(rt), keeping the process
    // alive consuming CPU and triggering antivirus.
    struct ChildGuard {
        pid: u32,
        killed: bool,
    }
    impl ChildGuard {
        fn kill(&mut self) {
            if self.killed { return; }
            self.killed = true;
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                let mut c = Command::new("taskkill");
                c.creation_flags(CREATE_NO_WINDOW);
                let _ = c.args(["/PID", &self.pid.to_string(), "/F", "/T"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe { libc::kill(self.pid as i32, libc::SIGKILL); }
            }
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if !self.killed {
                log::warn!("[tun_t2s] ChildGuard: tun2socks (pid={}) still alive on drop — force killing", self.pid);
                self.kill();
            }
        }
    }
    let mut child_guard = ChildGuard { pid, killed: false };

    // ── Windows: configure TUN adapter routing ──────────────────────
    #[cfg(target_os = "windows")]
    {
        // Give tun2socks a moment to create the adapter
        std::thread::sleep(std::time::Duration::from_millis(1500));
        configure_windows_tun(&cfg);
    }

    // ── Linux: configure TUN routing ───────────────────────────────
    #[cfg(target_os = "linux")]
    {
        std::thread::sleep(std::time::Duration::from_millis(500));
        configure_linux_tun(&cfg);
    }

    // ── macOS: configure TUN routing ───────────────────────────────
    #[cfg(target_os = "macos")]
    {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        configure_macos_tun(&cfg);
    }

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

    // Wait for process in a blocking task — child is moved here
    let wait_handle = tokio::task::spawn_blocking(move || child.wait());
    tokio::pin!(wait_handle);

    tokio::select! {
        _ = shutdown => {
            log::info!("[tun_t2s] Shutting down tun2socks (pid={})", pid);
            // Kill the child process (child_guard handles taskkill /F /T)
            child_guard.kill();
            #[cfg(target_os = "windows")]
            {
                cleanup_windows_tun(&cfg);
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                #[cfg(target_os = "linux")]
                cleanup_linux_tun(&cfg);
                #[cfg(target_os = "macos")]
                cleanup_macos_tun(&cfg);
            }
            // Wait for process to exit with timeout
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                &mut wait_handle
            ).await;
        }
        result = &mut wait_handle => {
            // Child exited on its own — mark as killed so Drop guard is a no-op
            child_guard.killed = true;
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

    // ── Final safety: ensure child process is dead ──
    // The select branches above already handle cleanup on shutdown/exit.
    // This is a last-resort safety net if something went wrong.
    child_guard.kill();

    log::info!("[tun_t2s] TUN shut down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_defaults() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name, "FCAE_VPN");
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.ipv4, "198.18.0.1/24");
        assert_eq!(cfg.socks_port, 1819);
        assert_eq!(cfg.socks_host, "127.0.0.1");
    }
}
