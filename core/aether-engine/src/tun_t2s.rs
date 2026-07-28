//! TUN implementation using hev-socks5-tunnel (https://github.com/heiher/hev-socks5-tunnel)
//! as the TUN engine.
//!
//! hev-socks5-tunnel is invoked as a subprocess with appropriate configuration.
//!
//! Flow: hev-socks5-tunnel (TUN) → Engine (SOCKS5 proxy) → Internet
//!
//! The Android implementation in tun.rs remains untouched.

use std::process::{Command, Stdio};
use tokio::sync::oneshot;

use crate::error::{AetherError, Result};

#[cfg(all(not(target_os = "android"), hevsocks5_available))]
static HEVSOCKS5_BYTES: &[u8] = include_bytes!(env!("HEVSOCKS5_EMBEDDED"));

#[cfg(all(not(target_os = "android"), wintun_embedded))]
static WINTUN_DLL_BYTES: &[u8] = include_bytes!(env!("WINTUN_EMBEDDED"));

#[cfg(all(not(target_os = "android"), hevsocks5_available))]
fn get_hevsocks5_path() -> Result<std::path::PathBuf> {
    use std::io::Write;
    if let Ok(path) = std::env::var("HEVSOCKS5_BIN") {
        let p = std::path::PathBuf::from(&path);
        if p.exists() { return Ok(p); }
    }
    let dir = std::env::temp_dir().join("fcaevpn");
    std::fs::create_dir_all(&dir).ok();
    #[cfg(target_os = "windows")]
    let name = "hev-socks5-tunnel.exe";
    #[cfg(not(target_os = "windows"))]
    let name = "hev-socks5-tunnel";
    let dest = dir.join(name);
    let needs_write = match std::fs::metadata(&dest) {
        Ok(m) => m.len() != HEVSOCKS5_BYTES.len() as u64,
        Err(_) => true,
    };
    if needs_write {
        let mut f = std::fs::File::create(&dest)
            .map_err(|e| AetherError::Other(format!("Failed to create hev-socks5-tunnel binary: {e}")))?;
        f.write_all(HEVSOCKS5_BYTES)
            .map_err(|e| AetherError::Other(format!("Failed to write hev-socks5-tunnel binary: {e}")))?;
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)
                .map_err(|e| AetherError::Other(format!("stat: {e}")))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms).ok();
        }
    }
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
            }
            #[cfg(not(wintun_embedded))]
            {
                let mut found = false;
                for candidate in &[
                    std::path::PathBuf::from("C:\\Windows\\System32\\wintun.dll"),
                    std::env::current_exe().unwrap_or_default().parent()
                        .unwrap_or(std::path::Path::new(".")).join("wintun.dll"),
                    std::path::PathBuf::from("wintun.dll"),
                ] {
                    if candidate.exists() {
                        if std::fs::copy(candidate, &wintun_dest).is_ok() { found = true; break; }
                    }
                }
                if !found {
                    return Err(AetherError::Other(format!(
                        "wintun.dll not found. Download from https://www.wintun.net/ and place in: {}",
                        dir.display()
                    )));
                }
            }
        }
    }
    Ok(dest)
}

#[cfg(target_os = "windows")]
fn wintun_dll_expected_size() -> usize {
    #[cfg(wintun_embedded)] { WINTUN_DLL_BYTES.len() }
    #[cfg(not(wintun_embedded))] { 0 }
}

#[cfg(all(not(target_os = "android"), not(hevsocks5_available)))]
fn get_hevsocks5_path() -> Result<std::path::PathBuf> {
    Err(AetherError::Other("hev-socks5-tunnel binary not embedded (build skipped)".into()))
}

#[cfg(target_os = "android")]
fn get_hevsocks5_path() -> Result<std::path::PathBuf> {
    Err(AetherError::Other("hev-socks5-tunnel not available on Android".into()))
}

pub fn is_available() -> bool {
    #[cfg(target_os = "android")] { return false; }
    #[cfg(not(hevsocks5_available))] { return false; }
    #[cfg(all(not(target_os = "android"), hevsocks5_available))] { get_hevsocks5_path().is_ok() }
}

#[cfg(target_os = "windows")]
pub fn force_cleanup_windows(name: &str) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    log::info!("[tun_t2s] Force-killing hev-socks5-tunnel processes");
    for args in [vec!["/IM", "hev-socks5-tunnel.exe", "/F", "/T"],
                  vec!["/FI", "IMAGENAME eq hev-socks5-tunnel.exe", "/F", "/T"]] {
        let mut c = Command::new("taskkill");
        c.creation_flags(CREATE_NO_WINDOW);
        let _ = c.args(&args).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    cleanup_adapter_by_name(name);
}

#[cfg(not(target_os = "windows"))]
pub fn force_cleanup_windows(_name: &str) {}

#[cfg(target_os = "windows")]
fn cleanup_adapter_by_name(name: &str) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let run = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut c = Command::new(cmd);
        c.creation_flags(CREATE_NO_WINDOW);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    };
    let name_h = name.replace('_', "-");
    let name_u = name.replace('-', "_");
    let _ = run("powershell", &["-NoProfile", "-Command", &format!(
        "Get-NetAdapter -Name '{}*','{}*' -ErrorAction SilentlyContinue | Remove-NetAdapter -Confirm:$false", name, name_h)]);
    let _ = run("netsh", &["interface", "ip", "delete", "interface", name]);
    let _ = run("netsh", &["interface", "ip", "delete", "interface", &name_h]);
    if name_h != name_u { let _ = run("netsh", &["interface", "ip", "delete", "interface", &name_u]); }
    for i in 2..20 {
        let num = format!("{} {}", name, i);
        if !run("netsh", &["interface", "ip", "delete", "interface", &num]).map(|o| o.status.success()).unwrap_or(false) { break; }
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_adapter_by_name(_name: &str) {}

#[derive(Clone)]
pub struct TunConfig {
    pub name: String, pub mtu: u32, pub ipv4: String, pub ipv6: Option<String>,
    pub socks_port: u16, pub socks_host: String, pub username: Option<String>,
    pub password: Option<String>, pub tunnel_peer_ip: Option<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self { name: "FCAE_VPN".into(), mtu: 1500, ipv4: "198.18.0.1/24".into(),
               ipv6: None, socks_port: 1819, socks_host: "127.0.0.1".into(),
               username: None, password: None, tunnel_peer_ip: None }
    }
}

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn OpenProcessToken(h: isize, a: u32, t: *mut isize) -> i32;
        fn CloseHandle(h: isize) -> i32;
        fn AllocateAndInitializeSid(a: *const u8, c: u8, s0: u32, s1: u32, s2: u32, s3: u32, s4: u32, s5: u32, s6: u32, s7: u32, s: *mut isize) -> i32;
        fn CheckTokenMembership(t: isize, s: isize, m: *mut i32) -> i32;
        fn FreeSid(s: isize) -> *mut std::ffi::c_void;
    }
    const TOKEN_QUERY: u32 = 0x0008;
    const NT_AUTH: [u8; 6] = [0,0,0,0,0,5];
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 { return false; }
        let mut sid: isize = 0;
        if AllocateAndInitializeSid(NT_AUTH.as_ptr(), 2, 32, 544, 0,0,0,0,0,0, &mut sid) == 0 { CloseHandle(token); return false; }
        let mut member: i32 = 0;
        let ok = CheckTokenMembership(0, sid, &mut member) != 0 && member != 0;
        FreeSid(sid); CloseHandle(token); ok
    }
}

#[cfg(not(target_os = "windows"))]
fn is_admin() -> bool { unsafe { libc::geteuid() == 0 } }

#[cfg(target_os = "windows")]
fn configure_windows_tun(cfg: &TunConfig) {
    use std::os::windows::process::CommandExt;
    use std::process::Command as Cmd;
    const NO_WIN: u32 = 0x08000000;
    let run = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut c = Cmd::new(cmd); c.creation_flags(NO_WIN);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    };
    let name = &cfg.name;
    let ip = cfg.ipv4.split('/').next().unwrap_or(&cfg.ipv4);
    let _ = run("netsh", &["interface","ip","set","address",name,"static",ip,"255.255.255.0"]);
    let _ = run("netsh", &["interface","ip","set","dns",name,"static","1.1.1.1"]);
    let name_h = name.replace('_', "-");
    if let Ok(o) = run("powershell", &["-NoProfile","-Command", &format!(
        "$a=Get-NetAdapter -Name '{{}}','{{}}' -ErrorAction SilentlyContinue|Select -First 1;if($a){{$a.ifIndex}}", name, name_h)])
    {
        if let Ok(idx) = String::from_utf8_lossy(&o.stdout).trim().parse::<u32>() {
            let _ = run("netsh", &["interface","ipv4","set","interface", &idx.to_string(), "metric=5"]);
            let _ = run("route", &["ADD","0.0.0.0","MASK","0.0.0.0",ip,"METRIC","5","IF", &idx.to_string()]);
            if let Some(ref peer_ip) = cfg.tunnel_peer_ip {
                if let Ok(o) = run("powershell", &["-NoProfile","-Command",
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|?{$_.NextHop -ne '0.0.0.0'}|Sort RouteMetric|Select -First 1).NextHop"])
                {
                    let gw = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if !gw.is_empty() { let _ = run("route", &["ADD",peer_ip,"MASK","255.255.255.255",&gw]); }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_tun(cfg: &TunConfig) {
    use std::process::Command as Cmd;
    let _ = Cmd::new("ip").args(["addr","add", &cfg.ipv4,"dev", &cfg.name]).status();
    let _ = Cmd::new("ip").args(["link","set", &cfg.name,"up"]).status();
    let _ = Cmd::new("ip").args(["route","add","default","dev", &cfg.name,"metric","100"]).status();
}

#[cfg(target_os = "windows")]
fn cleanup_windows_tun(cfg: &TunConfig) {
    use std::os::windows::process::CommandExt;
    use std::process::Command as Cmd;
    const NO_WIN: u32 = 0x08000000;
    let run = |cmd: &str, args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut c = Cmd::new(cmd); c.creation_flags(NO_WIN);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()
    };
    let ip = cfg.ipv4.split('/').next().unwrap_or(&cfg.ipv4);
    let _ = run("route", &["DELETE","0.0.0.0","MASK","0.0.0.0",ip]);
    let name_h = cfg.name.replace('_', "-");
    let _ = run("powershell", &["-NoProfile","-Command", &format!(
        "Get-NetAdapter -Name '{}*','{}*' -ErrorAction SilentlyContinue|Remove-NetAdapter -Confirm:$false", cfg.name, name_h)]);
    let _ = run("netsh", &["interface","ip","set","dns", &cfg.name,"dhcp"]);
    let _ = run("netsh", &["interface","ip","delete","interface", &cfg.name]);
}

#[cfg(target_os = "linux")]
fn cleanup_linux_tun(cfg: &TunConfig) {
    use std::process::Command as Cmd;
    let _ = Cmd::new("ip").args(["route","del","default","dev", &cfg.name]).status();
    let _ = Cmd::new("ip").args(["link","set", &cfg.name,"down"]).status();
}

pub async fn run_tun2socks(cfg: TunConfig, shutdown: oneshot::Receiver<()>) -> Result<()> {
    log::info!("[tun_t2s] Starting TUN with hev-socks5-tunnel");
    if !is_admin() {
        return Err(AetherError::Other(
            "TUN mode requires administrator privileges. Run as Administrator (Windows) or with sudo (Linux).".into()));
    }
    #[cfg(target_os = "windows")]
    cleanup_adapter_by_name(&cfg.name);
    let hev_path = get_hevsocks5_path()?;
    let ip = cfg.ipv4.split('/').next().unwrap_or(&cfg.ipv4);
    let prefix = cfg.ipv4.split('/').nth(1).and_then(|p| p.parse().ok()).unwrap_or(24);
    let tun_url = format!("tun://{}?ipv4={}/{}&mtu={}", cfg.name, ip, prefix, cfg.mtu);
    let socks_addr = if let (Some(ref u), Some(ref p)) = (&cfg.username, &cfg.password) {
        format!("{}:{}@{}:{}", u, p, cfg.socks_host, cfg.socks_port)
    } else {
        format!("{}:{}", cfg.socks_host, cfg.socks_port)
    };
    let args = vec![tun_url, "--socks5-addr".to_string(), socks_addr];
    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        const NO_WIN: u32 = 0x08000000;
        let mut c = Command::new(&hev_path);
        c.creation_flags(NO_WIN); c
    };
    #[cfg(not(target_os = "windows"))]
    let mut cmd = Command::new(&hev_path);
    let tun_dir = hev_path.parent().unwrap_or(std::path::Path::new("."));
    let mut child = cmd.current_dir(tun_dir).args(&args)
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|e| AetherError::Other(format!("Failed to spawn hev-socks5-tunnel: {e}")))?;
    let pid = child.id();
    log::info!("[tun_t2s] hev-socks5-tunnel started (pid={})", pid);
    #[cfg(target_os = "windows")]
    { std::thread::sleep(std::time::Duration::from_millis(1500)); configure_windows_tun(&cfg); }
    #[cfg(target_os = "linux")]
    { std::thread::sleep(std::time::Duration::from_millis(500)); configure_linux_tun(&cfg); }
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(stdout).lines().flatten() {
                log::info!("[hev-socks5-tunnel] {}", line);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(stderr).lines().flatten() {
                log::info!("[hev-socks5-tunnel] {}", line);
            }
        });
    }
    let wait_handle = tokio::task::spawn_blocking(move || child.wait());
    tokio::pin!(wait_handle);
    tokio::select! {
        _ = shutdown => {
            log::info!("[tun_t2s] Shutting down hev-socks5-tunnel (pid={})", pid);
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const NO_WIN: u32 = 0x08000000;
                for f in [false, true] {
                    let mut c = Command::new("taskkill"); c.creation_flags(NO_WIN);
                    let pid_str = pid.to_string();
                    let mut args = vec!["/PID", &pid_str, "/T"];
                    if f { args.push("/F"); }
                    let _ = c.args(&args).stdout(Stdio::null()).stderr(Stdio::null()).status();
                }
                cleanup_windows_tun(&cfg);
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                #[cfg(target_os = "linux")] cleanup_linux_tun(&cfg);
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut wait_handle).await;
        }
        result = &mut wait_handle => {
            match result {
                Ok(Ok(s)) if s.success() => log::info!("[tun_t2s] hev-socks5-tunnel exited normally"),
                Ok(Ok(s)) => return Err(AetherError::Other(format!("hev-socks5-tunnel exited with code {:?}", s.code()))),
                Ok(Err(e)) => return Err(AetherError::Other(format!("hev-socks5-tunnel process error: {}", e))),
                Err(e) => return Err(AetherError::Other(format!("hev-socks5-tunnel join error: {}", e))),
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const NO_WIN: u32 = 0x08000000;
        let mut c = Command::new("taskkill"); c.creation_flags(NO_WIN);
        let pid_str2 = pid.to_string();
        let _ = c.args(["/PID", &pid_str2, "/F", "/T"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        cleanup_windows_tun(&cfg);
    }
    #[cfg(target_os = "linux")]
    { unsafe { libc::kill(pid as i32, libc::SIGKILL); } cleanup_linux_tun(&cfg); }
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
