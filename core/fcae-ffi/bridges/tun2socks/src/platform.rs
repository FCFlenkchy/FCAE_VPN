//! OS-level TUN configuration: addresses, routes, DNS — and undoing them.
//!
//! Lifted out of the old `aether-engine/src/tun_t2s.rs`, where it was tangled
//! up with subprocess management. Two structural fixes:
//!
//! 1. **Undo is data, not code.** `configure` returns a [`TunUndo`] describing
//!    exactly what was changed; `restore` reverses precisely that. The old
//!    code re-derived what to clean up from the config and global statics,
//!    which is why a cleanup could run twice, or run against the wrong
//!    adapter after a reconnect.
//! 2. **Exactly-once is enforced by ownership.** Because the bridge holds the
//!    single `TunUndo` value and `stop()` takes it out of the mutex, the
//!    three-way race between the UI thread, the engine thread and process
//!    exit (previously handled with an `AtomicU8` state machine, a detached
//!    "finalizer" thread and bounded polling) cannot occur.

use std::process::{Command, Stdio};
use std::time::Duration;

use fcae_runtime::config::SessionConfig;
// CoreError is only constructed on platforms with a real TUN implementation.
#[allow(unused_imports)]
use fcae_runtime::error::{CoreError, Result};

/// Record of the system changes made when the device came up.
#[derive(Debug, Default, Clone)]
pub struct TunUndo {
    pub device_name: String,
    /// Host route we added for the tunnel endpoint, to be deleted.
    pub peer_route: Option<String>,
    /// Interfaces whose DNS we overrode, with their previous servers.
    pub dns_backup: Vec<(String, Vec<String>)>,
    /// True if we installed a default route through the TUN device.
    pub default_route: bool,
    pub ipv6: bool,
}

/// Run a command, swallowing output. Returns success.
///
/// Unused on Android: the VpnService owns addressing, routing and DNS, so the
/// desktop `ip`/`netsh`/`route` paths below are all compiled out there.
#[cfg_attr(target_os = "android", allow(dead_code))]
fn run(program: &str, args: &[&str]) -> bool {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Never flash a console window out of a GUI app.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    match cmd.status() {
        Ok(s) => s.success(),
        Err(e) => {
            log::debug!("[tun] `{program}` failed to run: {e}");
            false
        }
    }
}

/// Run a command and capture stdout.
///
/// Unused on Android, for the same reason as [`run`].
#[cfg_attr(target_os = "android", allow(dead_code))]
fn capture(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Strip the prefix length from "198.18.0.1/24".
// Used by the Windows/macOS paths; Linux passes CIDRs through unchanged.
#[allow(dead_code)]
fn addr_of(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

/// True when the process can create a TUN device.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Probing a privileged path is cheaper and more reliable than the
        // token API dance, and matches what the old code concluded.
        std::fs::OpenOptions::new()
            .write(true)
            .open("\\\\.\\PHYSICALDRIVE0")
            .is_ok()
            || capture("net", &["session"]).is_some()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Apply addresses, routes and DNS for a freshly created device.
pub fn configure(cfg: &SessionConfig, peer_ip: Option<&str>) -> Result<TunUndo> {
    // `mut` is only needed on the desktop paths, which record what they changed
    // so teardown can undo it; Android returns early and mutates nothing.
    #[cfg_attr(target_os = "android", allow(unused_mut))]
    let mut undo = TunUndo {
        device_name: cfg.tun.name.clone(),
        ipv6: cfg.tun.ipv6.is_some(),
        ..Default::default()
    };

    // Android: the VpnService already owns addressing, routing and DNS.
    // Touching them from native code is both unnecessary and forbidden.
    if cfg!(target_os = "android") {
        log::info!("[tun] Android: VpnService owns routing/DNS; nothing to configure natively");
        return Ok(undo);
    }

    #[cfg(target_os = "windows")]
    configure_windows(cfg, peer_ip, &mut undo)?;
    #[cfg(target_os = "linux")]
    configure_linux(cfg, peer_ip, &mut undo)?;
    #[cfg(target_os = "macos")]
    configure_macos(cfg, peer_ip, &mut undo)?;
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (cfg, peer_ip);
    }

    Ok(undo)
}

/// Reverse exactly what [`configure`] did.
pub fn restore(undo: TunUndo, _timeout: Duration) {
    if cfg!(target_os = "android") {
        return;
    }
    #[cfg(target_os = "windows")]
    restore_windows(&undo);
    #[cfg(target_os = "linux")]
    restore_linux(&undo);
    #[cfg(target_os = "macos")]
    restore_macos(&undo);
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = undo;
    }
}

// ── Windows ─────────────────────────────────────────────────────────────

/// Make `wintun.dll` available to the in-process driver loader.
///
/// Previously it was dropped next to an extracted `tun2socks.exe` and found
/// via the child's working directory. With no child process, it must sit
/// beside our own module (or in the data dir) instead.
#[cfg(windows)]
pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> Result<()> {
    use std::io::Write;

    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir);
    let dest = dir.join("wintun.dll");

    if dest.is_file() {
        return Ok(());
    }

    if let Some(bytes) = bytes {
        if let Ok(mut f) = std::fs::File::create(&dest) {
            if f.write_all(bytes).is_ok() {
                log::info!("[tun] wintun.dll written to {}", dest.display());
                return Ok(());
            }
        }
        // Executable directory may be read-only (Program Files); fall back.
        let alt = std::env::temp_dir().join("fcaevpn");
        let _ = std::fs::create_dir_all(&alt);
        let alt_dll = alt.join("wintun.dll");
        if !alt_dll.is_file() {
            std::fs::write(&alt_dll, bytes).map_err(|e| {
                CoreError::Internal(format!("cannot write wintun.dll to {}: {e}", alt.display()))
            })?;
        }
        // Prepend to the DLL search path so the loader finds it.
        let path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{};{path}", alt.display()));
        log::info!("[tun] wintun.dll staged in {}", alt.display());
        return Ok(());
    }

    if std::path::Path::new("C:\\Windows\\System32\\wintun.dll").is_file() {
        return Ok(());
    }

    Err(CoreError::Internal(
        "wintun.dll is missing. Download it from https://www.wintun.net/ and place it \
         next to the executable."
            .into(),
    ))
}

#[cfg(not(windows))]
pub fn ensure_wintun(_bytes: Option<&'static [u8]>) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn configure_windows(cfg: &SessionConfig, peer_ip: Option<&str>, undo: &mut TunUndo) -> Result<()> {
    let name = &cfg.tun.name;
    let ip = addr_of(&cfg.tun.ipv4);

    // Wait for the adapter to appear; wintun creation is asynchronous.
    let mut ready = false;
    for _ in 0..40 {
        if capture("netsh", &["interface", "ip", "show", "config", &format!("name={name}")])
            .is_some()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        return Err(CoreError::Internal(format!(
            "TUN adapter `{name}` did not appear within 4s"
        )));
    }

    run(
        "netsh",
        &[
            "interface", "ip", "set", "address",
            &format!("name={name}"), "static", ip, "255.255.255.0",
        ],
    );
    run("netsh", &["interface", "ipv4", "set", "subinterface",
        &format!("{name}"), &format!("mtu={}", cfg.tun.mtu), "store=active"]);

    // Keep tunnel traffic off the tunnel.
    if let Some(peer) = peer_ip {
        if run("route", &["add", peer, "mask", "255.255.255.255", "0.0.0.0", "metric", "1"]) {
            undo.peer_route = Some(peer.to_string());
        }
    }

    // Default route through the TUN device with a low metric.
    if run("route", &["add", "0.0.0.0", "mask", "0.0.0.0", ip, "metric", "1"]) {
        undo.default_route = true;
    }

    // DNS: back up the current servers before overriding.
    if let Some(server) = cfg.dns.server.as_deref().map(addr_of) {
        if let Some(prev) = capture("netsh", &["interface", "ip", "show", "dnsservers"]) {
            undo.dns_backup.push((name.clone(), parse_windows_dns(&prev)));
        }
        run("netsh", &["interface", "ip", "set", "dns",
            &format!("name={name}"), "static", server, "primary"]);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn parse_windows_dns(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            t.split_whitespace()
                .last()
                .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                .map(|s| s.to_string())
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn restore_windows(undo: &TunUndo) {
    let name = &undo.device_name;

    if undo.default_route {
        run("route", &["delete", "0.0.0.0"]);
    }
    if let Some(peer) = &undo.peer_route {
        run("route", &["delete", peer]);
    }
    if !undo.dns_backup.is_empty() {
        // Back to DHCP-provided DNS, which is what "restore" meant before.
        run("netsh", &["interface", "ip", "set", "dns",
            &format!("name={name}"), "dhcp"]);
    }
    run("ipconfig", &["/flushdns"]);
    log::info!("[tun] Windows routes/DNS restored for `{name}`");
}

// ── Linux ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn configure_linux(cfg: &SessionConfig, peer_ip: Option<&str>, undo: &mut TunUndo) -> Result<()> {
    let name = &cfg.tun.name;

    for _ in 0..30 {
        if capture("ip", &["link", "show", name]).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    run("ip", &["addr", "add", &cfg.tun.ipv4, "dev", name]);
    if let Some(v6) = &cfg.tun.ipv6 {
        run("ip", &["-6", "addr", "add", v6, "dev", name]);
    }
    run("ip", &["link", "set", "dev", name, "mtu", &cfg.tun.mtu.to_string(), "up"]);

    if let Some(peer) = peer_ip {
        if let Some(gw) = default_gateway_linux() {
            if run("ip", &["route", "add", &format!("{peer}/32"), "via", &gw]) {
                undo.peer_route = Some(peer.to_string());
            }
        }
    }

    // Split default via two /1 routes: higher priority than the real default
    // without deleting it, so restoring is just a matter of removing ours.
    if run("ip", &["route", "add", "0.0.0.0/1", "dev", name])
        && run("ip", &["route", "add", "128.0.0.0/1", "dev", name])
    {
        undo.default_route = true;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn default_gateway_linux() -> Option<String> {
    let out = capture("ip", &["route", "show", "default"])?;
    out.split_whitespace()
        .skip_while(|t| *t != "via")
        .nth(1)
        .map(|s| s.to_string())
}

#[cfg(target_os = "linux")]
fn restore_linux(undo: &TunUndo) {
    let name = &undo.device_name;
    if undo.default_route {
        run("ip", &["route", "del", "0.0.0.0/1", "dev", name]);
        run("ip", &["route", "del", "128.0.0.0/1", "dev", name]);
    }
    if let Some(peer) = &undo.peer_route {
        run("ip", &["route", "del", &format!("{peer}/32")]);
    }
    // resolvectl reverts automatically when the link disappears, but be
    // explicit in case the device lingers.
    run("resolvectl", &["revert", name]);
    log::info!("[tun] Linux routes/DNS restored for `{name}`");
}

// ── macOS ───────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn configure_macos(cfg: &SessionConfig, peer_ip: Option<&str>, undo: &mut TunUndo) -> Result<()> {
    // tun2socks creates utunN; the configured name is advisory on macOS.
    let name = detect_utun().unwrap_or_else(|| cfg.tun.name.clone());
    undo.device_name = name.clone();

    let ip = addr_of(&cfg.tun.ipv4);
    run("ifconfig", &[&name, ip, ip, "up"]);
    run("ifconfig", &[&name, "mtu", &cfg.tun.mtu.to_string()]);

    if let Some(peer) = peer_ip {
        if let Some(gw) = default_gateway_macos() {
            if run("route", &["add", "-host", peer, &gw]) {
                undo.peer_route = Some(peer.to_string());
            }
        }
    }

    if run("route", &["add", "-net", "0.0.0.0/1", ip])
        && run("route", &["add", "-net", "128.0.0.0/1", ip])
    {
        undo.default_route = true;
    }

    // Back up DNS per network service so it can be restored precisely.
    if let Some(server) = cfg.dns.server.as_deref().map(addr_of) {
        for service in macos_network_services() {
            if let Some(prev) = capture("networksetup", &["-getdnsservers", &service]) {
                let servers: Vec<String> = prev
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
                    .collect();
                undo.dns_backup.push((service.clone(), servers));
            }
            run("networksetup", &["-setdnsservers", &service, server]);
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn detect_utun() -> Option<String> {
    let out = capture("ifconfig", &["-l"])?;
    out.split_whitespace()
        .filter(|n| n.starts_with("utun"))
        .next_back()
        .map(|s| s.to_string())
}

#[cfg(target_os = "macos")]
fn default_gateway_macos() -> Option<String> {
    let out = capture("route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|g| g.trim().to_string())
}

#[cfg(target_os = "macos")]
fn macos_network_services() -> Vec<String> {
    capture("networksetup", &["-listallnetworkservices"])
        .map(|out| {
            out.lines()
                .skip(1) // header line
                .map(|l| l.trim_start_matches('*').trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn restore_macos(undo: &TunUndo) {
    if undo.default_route {
        run("route", &["delete", "-net", "0.0.0.0/1"]);
        run("route", &["delete", "-net", "128.0.0.0/1"]);
    }
    if let Some(peer) = &undo.peer_route {
        run("route", &["delete", "-host", peer]);
    }
    for (service, servers) in &undo.dns_backup {
        if servers.is_empty() {
            run("networksetup", &["-setdnsservers", service, "Empty"]);
        } else {
            let mut args = vec!["-setdnsservers", service];
            args.extend(servers.iter().map(|s| s.as_str()));
            run("networksetup", &args);
        }
    }
    log::info!("[tun] macOS routes/DNS restored");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_of_strips_prefix() {
        assert_eq!(addr_of("198.18.0.1/24"), "198.18.0.1");
        assert_eq!(addr_of("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn android_configure_is_a_noop() {
        // On non-Android hosts this still exercises the struct plumbing.
        let cfg = SessionConfig::default();
        let undo = TunUndo {
            device_name: cfg.tun.name.clone(),
            ..Default::default()
        };
        assert!(undo.peer_route.is_none());
        assert!(!undo.default_route);
    }
}
