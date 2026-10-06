//! System DNS setup shared by TUN engines. Android's VpnService owns its DNS.

use std::net::{IpAddr, SocketAddr};
use crate::config::SessionConfig;
use crate::error::{CoreError, Result};

/// IPv4 resolvers a Psiphon exit relays to through its UDP gateway. Empty
/// means the exit answers with its own resolver.
pub fn psiphon_resolvers(cfg: &SessionConfig) -> Result<Vec<std::net::Ipv4Addr>> {
    let mut result = Vec::new();
    for entry in cfg.dns.server.as_deref().unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let ip = entry.parse::<IpAddr>().ok().or_else(|| {
            entry.parse::<SocketAddr>().ok().filter(|a| a.port() == 53).map(|a| a.ip())
        }).ok_or_else(|| CoreError::InvalidConfig(format!("TUN DNS must be an IP address on port 53: {entry}")))?;
        let IpAddr::V4(v4) = ip else { continue };
        if v4.is_unspecified() || v4.is_multicast() || v4.is_loopback() || v4.is_broadcast() {
            return Err(CoreError::InvalidConfig(format!("invalid TUN DNS address: {entry}")));
        }
        if !result.contains(&v4) { result.push(v4); }
    }
    Ok(result)
}

pub fn servers(cfg: &SessionConfig) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in cfg.dns.server.as_deref().unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let ip = entry.parse::<IpAddr>().ok().or_else(|| {
            entry.parse::<SocketAddr>().ok().filter(|a| a.port() == 53).map(|a| a.ip())
        }).ok_or_else(|| CoreError::InvalidConfig(format!("TUN DNS must be an IP address on port 53: {entry}")))?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
            return Err(CoreError::InvalidConfig(format!("invalid TUN DNS address: {entry}")));
        }
        if ip.is_ipv6() && cfg.tun.ipv6.is_none() { continue; }
        let ip = ip.to_string();
        if !result.contains(&ip) { result.push(ip); }
    }
    Ok(result)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::unix_tun::{state_path, write_atomic};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn run(program: &str, args: &[&str]) -> Result<String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(program).args(args).env("LC_ALL", "C")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|e| CoreError::Internal(format!("TUN DNS: cannot run {program}: {e}")))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CoreError::Internal(format!("TUN DNS: {program} did not finish within 3 seconds")));
            }
        }
    }
    let output = child.wait_with_output().map_err(|e| CoreError::Internal(format!("TUN DNS: {program}: {e}")))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() || text.contains("** Error:") {
        return Err(CoreError::Internal(format!("TUN DNS: {program} {} failed; check permissions and resolver service", args.join(" "))));
    }
    Ok(text)
}

/// True when `program` resolves to a regular file on PATH or in the standard
/// sbin fallbacks (resolvectl/resolvconf live in /usr/bin or /usr/sbin
/// depending on the distro, and a spawn attempt would conflate "absent" with
/// "busy").
#[cfg(target_os = "linux")]
fn have(program: &str) -> bool {
    let on_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false);
    on_path
        || ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .any(|dir| std::path::Path::new(dir).join(program).is_file())
}

#[cfg(target_os = "linux")]
fn run_stdin(program: &str, args: &[&str], input: &str) -> Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| CoreError::Internal(format!("TUN DNS: cannot run {program}: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|e| CoreError::Internal(format!("TUN DNS: {program}: {e}")))?;
    if !output.status.success() {
        return Err(CoreError::Internal(format!(
            "TUN DNS: {program} {} failed; check permissions and resolver service",
            args.join(" ")
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
const RESOLV_CONF: &str = "/etc/resolv.conf";
#[cfg(target_os = "linux")]
const LEGACY_RESOLV_BACKUP: &str = "/run/fcae-resolv.conf.pre-fcae";
#[cfg(target_os = "linux")]
const RESOLV_MARKER: &str = "# written by FCAE VPN";
#[cfg(target_os = "linux")]
const BACKUP_FILE: &str = "resolv.conf";
#[cfg(target_os = "linux")]
const BACKUP_LINK: &str = "resolv.conf.link";
#[cfg(target_os = "linux")]
const BACKUP_ABSENT: &str = "resolv.conf.absent";
#[cfg(target_os = "linux")]
const RESOLVCONF_IFACE: &str = "resolvconf.iface";
#[cfg(target_os = "macos")]
const MACOS_BACKUP: &str = "dns-backup";

/// Which resolver manager owns the Linux DNS override. Picked once per
/// session so [`restore_linux`] undoes exactly what was applied; desktops
/// without systemd-resolved (Alpine, Devuan, containers, WSL1) fall through
/// to managing /etc/resolv.conf directly instead of refusing to run TUN.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub enum LinuxDns {
    Resolvectl,
    Resolvconf,
    /// The previous /etc/resolv.conf is persisted under the state directory.
    ResolvConf,
}

#[cfg(target_os = "linux")]
fn resolv_conf_is_ours() -> bool {
    let path = std::path::Path::new(RESOLV_CONF);
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
        && std::fs::read(path).is_ok_and(|old| {
            old.windows(RESOLV_MARKER.len()).any(|w| w == RESOLV_MARKER.as_bytes())
        })
}

#[cfg(target_os = "linux")]
fn resolv_backup_exists() -> bool {
    [BACKUP_FILE, BACKUP_LINK, BACKUP_ABSENT].iter().any(|n| state_path(n).exists())
}

/// Snapshot /etc/resolv.conf as it is: a symlink is kept as a symlink so the
/// resolver manager behind it keeps ownership after restore.
#[cfg(target_os = "linux")]
fn backup_resolv_conf() -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(RESOLV_CONF);
    if std::path::Path::new(LEGACY_RESOLV_BACKUP).exists() {
        write_atomic(&state_path(BACKUP_FILE), &std::fs::read(LEGACY_RESOLV_BACKUP)?)?;
        return std::fs::remove_file(LEGACY_RESOLV_BACKUP);
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            write_atomic(&state_path(BACKUP_LINK), std::fs::read_link(path)?.as_os_str().as_bytes())
        }
        Ok(_) => write_atomic(&state_path(BACKUP_FILE), &std::fs::read(path)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_atomic(&state_path(BACKUP_ABSENT), b""),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn apply_resolv_conf(servers: &[String]) -> Result<()> {
    let fail = |what: &str, e: std::io::Error| CoreError::Internal(format!("TUN DNS: cannot {what} {RESOLV_CONF}: {e}"));
    if !resolv_backup_exists() {
        if resolv_conf_is_ours() && !std::path::Path::new(LEGACY_RESOLV_BACKUP).exists() {
            log::warn!("TUN DNS: {RESOLV_CONF} is a leftover FCAE override with no backup; it is kept as the fallback");
        } else {
            backup_resolv_conf().map_err(|e| fail("back up", e))?;
        }
    }
    let mut text = String::from(RESOLV_MARKER);
    text.push('\n');
    for server in servers {
        text.push_str(&format!("nameserver {server}\n"));
    }
    write_atomic(std::path::Path::new(RESOLV_CONF), text.as_bytes()).map_err(|e| fail("write", e))
}

/// Put the persisted /etc/resolv.conf back if the file is still ours; a file
/// rewritten since by another manager wins and the backup is discarded.
#[cfg(target_os = "linux")]
fn restore_resolv_conf() {
    use std::os::unix::ffi::OsStringExt;
    if !resolv_backup_exists() {
        return;
    }
    let path = std::path::Path::new(RESOLV_CONF);
    let restored = (|| -> std::io::Result<()> {
        if !resolv_conf_is_ours() {
            return Ok(());
        }
        if let Ok(target) = std::fs::read(state_path(BACKUP_LINK)) {
            let tmp = std::path::PathBuf::from(format!("{RESOLV_CONF}.fcae-tmp"));
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(std::ffi::OsString::from_vec(target), &tmp)?;
            std::fs::rename(&tmp, path)
        } else if let Ok(old) = std::fs::read(state_path(BACKUP_FILE)) {
            write_atomic(path, &old)
        } else {
            std::fs::remove_file(path)
        }
    })();
    match restored {
        Ok(()) => {
            for name in [BACKUP_FILE, BACKUP_LINK, BACKUP_ABSENT] {
                let _ = std::fs::remove_file(state_path(name));
            }
        }
        Err(e) => log::warn!("TUN DNS: cannot restore {RESOLV_CONF}: {e}"),
    }
}

#[cfg(target_os = "linux")]
pub fn configure_linux(cfg: &SessionConfig, interface: &str) -> Result<(Vec<String>, LinuxDns)> {
    let servers = servers(cfg)?;
    if servers.is_empty() {
        return Ok((Vec::new(), LinuxDns::Resolvectl));
    }
    let dns = if have("resolvectl") {
        let mut args = vec!["dns", interface];
        args.extend(servers.iter().map(String::as_str));
        run("resolvectl", &args)?;
        run("resolvectl", &["domain", interface, "~."])?;
        run("resolvectl", &["default-route", interface, "yes"])?;
        LinuxDns::Resolvectl
    } else if have("resolvconf") {
        let mut text = String::new();
        for server in &servers {
            text.push_str(&format!("nameserver {server}\n"));
        }
        if let Err(e) = write_atomic(&state_path(RESOLVCONF_IFACE), interface.as_bytes()) {
            log::warn!("TUN DNS: cannot persist resolvconf state: {e}");
        }
        run_stdin("resolvconf", &["-a", interface], &text)?;
        LinuxDns::Resolvconf
    } else {
        apply_resolv_conf(&servers)?;
        LinuxDns::ResolvConf
    };
    let mut routes = Vec::new();
    let added: Result<()> = (|| {
        for server in &servers {
            let family = if server.contains(':') { "-6" } else { "-4" };
            let prefix = format!("{server}/{}", if family == "-6" { 128 } else { 32 });
            run("ip", &[family, "route", "replace", &prefix, "dev", interface])?;
            routes.push(prefix);
        }
        Ok(())
    })();
    if let Err(error) = added {
        restore_linux(interface, &routes, &dns);
        return Err(error);
    }
    Ok((routes, dns))
}

#[cfg(target_os = "linux")]
pub fn restore_linux(interface: &str, routes: &[String], dns: &LinuxDns) {
    match dns {
        LinuxDns::Resolvectl => {
            if let Err(e) = run("resolvectl", &["revert", interface]) {
                log::warn!("{e}");
            }
        }
        LinuxDns::Resolvconf => {
            if let Err(e) = run("resolvconf", &["-d", interface]) {
                log::warn!("{e}");
            }
            let _ = std::fs::remove_file(state_path(RESOLVCONF_IFACE));
        }
        LinuxDns::ResolvConf => restore_resolv_conf(),
    }
    for prefix in routes {
        let family = if prefix.contains(':') { "-6" } else { "-4" };
        if let Err(e) = run("ip", &[family, "route", "del", prefix, "dev", interface]) {
            log::warn!("{e}");
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_set_dns(service: &str, servers: &[String]) -> Result<String> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    run("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn macos_restore(backups: &[(String, Vec<String>)]) {
    for (service, servers) in backups {
        if let Err(e) = macos_set_dns(service, servers) {
            log::warn!("{e}");
        }
    }
    let _ = std::fs::remove_file(state_path(MACOS_BACKUP));
}

#[cfg(target_os = "macos")]
fn macos_load_backup() -> Option<Vec<(String, Vec<String>)>> {
    let text = std::fs::read_to_string(state_path(MACOS_BACKUP)).ok()?;
    Some(
        text.lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(service, servers)| (service.to_owned(), servers.split_whitespace().map(str::to_owned).collect()))
            .collect(),
    )
}

#[cfg(target_os = "macos")]
fn macos_apply(servers: &[String]) -> Result<Vec<(String, Vec<String>)>> {
    if let Some(stale) = macos_load_backup() {
        macos_restore(&stale);
    }
    let services = run("networksetup", &["-listallnetworkservices"])?;
    let mut backups = Vec::new();
    for name in services.lines().skip(1).map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('*')) {
        let previous = run("networksetup", &["-getdnsservers", name])?;
        let addresses = if previous.trim().starts_with("There aren't any DNS Servers set") {
            Vec::new()
        } else {
            previous.split_whitespace().map(|s| s.parse::<IpAddr>().map(|ip| ip.to_string()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| CoreError::Internal(format!("cannot back up DNS for macOS service {name}")))?
        };
        backups.push((name.to_owned(), addresses));
    }
    if backups.is_empty() {
        return Err(CoreError::Internal("TUN DNS: no enabled macOS network services".into()));
    }
    let text: String = backups.iter().map(|(s, a)| format!("{s}\t{}\n", a.join(" "))).collect();
    write_atomic(&state_path(MACOS_BACKUP), text.as_bytes())
        .map_err(|e| CoreError::Internal(format!("TUN DNS: cannot persist the macOS DNS backup: {e}")))?;
    for (name, _) in &backups {
        if let Err(e) = macos_set_dns(name, servers) {
            macos_restore(&backups);
            return Err(e);
        }
    }
    Ok(backups)
}

/// Undo DNS state persisted by a session that never restored it. The caller
/// holds the host state lock.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn recover_locked() {
    #[cfg(target_os = "linux")]
    {
        if let Ok(iface) = std::fs::read_to_string(state_path(RESOLVCONF_IFACE)) {
            if have("resolvconf") {
                let _ = run("resolvconf", &["-d", iface.trim()]);
            }
            let _ = std::fs::remove_file(state_path(RESOLVCONF_IFACE));
        }
        if resolv_backup_exists() || std::path::Path::new(LEGACY_RESOLV_BACKUP).exists() {
            if !resolv_backup_exists() {
                let _ = backup_resolv_conf();
            }
            restore_resolv_conf();
            log::info!("TUN DNS: restored {RESOLV_CONF} after an unclean shutdown");
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(stale) = macos_load_backup() {
        macos_restore(&stale);
        log::info!("TUN DNS: restored macOS DNS after an unclean shutdown");
    }
}

enum Dns {
    None,
    #[cfg(target_os = "linux")]
    Linux(String, Vec<String>, LinuxDns),
    #[cfg(target_os = "macos")]
    MacOs(Vec<(String, Vec<String>)>),
}

/// System DNS override for one TUN session; dropping it restores the host.
pub struct DnsGuard {
    dns: Dns,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    _lock: Option<crate::unix_tun::StateLock>,
}

impl DnsGuard {
    pub fn apply(cfg: &SessionConfig, interface: &str) -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let servers = servers(cfg)?;
            if servers.is_empty() {
                return Ok(Self { dns: Dns::None, _lock: None });
            }
            let lock = crate::unix_tun::StateLock::acquire();
            #[cfg(target_os = "linux")]
            let dns = {
                let _ = servers;
                let (routes, dns) = configure_linux(cfg, interface)?;
                Dns::Linux(interface.into(), routes, dns)
            };
            #[cfg(target_os = "macos")]
            let dns = {
                let _ = interface;
                Dns::MacOs(macos_apply(&servers)?)
            };
            Ok(Self { dns, _lock: Some(lock) })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (cfg, interface);
            Ok(Self { dns: Dns::None })
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        match &self.dns {
            Dns::None => {}
            #[cfg(target_os = "linux")]
            Dns::Linux(interface, routes, dns) => restore_linux(interface, routes, dns),
            #[cfg(target_os = "macos")]
            Dns::MacOs(backups) => macos_restore(backups),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_addresses_are_numeric_deduplicated_and_match_tun_families() {
        let mut cfg = SessionConfig::default();
        cfg.dns.server = Some("1.1.1.1, 1.1.1.1:53, [2606:4700:4700::1111]:53".into());
        assert_eq!(servers(&cfg).unwrap(), vec!["1.1.1.1", "2606:4700:4700::1111"]);
        cfg.tun.ipv6 = None;
        assert_eq!(servers(&cfg).unwrap(), vec!["1.1.1.1"]);
        for invalid in ["dns.example", "1.1.1.1:853", "0.0.0.0", "224.0.0.1", "127.0.0.53", "::1"] {
            cfg.dns.server = Some(invalid.into());
            assert!(servers(&cfg).is_err());
        }
    }

    #[test]
    fn psiphon_resolvers_keep_only_valid_ipv4_addresses() {
        let mut cfg = SessionConfig::default();
        cfg.dns.server = Some("1.1.1.1, 1.0.0.1:53, 1.1.1.1, 2606:4700:4700::1111".into());
        assert_eq!(psiphon_resolvers(&cfg).unwrap(), vec![
            std::net::Ipv4Addr::new(1, 1, 1, 1), std::net::Ipv4Addr::new(1, 0, 0, 1)]);
        cfg.dns.server = Some("2606:4700:4700::1111".into());
        assert!(psiphon_resolvers(&cfg).unwrap().is_empty());
        cfg.dns.server = None;
        assert!(psiphon_resolvers(&cfg).unwrap().is_empty());
        for invalid in ["dns.example", "1.1.1.1:853", "0.0.0.0", "224.0.0.1", "127.0.0.53", "255.255.255.255"] {
            cfg.dns.server = Some(invalid.into());
            assert!(psiphon_resolvers(&cfg).is_err(), "{invalid}");
        }
    }
}
