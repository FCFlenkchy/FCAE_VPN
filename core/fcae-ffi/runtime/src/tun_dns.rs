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
fn run(program: &str, args: &[&str]) -> Result<String> {
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
const RESOLV_BACKUP: &str = "/run/fcae-resolv.conf.pre-fcae";
#[cfg(target_os = "linux")]
const RESOLV_MARKER: &str = "# written by FCAE VPN";

/// Which resolver manager owns the Linux DNS override. Picked once per
/// session so [`restore_linux`] undoes exactly what was applied; desktops
/// without systemd-resolved (Alpine, Devuan, containers, WSL1) fall through
/// to managing /etc/resolv.conf directly instead of refusing to run TUN.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub enum LinuxDns {
    Resolvectl,
    Resolvconf,
    /// Backup of the previous /etc/resolv.conf, when there was one.
    ResolvConf(Option<std::path::PathBuf>),
}

#[cfg(target_os = "linux")]
fn apply_resolv_conf(servers: &[String]) -> Result<Option<std::path::PathBuf>> {
    let backup = {
        let old = std::fs::read(RESOLV_CONF).unwrap_or_default();
        if old
            .windows(RESOLV_MARKER.len())
            .any(|w| w == RESOLV_MARKER.as_bytes())
        {
            None
        } else {
            std::fs::write(RESOLV_BACKUP, &old).map_err(|e| {
                CoreError::Internal(format!("TUN DNS: cannot back up {RESOLV_CONF}: {e}"))
            })?;
            Some(std::path::PathBuf::from(RESOLV_BACKUP))
        }
    };
    let mut text = String::from(RESOLV_MARKER);
    text.push('\n');
    for server in servers {
        text.push_str(&format!("nameserver {server}\n"));
    }
    std::fs::write(RESOLV_CONF, text).map_err(|e| {
        CoreError::Internal(format!("TUN DNS: cannot write {RESOLV_CONF}: {e}"))
    })?;
    Ok(backup)
}

#[cfg(target_os = "linux")]
fn restore_resolv_conf(backup: &Option<std::path::PathBuf>) {
    let r = match backup {
        Some(backup) => std::fs::rename(backup, RESOLV_CONF),
        None => std::fs::remove_file(RESOLV_CONF),
    };
    if let Err(e) = r {
        log::warn!("TUN DNS: cannot restore {RESOLV_CONF}: {e}");
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
        run_stdin("resolvconf", &["-a", interface], &text)?;
        LinuxDns::Resolvconf
    } else {
        LinuxDns::ResolvConf(apply_resolv_conf(&servers)?)
    };
    let mut routes = Vec::new();
    let added: Result<()> = (|| {
        for server in &servers {
            let family = if server.contains(':') { "-6" } else { "-4" };
            let prefix = format!("{server}/{}", if family == "-6" { 128 } else { 32 });
            run("ip", &[family, "route", "add", &prefix, "dev", interface])?;
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
        }
        LinuxDns::ResolvConf(backup) => restore_resolv_conf(backup),
    }
    for prefix in routes {
        let family = if prefix.contains(':') { "-6" } else { "-4" };
        if let Err(e) = run("ip", &[family, "route", "del", prefix, "dev", interface]) {
            log::warn!("{e}");
        }
    }
}

pub enum DnsGuard {
    None,
    #[cfg(windows)]
    Windows(crate::windows_tun::DnsGuard),
    #[cfg(target_os = "linux")]
    Linux(String, Vec<String>, LinuxDns),
    #[cfg(target_os = "macos")]
    MacOs(Vec<(String, Vec<String>)>),
}

impl DnsGuard {
    pub fn apply(cfg: &SessionConfig, interface: &str) -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if servers(cfg)?.is_empty() { return Ok(Self::None); }
        #[cfg(target_os = "linux")]
        {
            let (routes, dns) = configure_linux(cfg, interface)?;
            return Ok(Self::Linux(interface.into(), routes, dns));
        }
        #[cfg(target_os = "macos")]
        {
            let _ = interface;
            let servers = servers(cfg)?;
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
            if backups.is_empty() { return Err(CoreError::Internal("TUN DNS: no enabled macOS network services".into())); }
            let guard = Self::MacOs(backups);
            if let Self::MacOs(backups) = &guard {
                for (name, _) in backups {
                    let mut args = vec!["-setdnsservers", name.as_str()];
                    args.extend(servers.iter().map(String::as_str));
                    run("networksetup", &args)?;
                }
            }
            return Ok(guard);
        }
        #[cfg(windows)]
        { crate::windows_tun::DnsGuard::apply(cfg, interface).map(Self::Windows) }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        { let _ = (cfg, interface); Ok(Self::None) }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        match self {
            Self::None => {},
            #[cfg(windows)]
            Self::Windows(_) => {},
            #[cfg(target_os = "linux")]
            Self::Linux(interface, routes, dns) => restore_linux(interface, routes, dns),
            #[cfg(target_os = "macos")]
            Self::MacOs(backups) => {
                for (name, servers) in backups {
                    let mut args = vec!["-setdnsservers", name.as_str()];
                    if servers.is_empty() { args.push("Empty"); }
                    else { args.extend(servers.iter().map(String::as_str)); }
                    if let Err(e) = run("networksetup", &args) { log::warn!("{e}"); }
                }
            }
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
