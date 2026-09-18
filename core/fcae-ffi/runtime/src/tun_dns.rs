//! System DNS setup shared by TUN engines. Android's VpnService owns its DNS.

use std::net::{IpAddr, SocketAddr};
use crate::config::SessionConfig;
use crate::error::{CoreError, Result};

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

#[cfg(target_os = "linux")]
pub fn configure_linux(cfg: &SessionConfig, interface: &str) -> Result<Vec<String>> {
    let servers = servers(cfg)?;
    if servers.is_empty() { return Ok(Vec::new()); }
    let mut routes = Vec::new();
    let setup: Result<()> = (|| {
        for server in &servers {
            let family = if server.contains(':') { "-6" } else { "-4" };
            let prefix = format!("{server}/{}", if family == "-6" { 128 } else { 32 });
            run("ip", &[family, "route", "add", &prefix, "dev", interface])?;
            routes.push(prefix);
        }
        let mut args = vec!["dns", interface];
        args.extend(servers.iter().map(String::as_str));
        run("resolvectl", &args)?;
        run("resolvectl", &["domain", interface, "~."])?;
        run("resolvectl", &["default-route", interface, "yes"])?;
        Ok(())
    })();
    if let Err(error) = setup {
        restore_linux(interface, &routes);
        return Err(error);
    }
    Ok(routes)
}

#[cfg(target_os = "linux")]
pub fn restore_linux(interface: &str, routes: &[String]) {
    if let Err(e) = run("resolvectl", &["revert", interface]) { log::warn!("{e}"); }
    for prefix in routes {
        let family = if prefix.contains(':') { "-6" } else { "-4" };
        if let Err(e) = run("ip", &[family, "route", "del", prefix, "dev", interface]) { log::warn!("{e}"); }
    }
}

pub enum DnsGuard {
    None,
    #[cfg(target_os = "linux")]
    Linux(String, Vec<String>),
    #[cfg(target_os = "macos")]
    MacOs(Vec<(String, Vec<String>)>),
}

impl DnsGuard {
    pub fn apply(cfg: &SessionConfig, interface: &str) -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if servers(cfg)?.is_empty() { return Ok(Self::None); }
        #[cfg(target_os = "linux")]
        {
            let routes = configure_linux(cfg, interface)?;
            return Ok(Self::Linux(interface.into(), routes));
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
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { let _ = (cfg, interface); Ok(Self::None) }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        match self {
            Self::None => {},
            #[cfg(target_os = "linux")]
            Self::Linux(interface, routes) => restore_linux(interface, routes),
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
}
