//! Desktop Linux/macOS host configuration for TUN engines: addresses, split
//! default routes for both families, carrier bypass routes and DNS, with the
//! persistent state needed to undo them after a crash.

use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::config::SessionConfig;
use crate::error::Result;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error::CoreError;
use crate::tun_dns::{self, DnsGuard};

#[cfg(target_os = "linux")]
const STATE_DIR: &str = "/var/lib/fcae-vpn";
#[cfg(target_os = "macos")]
const STATE_DIR: &str = "/Library/Application Support/FCAE VPN";
const ROUTES_FILE: &str = "routes";
const LOCK_FILE: &str = "session.lock";

pub(crate) fn state_path(name: &str) -> PathBuf {
    Path::new(STATE_DIR).join(name)
}

pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".fcae-tmp");
    let tmp = PathBuf::from(tmp);
    let written = (|| {
        let mut file = File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

static LOCK: Mutex<(usize, Option<File>)> = Mutex::new((0, None));

fn try_flock() -> Option<File> {
    std::fs::create_dir_all(STATE_DIR).ok()?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state_path(LOCK_FILE))
        .ok()?;
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
}

/// Marks the persisted undo state as owned by a live session, so another
/// instance's [`recover`] leaves it alone. Re-entrant within the process.
pub(crate) struct StateLock;

impl StateLock {
    pub(crate) fn acquire() -> Self {
        let mut lock = LOCK.lock();
        if lock.0 == 0 {
            lock.1 = try_flock();
            if lock.1.is_none() {
                log::warn!("[tun] host state is locked by another FCAE instance");
            }
        }
        lock.0 += 1;
        Self
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let mut lock = LOCK.lock();
        lock.0 -= 1;
        if lock.0 == 0 {
            lock.1 = None;
        }
    }
}

/// Undo routes and DNS left behind by a session that died without cleanup.
/// A no-op without root or while any instance holds a live session.
pub fn recover() {
    if unsafe { libc::geteuid() } != 0 || LOCK.lock().0 != 0 {
        return;
    }
    let Some(_flock) = try_flock() else { return };
    if let Ok(text) = std::fs::read_to_string(state_path(ROUTES_FILE)) {
        for line in text.lines().filter(|l| !l.is_empty()) {
            let argv: Vec<&str> = line.split('\t').collect();
            let _ = tun_dns::run(argv[0], &argv[1..]);
        }
        let _ = std::fs::remove_file(state_path(ROUTES_FILE));
        log::info!("[tun] removed routes left by an unclean shutdown");
    }
    tun_dns::recover_locked();
    if let Err(error) = recover_dns_firewall() { log::warn!("{error}"); }
}

/// Wait for `name` to exist and, with `up`, to be administratively up (the
/// kernel refuses routes through a down link).
#[cfg(target_os = "linux")]
pub fn wait_for_device(name: &str, up: bool, budget: Duration) -> bool {
    let args: &[&str] = if up { &["-o", "link", "show", "dev", name, "up"] } else { &["-o", "link", "show", "dev", name] };
    wait_until(|| tun_dns::run("ip", args).is_ok_and(|out| !out.trim().is_empty()), budget)
}

#[cfg(target_os = "macos")]
pub fn utun_devices() -> Vec<String> {
    tun_dns::run("ifconfig", &["-l"])
        .map(|out| out.split_whitespace().filter(|n| n.starts_with("utun")).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The utun interface that appeared and came up after `before` was sampled.
#[cfg(target_os = "macos")]
pub fn wait_for_new_utun(before: &[String], budget: Duration) -> Option<String> {
    let mut found = None;
    wait_until(
        || {
            found = utun_devices().into_iter().find(|n| {
                !before.contains(n) && tun_dns::run("ifconfig", &[n]).is_ok_and(|out| out.contains("<UP"))
            });
            found.is_some()
        },
        budget,
    );
    found
}

fn wait_until(mut probe: impl FnMut() -> bool, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let mut slice = Duration::from_millis(5);
    loop {
        if probe() {
            return true;
        }
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return probe();
        }
        std::thread::sleep(slice.min(remain));
        slice = (slice * 2).min(Duration::from_millis(100));
    }
}

/// Next hop and egress device of the host default route.
#[cfg(target_os = "linux")]
fn gateway(v6: bool) -> Option<(String, Option<String>)> {
    let out = tun_dns::run("ip", &[if v6 { "-6" } else { "-4" }, "route", "show", "default"]).ok()?;
    let line = out.lines().find(|l| l.contains(" via "))?;
    let after = |key: &str| {
        let mut it = line.split_whitespace();
        it.find(|t| *t == key)?;
        it.next().map(str::to_owned)
    };
    Some((after("via")?, after("dev")))
}

#[cfg(target_os = "macos")]
fn gateway(v6: bool) -> Option<String> {
    let args: &[&str] = if v6 { &["-n", "get", "-inet6", "default"] } else { &["-n", "get", "default"] };
    let out = tun_dns::run("route", args).ok()?;
    let field = |key: &str| out.lines().find_map(|l| l.trim().strip_prefix(key)).map(|v| v.trim().to_owned());
    let via = field("gateway:")?;
    match field("interface:") {
        Some(dev) if v6 && via.starts_with("fe80:") && !via.contains('%') => Some(format!("{via}%{dev}")),
        _ => Some(via),
    }
}


#[cfg(target_os = "linux")]
const DNS_FIREWALL_FILE: &str = "dns-firewall";

#[cfg(target_os = "linux")]
fn recover_dns_firewall() -> Result<()> {
    let path = state_path(DNS_FIREWALL_FILE);
    let table = match std::fs::read_to_string(&path) {
        Ok(table) => table,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CoreError::Internal(format!("[tun] DNS: cannot read firewall state: {e}"))),
    };
    let suffix = table.strip_prefix("fcae_dns_").unwrap_or("");
    if suffix.split('_').any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit())) {
        return Err(CoreError::Internal("[tun] DNS: invalid firewall recovery state".into()));
    }
    // Distinguish a missing table from a missing/unavailable nft installation.
    tun_dns::run("nft", &["list", "tables"])?;
    if tun_dns::run("nft", &["list", "table", "inet", &table]).is_ok() {
        tun_dns::run("nft", &["delete", "table", "inet", &table])?;
    }
    std::fs::remove_file(path).map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot remove firewall state: {e}")))?;
    Ok(())
}

#[cfg(target_os = "macos")]
const DNS_FIREWALL_FILE: &str = "dns-firewall.pf";

#[cfg(target_os = "macos")]
fn recover_dns_firewall() -> Result<()> {
    let path = state_path(DNS_FIREWALL_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CoreError::Internal(format!("[tun] DNS: cannot read PF recovery state: {e}"))),
    };
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != 3 || !parts[0].starts_with("com.apple/000_fcae_")
        || parts[0]["com.apple/000_fcae_".len()..].split('_').any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()))
        || parts[1].is_empty() || !parts[1].bytes().all(|c| c.is_ascii_digit())
        || parts[2].is_empty() || !parts[2].bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
        return Err(CoreError::Internal("[tun] DNS: invalid PF recovery state".into()));
    }
    let boot = tun_dns::run("sysctl", &["-n", "kern.bootsessionuuid"])?;
    if boot.trim().eq_ignore_ascii_case(parts[2]) {
        // The private anchor is the only ruleset touched; never flush main PF.
        tun_dns::run("pfctl", &["-a", parts[0], "-F", "rules"])?;
        tun_dns::run("pfctl", &["-X", parts[1]])?;
    }
    std::fs::remove_file(path).map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot remove PF recovery state: {e}")))?;
    Ok(())
}

/// Routes, bypasses and DNS installed for one TUN device; dropping it undoes
/// exactly what was applied, in reverse order.
pub struct TunGuard {
    device: String,
    undo: Vec<Vec<String>>,
    persisted: Vec<String>,
    dns: Option<DnsGuard>,
    _lock: StateLock,
    default_snapshot:[String;2],
}

impl TunGuard {
    /// `assign_addresses` is false for engines that address and raise the
    /// device themselves.
    pub fn configure(cfg: &SessionConfig, device: &str, peer_ip: Option<&str>, assign_addresses: bool) -> Result<Self> {
        let mut guard = Self {
            device: device.to_owned(),
            undo: Vec::new(),
            persisted: Vec::new(),
            dns: None,
            _lock: StateLock::acquire(),
            default_snapshot:[format!("{:?}",gateway(false)),format!("{:?}",gateway(true))],
        };
        guard.apply(cfg, peer_ip, assign_addresses)?;
        log::info!("[tun] routes/DNS applied to `{device}`");
        Ok(guard)
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    /// Read-only checks used by captured-flow routing. No policy acknowledgement
    /// survives a missing capture route or changed uplink.
    pub fn check_health(&mut self)->Result<()> {
        if self.default_snapshot != [format!("{:?}",gateway(false)),format!("{:?}",gateway(true))] {
            return Err(CoreError::Internal("physical default route changed; reconnect app routing".into()));
        }
        #[cfg(target_os="linux")]
        for undo in &self.undo {
            if undo.len()<5 || undo[0]!="ip" || undo[2]!="route" {continue;}
            let reject=undo[4]=="unreachable";
            let prefix=if reject {undo.get(5)} else {undo.get(4)};
            let Some(prefix)=prefix.filter(|p|matches!(p.as_str(),"0.0.0.0/1"|"128.0.0.0/1"|"::/1"|"8000::/1")) else {continue;};
            let text=tun_dns::run("ip",&[&undo[1],"-j","route","show","exact",prefix])?;
            let value:serde_json::Value=serde_json::from_str(&text).map_err(|e|CoreError::Internal(e.to_string()))?;
            let valid=value.as_array().is_some_and(|rows|rows.iter().any(|row|{
                row["dst"].as_str()==Some(prefix.as_str()) && if reject {row["type"].as_str()==Some("unreachable")} else {row["dev"].as_str()==Some(self.device.as_str())}
            }));
            if !valid {return Err(CoreError::Internal(format!("capture route {prefix} changed; reconnect app routing")));}
        }
        #[cfg(target_os="macos")]
        for undo in &self.undo {
            if undo.len()!=6 || undo[0]!="route" || undo[4]!="-net" {continue;}
            let prefix=&undo[5];
            if !matches!(prefix.as_str(),"0.0.0.0/1"|"128.0.0.0/1"|"::/1"|"8000::/1") {continue;}
            let text=tun_dns::run("route",&["-n","get",&undo[3],"-net",prefix])?;
            let on_tunnel=text.lines().find_map(|line|line.trim().strip_prefix("interface:")).is_some_and(|name|name.trim()==self.device);
            let rejected=text.lines().any(|line|line.trim().starts_with("flags:")&&line.contains("REJECT"));
            if !on_tunnel && !rejected {return Err(CoreError::Internal(format!("capture route {prefix} changed; reconnect app routing")));}
        }
        Ok(())
    }

    fn apply(&mut self, cfg: &SessionConfig, peer_ip: Option<&str>, assign_addresses: bool) -> Result<()> {
        // Remove only persisted FCAE DNS filters from older versions. Routing
        // this TUN must never impose a host-wide DNS firewall policy.
        recover_dns_firewall()?;
        self.program(cfg, peer_ip, assign_addresses)
    }

    /// Addresses, routes and resolvers for the device.
    fn program(&mut self, cfg: &SessionConfig, peer_ip: Option<&str>, assign_addresses: bool) -> Result<()> {
        let v6 = if assign_addresses { self.assign(cfg)? } else { cfg.tun.ipv6.is_some() };
        for peer in crate::backend::bypass_peers(peer_ip) {
            self.bypass(peer);
        }
        self.split_default(false, true)?;
        self.split_default(true, v6).map_err(|error| CoreError::Internal(
            format!("[tun] cannot establish IPv6 tunnel or reject routes; refusing to leave IPv6 outside the VPN: {error}")
        ))?;
        // The LAN keeps the physical interface: a printer, a NAS or the
        // router's admin page must not disappear because a VPN came up. Each
        // prefix below is more specific than the two halves above, so it wins.
        if cfg.tun.exclude_private {
            for (network, bits) in crate::config::excluded_prefixes() {
                if network.is_ipv6() && !v6 {
                    continue;
                }
                self.bypass_prefix(network, bits);
            }
            log::info!("[tun] private ranges keep the physical interface");
        }
        let mut dns_cfg = cfg.clone();
        if !v6 { dns_cfg.tun.ipv6 = None; }
        if tun_dns::servers(&dns_cfg)?.is_empty() {
            log::info!("[tun] DNS: no usable resolvers configured; using default IPv4 resolvers");
            dns_cfg.dns.server = Some("1.1.1.1,1.0.0.1".into());
        }
        #[cfg(target_os = "macos")]
        {
            self.add_dns_routes(&dns_cfg)?;
        }
        self.dns = Some(DnsGuard::apply(&dns_cfg, &self.device)?);
        Ok(())
    }

    /// Returns whether the device carries an IPv6 address.
    #[cfg(target_os = "linux")]
    fn assign(&mut self, cfg: &SessionConfig) -> Result<bool> {
        let dev = self.device.clone();
        tun_dns::run("ip", &["-4", "addr", "replace", &cfg.tun.ipv4, "dev", &dev])?;
        let v6 = cfg.tun.ipv6.as_deref().is_some_and(|v6| {
            tun_dns::run("ip", &["-6", "addr", "replace", v6, "dev", &dev])
                .inspect_err(|e| log::warn!("[tun] {e}"))
                .is_ok()
        });
        tun_dns::run("ip", &["link", "set", "dev", &dev, "mtu", &cfg.tun.mtu.to_string(), "up"])?;
        Ok(v6)
    }

    #[cfg(target_os = "macos")]
    fn assign(&mut self, cfg: &SessionConfig) -> Result<bool> {
        let dev = self.device.clone();
        let ip = cfg.tun.ipv4.split('/').next().unwrap_or(&cfg.tun.ipv4);
        tun_dns::run("ifconfig", &[&dev, "inet", ip, ip, "up"])?;
        tun_dns::run("ifconfig", &[&dev, "mtu", &cfg.tun.mtu.to_string()])?;
        let v6 = cfg.tun.ipv6.as_deref().is_some_and(|v6| {
            let (addr, len) = v6.split_once('/').unwrap_or((v6, "64"));
            tun_dns::run("ifconfig", &[&dev, "inet6", addr, "prefixlen", len, "alias"])
                .inspect_err(|e| log::warn!("[tun] {e}"))
                .is_ok()
        });
        Ok(v6)
    }

    fn add(&mut self, add: &[&str], del: Vec<String>, persist: bool) -> Result<()> {
        tun_dns::run(add[0], &add[1..])?;
        if persist {
            self.persisted.push(del.join("\t"));
            let mut text = self.persisted.join("\n");
            text.push('\n');
            if let Err(e) = write_atomic(&state_path(ROUTES_FILE), text.as_bytes()) {
                log::warn!("[tun] cannot persist route undo state: {e}");
            }
        }
        self.undo.push(del);
        Ok(())
    }

    /// Keep a whole range out of the device. `add`, never `replace`: a host
    /// that already has a route for the prefix -- an on-link LAN, a split
    /// tunnel -- keeps it, and that pre-existing route is more specific than
    /// the tunnel's halves anyway. Only a prefix with nothing behind it gets a
    /// row through the physical gateway.
    #[cfg(target_os = "linux")]
    fn bypass_prefix(&mut self, network: IpAddr, bits: u8) {
        let family = if network.is_ipv4() { "-4" } else { "-6" };
        let Some((via, dev)) = gateway(network.is_ipv6()) else {
            log::debug!("[tun] no {family} default gateway; {network}/{bits} is not excluded");
            return;
        };
        let prefix = format!("{network}/{bits}");
        let mut args = vec!["ip", family, "route", "add", &prefix, "via", &via];
        if let Some(dev) = &dev {
            args.extend(["dev", dev]);
        }
        let del = ["ip", family, "route", "del", &prefix].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&args, del, true) {
            log::debug!("[tun] {prefix} keeps its existing route: {e}");
        }
    }

    /// The macOS half of [`Self::bypass_prefix`]; `route add` fails the same
    /// way `ip route add` does when the prefix is already routed.
    #[cfg(target_os = "macos")]
    fn bypass_prefix(&mut self, network: IpAddr, bits: u8) {
        let family = if network.is_ipv4() { "-inet" } else { "-inet6" };
        let Some(via) = gateway(network.is_ipv6()) else {
            log::debug!("[tun] no default gateway; {network}/{bits} is not excluded");
            return;
        };
        let prefix = format!("{network}/{bits}");
        let del = ["route", "-n", "delete", family, "-net", &prefix].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&["route", "-n", "add", family, "-net", &prefix, &via], del, true) {
            log::debug!("[tun] {prefix} keeps its existing route: {e}");
        }
    }

    #[cfg(target_os = "linux")]
    fn bypass(&mut self, peer: IpAddr) {
        let family = if peer.is_ipv4() { "-4" } else { "-6" };
        let Some((via, dev)) = gateway(peer.is_ipv6()) else {
            log::warn!("[tun] no {family} default gateway; carrier {peer} is not bypassed");
            return;
        };
        let prefix = format!("{peer}/{}", if peer.is_ipv4() { 32 } else { 128 });
        let mut args = vec!["ip", family, "route", "replace", &prefix, "via", &via];
        if let Some(dev) = &dev {
            args.extend(["dev", dev]);
        }
        let del = ["ip", family, "route", "del", &prefix].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&args, del, true) {
            log::warn!("[tun] carrier bypass for {peer}: {e}");
        }
    }

    #[cfg(target_os = "macos")]
    fn bypass(&mut self, peer: IpAddr) {
        let Some(via) = gateway(peer.is_ipv6()) else {
            log::warn!("[tun] no default gateway for carrier {peer}; it is not bypassed");
            return;
        };
        let family = if peer.is_ipv4() { "-inet" } else { "-inet6" };
        let peer = peer.to_string();
        let del = ["route", "-n", "delete", family, "-host", &peer].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&["route", "-n", "add", family, "-host", &peer, &via], del, true) {
            log::warn!("[tun] carrier bypass for {peer}: {e}");
        }
    }

    #[cfg(target_os = "macos")]
    fn add_dns_routes(&mut self, cfg: &SessionConfig) -> Result<()> {
        let dev = self.device.clone();
        for server in tun_dns::servers(cfg)? {
            let family = if server.contains(':') { "-inet6" } else { "-inet" };
            let del = ["route", "-n", "delete", family, "-host", &server, "-interface", &dev].map(str::to_owned).to_vec();
            self.add(&["route", "-n", "add", family, "-host", &server, "-interface", &dev], del, false)?;
        }
        Ok(())
    }

    /// Two /1 routes outrank the host default without replacing it. For a
    /// family the device cannot carry, the halves are rejected instead, so
    /// that family fails fast rather than leaking around the tunnel.
    #[cfg(target_os = "linux")]
    fn split_default(&mut self, v6: bool, into_device: bool) -> Result<()> {
        let dev = self.device.clone();
        let (family, halves) = if v6 { ("-6", ["::/1", "8000::/1"]) } else { ("-4", ["0.0.0.0/1", "128.0.0.0/1"]) };
        for half in halves {
            let (add, del): (Vec<&str>, Vec<&str>) = if into_device {
                (vec!["ip", family, "route", "replace", half, "dev", &dev], vec!["ip", family, "route", "del", half, "dev", &dev])
            } else {
                (vec!["ip", family, "route", "replace", "unreachable", half], vec!["ip", family, "route", "del", "unreachable", half])
            };
            self.add(&add, del.into_iter().map(str::to_owned).collect(), !into_device)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn split_default(&mut self, v6: bool, into_device: bool) -> Result<()> {
        let dev = self.device.clone();
        let (family, halves) = if v6 { ("-inet6", ["::/1", "8000::/1"]) } else { ("-inet", ["0.0.0.0/1", "128.0.0.0/1"]) };
        for half in halves {
            let del: Vec<String> = ["route", "-n", "delete", family, "-net", half].map(str::to_owned).to_vec();
            if into_device {
                self.add(&["route", "-n", "add", family, "-net", half, "-interface", &dev], del, false)?;
            } else {
                self.add(&["route", "-n", "add", family, "-net", half, "::1", "-reject"], del, true)?;
            }
        }
        Ok(())
    }
}

impl Drop for TunGuard {
    fn drop(&mut self) {
        self.dns = None;
        for argv in self.undo.drain(..).rev() {
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            if let Err(e) = tun_dns::run(argv[0], &argv[1..]) {
                log::warn!("[tun] {e}");
            }
        }
        if !self.persisted.is_empty() {
            let _ = std::fs::remove_file(state_path(ROUTES_FILE));
        }
        log::info!("[tun] routes/DNS restored for `{}`", self.device);
    }
}
