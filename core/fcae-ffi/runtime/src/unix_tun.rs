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
                log::warn!("TUN: host state is locked by another FCAE instance");
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
        log::info!("TUN: removed routes left by an unclean shutdown");
    }
    tun_dns::recover_locked();
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

/// Routes, bypasses and DNS installed for one TUN device; dropping it undoes
/// exactly what was applied, in reverse order.
pub struct TunGuard {
    device: String,
    undo: Vec<Vec<String>>,
    persisted: Vec<String>,
    dns: Option<DnsGuard>,
    _lock: StateLock,
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
        };
        guard.apply(cfg, peer_ip, assign_addresses)?;
        log::info!("TUN: routes/DNS applied to `{device}`");
        Ok(guard)
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    fn apply(&mut self, cfg: &SessionConfig, peer_ip: Option<&str>, assign_addresses: bool) -> Result<()> {
        let v6 = if assign_addresses { self.assign(cfg)? } else { cfg.tun.ipv6.is_some() };
        for peer in crate::backend::bypass_peers(peer_ip) {
            self.bypass(peer);
        }
        self.split_default(false, true)?;
        if let Err(e) = self.split_default(true, v6) {
            log::warn!("TUN: IPv6 split routes unavailable ({e})");
        }
        self.dns = Some(DnsGuard::apply(cfg, &self.device)?);
        Ok(())
    }

    /// Returns whether the device carries an IPv6 address.
    #[cfg(target_os = "linux")]
    fn assign(&mut self, cfg: &SessionConfig) -> Result<bool> {
        let dev = self.device.clone();
        tun_dns::run("ip", &["-4", "addr", "replace", &cfg.tun.ipv4, "dev", &dev])?;
        let v6 = cfg.tun.ipv6.as_deref().is_some_and(|v6| {
            tun_dns::run("ip", &["-6", "addr", "replace", v6, "dev", &dev])
                .inspect_err(|e| log::warn!("TUN: {e}"))
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
                .inspect_err(|e| log::warn!("TUN: {e}"))
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
                log::warn!("TUN: cannot persist route undo state: {e}");
            }
        }
        self.undo.push(del);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn bypass(&mut self, peer: IpAddr) {
        let family = if peer.is_ipv4() { "-4" } else { "-6" };
        let Some((via, dev)) = gateway(peer.is_ipv6()) else {
            log::warn!("TUN: no {family} default gateway; carrier {peer} is not bypassed");
            return;
        };
        let prefix = format!("{peer}/{}", if peer.is_ipv4() { 32 } else { 128 });
        let mut args = vec!["ip", family, "route", "replace", &prefix, "via", &via];
        if let Some(dev) = &dev {
            args.extend(["dev", dev]);
        }
        let del = ["ip", family, "route", "del", &prefix].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&args, del, true) {
            log::warn!("TUN: carrier bypass for {peer}: {e}");
        }
    }

    #[cfg(target_os = "macos")]
    fn bypass(&mut self, peer: IpAddr) {
        let Some(via) = gateway(peer.is_ipv6()) else {
            log::warn!("TUN: no default gateway for carrier {peer}; it is not bypassed");
            return;
        };
        let family = if peer.is_ipv4() { "-inet" } else { "-inet6" };
        let peer = peer.to_string();
        let del = ["route", "-n", "delete", family, "-host", &peer].map(str::to_owned).to_vec();
        if let Err(e) = self.add(&["route", "-n", "add", family, "-host", &peer, &via], del, true) {
            log::warn!("TUN: carrier bypass for {peer}: {e}");
        }
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
                log::warn!("TUN: {e}");
            }
        }
        if !self.persisted.is_empty() {
            let _ = std::fs::remove_file(state_path(ROUTES_FILE));
        }
        log::info!("TUN: routes/DNS restored for `{}`", self.device);
    }
}
