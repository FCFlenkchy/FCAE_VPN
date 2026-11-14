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
static DNS_FIREWALL_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static DNS_FIREWALL_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

#[cfg(target_os = "linux")]
struct DnsFirewall { monitor: Option<std::process::Child> }

#[cfg(target_os = "linux")]
impl DnsFirewall {
    fn install(device: &str) -> Result<Self> {
        use std::sync::atomic::Ordering;
        if device.is_empty() || device.len() > 15 || !device.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)) {
            return Err(CoreError::InvalidConfig("invalid Linux TUN interface name for DNS protection".into()));
        }
        if LOCK.lock().1.is_none() {
            return Err(CoreError::Internal("[tun] DNS: cannot acquire exclusive host state lock".into()));
        }
        if DNS_FIREWALL_BUSY.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(CoreError::Internal("[tun] DNS: another tunnel owns DNS protection".into()));
        }
        let mut guard = Self { monitor: None };
        recover_dns_firewall()?;
        let table = format!("fcae_dns_{}_{}", std::process::id(), DNS_FIREWALL_SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let script = format!(r#"table inet {table} {{
 chain output {{
  type filter hook output priority -10; policy accept;
  oifname "lo" ip daddr {{ 127.0.0.53, 127.0.0.54 }} tcp dport 53 accept
  oifname "lo" ip daddr {{ 127.0.0.53, 127.0.0.54 }} udp dport 53 accept
  oifname != "{device}" tcp dport {{ 53, 853 }} drop
  oifname != "{device}" udp dport {{ 53, 853 }} drop
 }}
}}
"#);
        let script_path = state_path("dns-firewall.nft");
        write_atomic(&script_path, script.as_bytes()).map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot write firewall rules: {e}")))?;
        write_atomic(&state_path(DNS_FIREWALL_FILE), table.as_bytes()).map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot persist firewall state: {e}")))?;
        // The monitor installs the table itself, then owns cleanup. If FCAE
        // exits while nft is still installing, it waits for that operation
        // before observing the closed pipe and removing the table.
        let monitor_script = r#"
trap '' PIPE
nft -f "$1" >/dev/null 2>&1
status=$?
rm -f "$1"
printf '%s\n' "$status" || :
if [ "$status" -eq 0 ]; then IFS= read -r line || :; fi
if nft list tables >/dev/null 2>&1; then
    if nft list table inet "$2" >/dev/null 2>&1; then
        nft delete table inet "$2" >/dev/null 2>&1 || exit 1
    fi
    if [ "$(cat "$3" 2>/dev/null)" = "$2" ]; then rm -f "$3" || exit 1; fi
    exit 0
fi
exit 1
"#;
        let monitor = std::process::Command::new("/bin/sh")
            .args(["-c", monitor_script, "fcae-dns-monitor"])
            .arg(&script_path).arg(&table).arg(state_path(DNS_FIREWALL_FILE))
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()).spawn()
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot start firewall monitor: {e}")))?;
        guard.monitor = Some(monitor);
        let stdout = guard.monitor.as_mut().and_then(|child| child.stdout.take())
            .ok_or_else(|| CoreError::Internal("[tun] DNS: missing firewall monitor output".into()))?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut line = String::new();
            let status = std::io::BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(status);
        });
        let status = rx.recv_timeout(Duration::from_secs(10))
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: firewall installation did not complete: {e}")))?
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: firewall monitor failed: {e}")))?;
        if status.trim() != "0" {
            return Err(CoreError::Internal(format!("[tun] DNS: nftables rules failed to install (status {})", status.trim())));
        }
        log::info!("[tun] DNS: Linux firewall protection enabled for ports 53 and 853");
        Ok(guard)
    }
}

#[cfg(target_os = "linux")]
impl Drop for DnsFirewall {
    fn drop(&mut self) {
        if let Some(mut monitor) = self.monitor.take() {
            drop(monitor.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match monitor.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() { log::warn!("[tun] DNS: firewall cleanup failed; recovery state retained"); }
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                    _ => {
                        log::warn!("[tun] DNS: firewall monitor is still cleaning up");
                        std::thread::spawn(move || {
                            let _ = monitor.wait();
                            DNS_FIREWALL_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
                        });
                        return;
                    }
                }
            }
        } else if let Err(error) = recover_dns_firewall() {
            log::warn!("{error}");
        }
        DNS_FIREWALL_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
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

#[cfg(target_os = "macos")]
struct DnsFirewall { monitor: Option<std::process::Child> }

#[cfg(target_os = "macos")]
impl DnsFirewall {
    fn install(device: &str) -> Result<Self> {
        use std::sync::atomic::Ordering;
        let suffix = device.strip_prefix("utun").unwrap_or("");
        if suffix.is_empty() || !suffix.bytes().all(|c| c.is_ascii_digit()) {
            return Err(CoreError::InvalidConfig("invalid macOS TUN interface name for DNS protection".into()));
        }
        if LOCK.lock().1.is_none() {
            return Err(CoreError::Internal("[tun] DNS: cannot acquire exclusive host state lock".into()));
        }
        if DNS_FIREWALL_BUSY.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(CoreError::Internal("[tun] DNS: another tunnel owns DNS protection".into()));
        }
        let mut guard = Self { monitor: None };
        recover_dns_firewall()?;
        let main_rules = tun_dns::run("pfctl", &["-sr"])?;
        let mut found_anchor = false;
        for line in main_rules.lines().map(str::trim_start) {
            if line.starts_with("anchor \"com.apple/*\"") { found_anchor = true; break; }
            if line.starts_with("anchor ") || (line.starts_with("pass ") && line.split_whitespace().any(|word| word == "quick")) {
                return Err(CoreError::Internal("[tun] DNS: an earlier PF rule could bypass DNS protection; refusing an unprotected tunnel".into()));
            }
        }
        if !found_anchor {
            return Err(CoreError::Internal("[tun] DNS: the active macOS PF ruleset has no com.apple wildcard anchor; refusing an unprotected tunnel".into()));
        }
        let anchor = format!("com.apple/000_fcae_{}_{}", std::process::id(), DNS_FIREWALL_SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let script_path = state_path("dns-firewall.pf.rules");
        let rules = format!("block drop out quick on ! {device} proto {{ tcp udp }} from any to any port {{ 53 853 }}\n");
        write_atomic(&script_path, rules.as_bytes()).map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot write PF rules: {e}")))?;
        let monitor_script = r#"
trap '' PIPE
umask 077
boot=$(sysctl -n kern.bootsessionuuid 2>/dev/null) || { echo boot; exit 1; }
out=$(pfctl -E 2>&1)
token=$(printf '%s\n' "$out" | awk '$1 == "Token" && $2 == ":" && $3 ~ /^[0-9]+$/ {print $3; exit}')
case "$token" in ''|*[!0-9]*) echo token; exit 1;; esac
if ! printf '%s\t%s\t%s\n' "$2" "$token" "$boot" > "$3.tmp" || ! mv "$3.tmp" "$3"; then
    pfctl -X "$token" >/dev/null 2>&1
    echo state
    exit 1
fi
pfctl -a "$2" -f "$1" >/dev/null 2>&1
status=$?
rm -f "$1"
printf '%s\n' "$status" || :
if [ "$status" -eq 0 ]; then IFS= read -r line || :; fi
if pfctl -a "$2" -F rules >/dev/null 2>&1 && pfctl -X "$token" >/dev/null 2>&1; then
    state=$(cat "$3" 2>/dev/null)
    expected=$(printf '%s\t%s\t%s' "$2" "$token" "$boot")
    if [ "$state" = "$expected" ]; then rm -f "$3" || exit 1; fi
    exit 0
fi
exit 1
"#;
        let monitor = std::process::Command::new("/bin/sh")
            .args(["-c", monitor_script, "fcae-pf-monitor"])
            .arg(&script_path).arg(&anchor).arg(state_path(DNS_FIREWALL_FILE))
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()).spawn()
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: cannot start PF monitor: {e}")))?;
        guard.monitor = Some(monitor);
        let stdout = guard.monitor.as_mut().and_then(|child| child.stdout.take())
            .ok_or_else(|| CoreError::Internal("[tun] DNS: missing PF monitor output".into()))?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut line = String::new();
            let status = std::io::BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(status);
        });
        let status = rx.recv_timeout(Duration::from_secs(10))
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: PF installation did not complete: {e}")))?
            .map_err(|e| CoreError::Internal(format!("[tun] DNS: PF monitor failed: {e}")))?;
        if status.trim() != "0" {
            return Err(CoreError::Internal(format!("[tun] DNS: PF DNS protection failed to install ({})", status.trim())));
        }
        log::info!("[tun] DNS: macOS PF protection enabled for ports 53 and 853");
        Ok(guard)
    }
}

#[cfg(target_os = "macos")]
impl Drop for DnsFirewall {
    fn drop(&mut self) {
        if let Some(mut monitor) = self.monitor.take() {
            drop(monitor.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match monitor.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() { log::warn!("[tun] DNS: PF cleanup failed; recovery state retained"); }
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                    _ => {
                        log::warn!("[tun] DNS: PF monitor is still cleaning up");
                        std::thread::spawn(move || {
                            let _ = monitor.wait();
                            DNS_FIREWALL_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
                        });
                        return;
                    }
                }
            }
        } else if let Err(error) = recover_dns_firewall() {
            log::warn!("{error}");
        }
        DNS_FIREWALL_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Routes, bypasses and DNS installed for one TUN device; dropping it undoes
/// exactly what was applied, in reverse order.
pub struct TunGuard {
    device: String,
    undo: Vec<Vec<String>>,
    persisted: Vec<String>,
    dns: Option<DnsGuard>,
    dns_firewall: Option<DnsFirewall>,
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
            dns_firewall: None,
            _lock: StateLock::acquire(),
        };
        guard.apply(cfg, peer_ip, assign_addresses)?;
        log::info!("[tun] routes/DNS applied to `{device}`");
        Ok(guard)
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    fn apply(&mut self, cfg: &SessionConfig, peer_ip: Option<&str>, assign_addresses: bool) -> Result<()> {
        // The DNS firewall is a ruleset/table keyed on the device name alone:
        // nothing programmed below depends on it, and it depends on none of
        // that. Installing it first and in series made every desktop TUN start
        // pay for an nft/pfctl load before it even began on the addresses and
        // routes, and the tunnel is not up for the user until both are done.
        let device = self.device.clone();
        let (firewall, programmed) = std::thread::scope(|scope| {
            let firewall = scope.spawn(move || DnsFirewall::install(&device));
            let programmed = self.program(cfg, peer_ip, assign_addresses);
            let firewall = firewall
                .join()
                .unwrap_or_else(|_| Err(CoreError::Internal("[tun] DNS: the firewall installer panicked".into())));
            (firewall, programmed)
        });
        // On an error the guard is dropped, and its Drop is what puts back
        // whatever either half already changed.
        self.dns_firewall = Some(firewall?);
        programmed
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
        drop(self.dns_firewall.take());
        log::info!("[tun] routes/DNS restored for `{}`", self.device);
    }
}
