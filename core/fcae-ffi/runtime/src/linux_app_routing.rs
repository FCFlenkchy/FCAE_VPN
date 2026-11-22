//! Experimental app-managed controlled-launch bypass provider.
//! Only sockets created inside the owned cgroup are covered; existing instances,
//! D-Bus handoff and system-resolver DNS are deliberately not claimed as covered.
//! Callers must supply a physical uplink snapshot, not a route through the TUN.
#[path = "linux_app_routing_journal.rs"]
mod journal;
use journal::Journal;

use crate::app_routing::{
    Action, CompiledPolicy, Mechanism, Mode, PolicyError, Provider, Selector,
};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[derive(Clone, Debug)]
pub struct PhysicalUplink {
    pub interface: String,
    pub gateway: Option<IpAddr>,
    /// Connected prefixes on this interface, before tunnel setup.
    pub connected: Vec<String>,
}
impl PhysicalUplink {
    fn validate(&self, v6: bool) -> io::Result<()> {
        if self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
            || self.interface.starts_with('-')
            || self.gateway.is_some_and(|g| g.is_ipv6() != v6)
            || self.connected.len() > 1024
        {
            return Err(io::Error::other("invalid physical uplink"));
        }
        for prefix in &self.connected {
            let (address, bits) = prefix
                .split_once('/')
                .ok_or_else(|| io::Error::other("invalid connected prefix"))?;
            let address: IpAddr = address.parse().map_err(io::Error::other)?;
            let bits: u8 = bits.parse().map_err(io::Error::other)?;
            if address.is_ipv6() != v6 || bits == 0 || bits > if v6 { 128 } else { 32 } {
                return Err(io::Error::other(
                    "invalid connected prefix family or length",
                ));
            }
        }
        Ok(())
    }
}

fn tool(name: &str) -> io::Result<PathBuf> {
    // Never resolve privileged programs using a caller-controlled PATH.
    for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let path = Path::new(dir).join(name);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 {
                return Ok(path);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("trusted {name} executable unavailable"),
    ))
}
fn run(program: &Path, args: &[String], input: Option<&str>) -> io::Result<String> {
    use std::io::Write;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(text) = input {
        if let Err(error) = child.stdin.take().unwrap().write_all(text.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

/// Root-only in-process pilot, NOT an IPC/elevation service. Holds a root-owned
/// lock and uses only direct argv calls. Do not expose this object over raw IPC.
pub struct LinuxBypassProvider {
    ip: PathBuf,
    nft: PathBuf,
    _lock: File,
    cgroup: PathBuf,
    nft_table: String,
    table: u32,
    priority: u32,
    mark: u32,
    uplinks: [Option<PhysicalUplink>; 2],
    undo: Vec<(PathBuf, Vec<String>)>,
    nft_owned: bool,
    policy: Option<CompiledPolicy>,
}
impl LinuxBypassProvider {
    pub fn scope_path(&self) -> &Path {
        &self.cgroup
    }
    pub fn prepare(v4: Option<PhysicalUplink>, v6: Option<PhysicalUplink>) -> io::Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controlled launch requires root",
            ));
        }
        if let Some(u) = &v4 {
            u.validate(false)?;
            // Strict reverse-path filtering would drop physical replies whose
            // ordinary main-table return route points at the full-device TUN.
            // Do not mutate host sysctls implicitly in this experimental API.
            for iface in ["all", u.interface.as_str()] {
                let mode =
                    fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter"))?;
                if mode.trim() == "1" {
                    return Err(io::Error::other(
                        "strict rp_filter is incompatible with controlled bypass",
                    ));
                }
            }
        }
        if let Some(u) = &v6 {
            u.validate(true)?;
        }
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::other("no physical uplink supplied"));
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            return Err(io::Error::other("cgroup v2 is required"));
        }
        let lock = routing_lock()?;
        let ip = tool("ip")?;
        let nft = tool("nft")?;
        Self::recover_locked(&ip, &nft)?;
        let mut random = [0u8; 8];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let nonce = u64::from_ne_bytes(random);
        let slot = (nonce % 10000) as u32;
        let table = 40000 + slot;
        let priority = 10000 + slot;
        // Never replace a pre-existing table or rule priority.
        for family in ["-4", "-6"] {
            let rules: serde_json::Value =
                serde_json::from_str(&run(&ip, &words(&[family, "-j", "rule", "show"]), None)?)
                    .map_err(io::Error::other)?;
            if rules
                .as_array()
                .ok_or_else(|| io::Error::other("invalid rule inventory"))?
                .iter()
                .any(|r| {
                    let p = r["priority"].as_u64();
                    p == Some(priority as u64)
                        || p.is_some_and(|n| n > 0 && n < 32766)
                        || r["table"].as_u64() == Some(table as u64)
                        || r["table"].as_str() == Some(&table.to_string())
                })
            {
                return Err(io::Error::other(
                    "existing policy-routing rules conflict with this pilot",
                ));
            }
            let routes: serde_json::Value = serde_json::from_str(&run(
                &ip,
                &words(&[family, "-j", "route", "show", "table", "all"]),
                None,
            )?)
            .map_err(io::Error::other)?;
            if routes
                .as_array()
                .ok_or_else(|| io::Error::other("invalid route inventory"))?
                .iter()
                .any(|r| {
                    r["table"].as_u64() == Some(table as u64)
                        || r["table"].as_str() == Some(&table.to_string())
                })
            {
                return Err(io::Error::other("routing table collision"));
            }
        }
        let name = format!("fcae_app_{nonce:x}");
        let cgroup = Path::new("/sys/fs/cgroup").join(&name);
        fs::create_dir(&cgroup)?;
        let provider = Self {
            ip,
            nft,
            _lock: lock,
            cgroup,
            nft_table: name,
            table,
            priority,
            mark: 0xfc000000 | table,
            uplinks: [v4, v6],
            undo: Vec::new(),
            nft_owned: false,
            policy: None,
        };
        provider.ownership().store()?;
        Ok(provider)
    }
    fn add_ip(&mut self, args: Vec<String>, undo: Vec<String>) -> io::Result<()> {
        self.undo.push((self.ip.clone(), undo));
        self.ownership().store()?; // Durable intent must precede the OS mutation.
        run(&self.ip, &args, None)?;
        Ok(())
    }
    fn install_routes(&mut self) -> io::Result<()> {
        let table = self.table.to_string();
        let priority = self.priority.to_string();
        let mark = format!("{:#x}/0xffffffff", self.mark);
        for (index, family) in ["-4", "-6"].iter().enumerate() {
            // A missing physical family is unreachable, never a fallthrough to TUN.
            let base = words(&[
                family,
                "route",
                "add",
                "unreachable",
                "default",
                "table",
                &table,
                "metric",
                "32760",
            ]);
            let mut inverse = base.clone();
            inverse[2] = "del".into();
            self.add_ip(base, inverse)?;
            if let Some(uplink) = self.uplinks[index].clone() {
                for prefix in &uplink.connected {
                    let args = words(&[
                        family,
                        "route",
                        "add",
                        prefix,
                        "dev",
                        &uplink.interface,
                        "table",
                        &table,
                    ]);
                    let mut inverse = args.clone();
                    inverse[2] = "del".into();
                    self.add_ip(args, inverse)?;
                }
                let mut args = words(&[family, "route", "add", "default"]);
                if let Some(gateway) = uplink.gateway {
                    args.extend(words(&["via", &gateway.to_string()]));
                }
                args.extend(words(&["dev", &uplink.interface]));
                if uplink.gateway.is_some() {
                    args.push("onlink".into());
                }
                args.extend(words(&["table", &table, "metric", "100"]));
                let mut inverse = args.clone();
                inverse[2] = "del".into();
                self.add_ip(args, inverse)?;
            }
            let args = words(&[
                family, "rule", "add", "priority", &priority, "fwmark", &mark, "lookup", &table,
            ]);
            let mut inverse = args.clone();
            inverse[2] = "del".into();
            self.add_ip(args, inverse)?;
        }
        // Rerouting in OUTPUT does not rewrite the source address selected by
        // the original TUN route. Scope-marked masquerading corrects it on the
        // physical egress and conntrack restores replies, for IPv4 and IPv6.
        let script = format!("add table inet {0}\nadd chain inet {0} output {{ type route hook output priority -150; policy accept; }}\nadd chain inet {0} postrouting {{ type nat hook postrouting priority 100; policy accept; }}\nadd rule inet {0} output socket cgroupv2 level 1 \"{0}\" counter meta mark set {1:#x}\nadd rule inet {0} postrouting meta mark {1:#x} counter masquerade\n", self.nft_table, self.mark);
        // One atomic nft transaction, after both route families are prepared.
        self.nft_owned = true;
        self.ownership().store()?;
        run(&self.nft, &words(&["-f", "-"]), Some(&script))?;
        Ok(())
    }
    /// Launches a new non-root process inside the scope *before* exec/socket
    /// creation. No shell, no inherited application environment, no root target.
    /// Caller owns Child and must retain this provider until all descendants exit.
    pub fn launch(
        &self,
        executable: &Path,
        args: &[String],
        uid: u32,
        gid: u32,
    ) -> io::Result<Child> {
        let policy = self
            .policy
            .as_ref()
            .ok_or_else(|| io::Error::other("no installed launch policy"))?;
        if uid == 0 || gid == 0 {
            return Err(io::Error::other("root launch target refused"));
        }
        let path = fs::canonicalize(executable)?;
        let path_text = path
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF-8 executable"))?;
        if !policy
            .local_selectors()
            .contains(&Selector::LinuxLaunchTarget(path_text.to_owned()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable is not selected",
            ));
        }
        let membership = OpenOptions::new()
            .write(true)
            .open(self.cgroup.join("cgroup.procs"))?;
        let (account_gid, account, home) = launch_user(uid)?;
        if account_gid != gid {
            return Err(io::Error::other("target group does not match account"));
        }
        let mut command = Command::new(&path);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", &home)
            .env("USER", &account)
            .env("LOGNAME", &account)
            .current_dir(&home)
            .stdin(Stdio::null());
        let runtime = format!("/run/user/{uid}");
        if fs::metadata(&runtime)
            .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0)
        {
            command.env("XDG_RUNTIME_DIR", runtime);
        }
        for key in ["DISPLAY", "WAYLAND_DISPLAY"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let authority = Path::new(&home).join(".Xauthority");
        if fs::metadata(&authority).is_ok_and(|m| m.is_file() && m.uid() == uid) {
            command.env("XAUTHORITY", authority);
        }
        // Do not copy root's HOME, proxy settings, loader variables or bus address.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // write(2) with a stack buffer: no allocation or locks after fork.
                let mut digits = [0u8; 24];
                let mut at = digits.len();
                let mut pid = libc::getpid() as u32;
                loop {
                    at -= 1;
                    digits[at] = b'0' + (pid % 10) as u8;
                    pid /= 10;
                    if pid == 0 {
                        break;
                    }
                }
                let len = digits.len() - at;
                if libc::write(membership.as_raw_fd(), digits[at..].as_ptr().cast(), len)
                    != len as isize
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
    fn cleanup(&mut self) -> io::Result<()> {
        // Removing policy while descendants still run could silently recapture
        // intentional bypass traffic. Refuse instead; never kill arbitrary apps.
        if self.scope_populated()? {
            return Err(io::Error::other("launch scope still has live processes"));
        }
        if self.nft_owned {
            delete_allow_absent(
                &self.nft,
                &words(&["delete", "table", "inet", &self.nft_table]),
            )?;
            self.nft_owned = false;
        }
        // Keep failed undo entries so explicit rollback can be retried.
        while let Some((program, args)) = self.undo.last() {
            delete_allow_absent(program, args)?;
            self.undo.pop();
        }
        self.policy = None;
        match fs::remove_dir(&self.cgroup) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.ownership().remove()?;
        Ok(())
    }
}
impl Provider for LinuxBypassProvider {
    fn mechanism(&self) -> Mechanism {
        Mechanism::ControlledLaunch
    }
    fn install(&mut self, policy: &CompiledPolicy) -> Result<u64, PolicyError> {
        // This pilot controls only its launched bypass scope. It cannot promise
        // blocking of unknown/out-of-scope traffic or a VPN-required kill switch.
        if policy.mode() != Mode::Exclude
            || policy.unknown_action() != Action::Tunnel
            || policy.fail_closed()
            || !policy.foreign_selectors().is_empty()
            || policy.local_selectors().is_empty()
            || self.policy.is_some()
            || !self.undo.is_empty()
            || self.nft_owned
            || !self.cgroup.exists()
        {
            return Err(PolicyError::ProviderUnavailable);
        }
        for selector in policy.local_selectors() {
            let Selector::LinuxLaunchTarget(path) = selector else {
                return Err(PolicyError::InvalidSelector);
            };
            let canonical = fs::canonicalize(path).map_err(|_| PolicyError::InvalidSelector)?;
            if canonical.to_str() != Some(path) || !canonical.is_file() {
                return Err(PolicyError::InvalidSelector);
            }
        }
        if let Err(error) = self.install_routes() {
            let cleanup = self.cleanup();
            return Err(PolicyError::ProviderOperation(format!(
                "{error}; rollback: {cleanup:?}"
            )));
        }
        self.policy = Some(policy.clone());
        Ok(policy.revision())
    }
    fn rollback(&mut self) -> Result<(), PolicyError> {
        self.cleanup()
            .map_err(|e| PolicyError::ProviderOperation(e.to_string()))
    }
}
impl Drop for LinuxBypassProvider {
    fn drop(&mut self) {
        match self.cleanup() {
            Ok(()) => {
                let _ = fs::remove_dir(&self.cgroup);
            }
            Err(error) => log::error!(
                "[app-routing] scope {} retained: {}",
                self.cgroup.display(),
                error
            ),
        }
    }
}

/// Resolve target credentials before fork; never reuse privileged app credentials.
pub fn launch_user(uid: u32) -> io::Result<(u32, String, String)> {
    if uid == 0 {
        return Err(io::Error::other("root target refused"));
    }
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code));
    }
    if found.is_null() || entry.pw_gid == 0 || entry.pw_dir.is_null() || entry.pw_name.is_null() {
        return Err(io::Error::other("non-root target user not found"));
    }
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(io::Error::other)?
        .to_owned();
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(io::Error::other)?
        .to_owned();
    if !Path::new(&home).is_absolute() {
        return Err(io::Error::other("target home must be absolute"));
    }
    Ok((entry.pw_gid, name, home))
}

impl LinuxBypassProvider {
    pub fn scope_populated(&self) -> io::Result<bool> {
        match fs::read_to_string(self.cgroup.join("cgroup.events")) {
            Ok(events) => Ok(events.lines().any(|line| line == "populated 1")),
            Err(e) if e.kind() == io::ErrorKind::NotFound && !self.cgroup.exists() => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// Explicit app-owned scope termination, never an unrelated discovered PID.
    pub fn terminate_scope(&self) -> io::Result<()> {
        fs::write(self.cgroup.join("cgroup.kill"), b"1")
    }
    pub fn prepare_detected() -> io::Result<Self> {
        let ip = tool("ip")?;
        let mut uplinks = [None, None];
        for (index, family) in ["-4", "-6"].iter().enumerate() {
            let routes: serde_json::Value = serde_json::from_str(&run(
                &ip,
                &words(&[family, "-j", "route", "show", "table", "main", "default"]),
                None,
            )?)
            .map_err(io::Error::other)?;
            let mut candidates = routes
                .as_array()
                .ok_or_else(|| io::Error::other("invalid default route inventory"))?
                .clone();
            candidates.sort_by_key(|r| r["metric"].as_u64().unwrap_or(0));
            for route in candidates {
                let Some(interface) = route["dev"].as_str() else {
                    continue;
                };
                let Some(gateway) = route["gateway"].as_str() else {
                    continue;
                };
                let candidate = PhysicalUplink {
                    interface: interface.to_owned(),
                    gateway: Some(gateway.parse().map_err(io::Error::other)?),
                    connected: Vec::new(),
                };
                candidate.validate(index == 1)?;
                // Automatic discovery is deliberately physical-device-only.
                // Do not accidentally select the VPN's default route as bypass.
                if !Path::new("/sys/class/net")
                    .join(interface)
                    .join("device")
                    .exists()
                {
                    continue;
                }
                let connected: serde_json::Value = serde_json::from_str(&run(
                    &ip,
                    &words(&[
                        family, "-j", "route", "show", "table", "main", "dev", interface, "scope",
                        "link",
                    ]),
                    None,
                )?)
                .map_err(io::Error::other)?;
                let mut candidate = candidate;
                for route in connected
                    .as_array()
                    .ok_or_else(|| io::Error::other("invalid connected route inventory"))?
                {
                    if let Some(prefix) = route["dst"].as_str().filter(|p| p.contains('/')) {
                        candidate.connected.push(prefix.to_owned());
                    }
                }
                candidate.validate(index == 1)?;
                uplinks[index] = Some(candidate);
                break;
            }
        }
        let [v4, v6] = uplinks;
        let provider = Self::prepare(v4, v6)?;
        if !provider.cgroup.join("cgroup.kill").exists() {
            return Err(io::Error::other(
                "app-managed launch requires cgroup.kill support (Linux 5.14+)",
            ));
        }
        Ok(provider)
    }
}

fn routing_lock() -> io::Result<File> {
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/fcae-app-routing.lock")?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(io::Error::other("insecure routing lock"));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock)
}

fn delete_allow_absent(program: &Path, args: &[String]) -> io::Result<()> {
    match run(program, args, None) {
        Ok(_) => Ok(()),
        Err(e) => {
            let message = e.to_string();
            // ip/nft run with LC_ALL=C. Other failures retain the journal.
            if e.kind() == io::ErrorKind::Other
                && (message.contains("No such process")
                    || message.contains("No such file or directory"))
            {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
impl LinuxBypassProvider {
    fn ownership(&self) -> Journal {
        Journal {
            version: 1,
            scope: self.nft_table.clone(),
            table: self.table,
            priority: self.priority,
            mark: self.mark,
            undo: self.undo.iter().map(|(_, args)| args.clone()).collect(),
            nft_intent: self.nft_owned,
        }
    }
    pub fn recover_stale() -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::other("routing recovery requires root"));
        }
        let _lock = routing_lock()?;
        Self::recover_locked(&tool("ip")?, &tool("nft")?)
    }
    // The global root lock must be held for the whole replay. Live scopes are
    // not killed or silently rerouted: the user can close those applications.
    fn recover_locked(ip: &Path, nft: &Path) -> io::Result<()> {
        for journal in Journal::load_all()? {
            let scope = journal.scope_path();
            match fs::read_to_string(scope.join("cgroup.events")) {
                Ok(events) if events.lines().any(|line| line == "populated 1") => {
                    return Err(io::Error::other(format!("Previous scope {} still has applications. Close them before retrying recovery.", scope.display())));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound && !scope.exists() => {}
                Err(e) => return Err(e),
            }
            if journal.nft_intent {
                delete_allow_absent(nft, &words(&["delete", "table", "inet", &journal.scope]))?;
            }
            for args in journal.undo.iter().rev() {
                delete_allow_absent(ip, args)?;
            }
            match fs::remove_dir(scope) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            journal.remove()?;
        }
        Ok(())
    }
}
