//! Windows backend: upstream's `hev-socks5-tunnel.exe` as a child process.
//!
//! hev's Windows support lives behind `__MSYS__` (tun device, hev-task-system
//! IOCP reactor, Win64 ABI assembly, wintun session) and its binaries link the
//! MSYS runtime, which has to own the process: MSYS2's own documentation states
//! its DLLs are ABI-incompatible with anything outside MSYS2, and no Rust target
//! builds for it. So the engine runs as a separate process — the same
//! executable upstream ships — with three consequences this module handles:
//!
//! * **Configuration is a file.** The engine's CLI takes a YAML path and creates
//!   the device itself, so this backend hands it [`CONFIG`] — the engine config,
//!   spelled out in full below — through a temporary file; the engine then
//!   creates the adapter (name, GUID, address, MTU) while routing and DNS stay
//!   ours, in the platform layer the other engines use.
//! * **There is no IPC.** The engine's stop flag is only reachable through the
//!   in-process API, so `stop` delivers a console Ctrl+C (what an MSYS build
//!   maps onto the `SIGINT` its CLI handles, and a clean exit is what removes the
//!   wintun adapter) and falls back to terminating the process.
//! * **Failures are invisible.** The engine has no stderr worth reading, so it is
//!   told to log to a file and the tail of that file is what a failed start
//!   reports.
//!
//! One wintun adapter identity is shared with the other engines: [`CONFIG`]
//! carries the same adapter name and the same GUID they use, so switching
//! engines keeps the adapter, its firewall profile and its DNS assignment.

use std::net::SocketAddr;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fcae_bridge_tun2socks::platform;
use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

use crate::{bare_address, log_level, HevStats};

/// Name of the engine executable; it is installed beside our own binary.
const SIDECAR_EXE: &str = "hev-socks5-tunnel.exe";
/// Overrides the lookup, for development builds that keep the exe elsewhere.
const SIDECAR_ENV: &str = "FCAE_HEV_SIDECAR";

/// A GUI app must not flash a console window for its child; the child still
/// gets a console (hidden), which is what [`request_stop`] delivers the event
/// to.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

const CTRL_C_EVENT: u32 = 0;

/// How long a fresh engine is given to prove it stays up before the interface
/// is configured for it. Long enough for a config or adapter failure to exit.
const START_PROBE: Duration = Duration::from_millis(250);
/// One retry: a killed engine leaves its wintun adapter behind, and a stale
/// adapter is the one startup failure worth fixing automatically.
const MAX_ATTEMPTS: u32 = 2;
/// How often the child is polled while a stop is in flight.
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// How long a stop waits for the engine's clean shutdown before terminating it.
const TERMINATE_GRACE: Duration = Duration::from_secs(2);
/// How much of the engine log an error message carries.
const LOG_TAIL_BYTES: usize = 600;

/// The engine's configuration, written out once instead of assembled from the
/// session.
///
/// Windows cannot host the engine in-process, so this file *is* the handover:
/// everything the product fixes — the adapter identity and GUID, the queue
/// model, how ICMP and UDP are answered and where the log goes — is spelled out
/// here, and only the values that follow the session are substituted (see
/// [`render_config`]). The tunnel section has to match the interface
/// [`platform::configure`] builds, since the engine creates the device from it.
const CONFIG: &str = "\
tunnel:
  name: '{name}'
  guid: 24198F4C-7895-434C-AD65-9E29A92DDC61
  mtu: {mtu}
  multi-queue: false
  ipv4: {ipv4}
  ipv6: '{ipv6}'
  icmp: 'off'

socks5:
  port: {port}
  address: '{address}'
  udp: 'tcp'

misc:
  log-level: '{level}'
  log-file: '{log}'
";

/// The config above pins the same adapter as the other engines: the compiler
/// holds the two copies together so neither can be edited on its own.
const _: () = assert!(
    contains(CONFIG.as_bytes(), crate::WINTUN_ADAPTER_GUID.as_bytes()),
    "the hardcoded engine config no longer carries the shared adapter GUID"
);

/// `str::contains` is not const.
const fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        let mut j = 0;
        while j < needle.len() && haystack[i + j] == needle[j] {
            j += 1;
        }
        if j == needle.len() {
            return true;
        }
        i += 1;
    }
    false
}

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(dw_process_id: u32) -> i32;
    fn FreeConsole() -> i32;
    fn GenerateConsoleCtrlEvent(dw_ctrl_event: u32, dw_process_group_id: u32) -> i32;
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
}

/// A live engine process and everything that has to be undone with it.
struct Active {
    child: Child,
    config: PathBuf,
    log: PathBuf,
    /// Routing and DNS applied for this session; undone on stop.
    undo: platform::TunUndo,
}

/// The bridge. One per process; `TunBridge` methods are safe to call from any
/// thread and are idempotent.
pub struct HevSocks5TunnelBridge {
    /// Serialises `start`/`stop`/`abort`: one engine process at a time, and a
    /// teardown must never interleave with a start.
    lifecycle: Mutex<()>,
    active: Mutex<Option<Active>>,
    /// Distinguishes the temporary files of successive engines.
    sequence: AtomicU32,
}

impl Default for HevSocks5TunnelBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl HevSocks5TunnelBridge {
    pub fn new() -> Self {
        Self {
            lifecycle: Mutex::new(()),
            active: Mutex::new(None),
            sequence: AtomicU32::new(0),
        }
    }

    /// Android hands the descriptor to the in-process engine; the sidecar never
    /// runs there. The FFI forwards the descriptor to every engine
    /// unconditionally, so the method exists to keep one API for both backends.
    pub fn set_android_fd(&self, _fd: i32) {}

    /// Counterpart of [`Self::set_android_fd`].
    pub fn clear_android_fd(&self) {}

    /// Counterpart of [`Self::set_android_fd`].
    pub fn android_fd(&self) -> Option<i32> {
        None
    }

    /// The engine's counters live in its own process and its CLI exposes no
    /// channel for them, so there is nothing to read.
    pub fn stats(&self) -> Option<HevStats> {
        None
    }

    /// Hand the engine a session: write its config, start the process and route
    /// the interface it creates.
    ///
    /// There is no engine thread to join here: the data plane runs in the
    /// child, so a start only has to be sure the previous process is gone
    /// before a new one takes the adapter.
    fn launch(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
    ) -> Result<(Child, PathBuf, PathBuf)> {
        let exe = exe_path().ok_or_else(|| {
            CoreError::Internal(format!(
                "{SIDECAR_EXE} is missing from the installation (set {SIDECAR_ENV} to override)"
            ))
        })?;

        // The engine loads wintun.dll from its own directory or System32. The
        // packaging step places it beside the executable; this turns a missing
        // driver into a clear error instead of an opaque engine exit.
        platform::ensure_wintun(None)?;

        let socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        let dir = work_dir();
        std::fs::create_dir_all(&dir).map_err(|e| {
            CoreError::Internal(format!("cannot create {}: {e}", dir.display()))
        })?;
        let stem = format!("hev-{}-{sequence}", std::process::id());
        let config = dir.join(format!("{stem}.yml"));
        let log = dir.join(format!("{stem}.log"));

        let yaml = render_config(cfg, socks, &log.to_string_lossy());
        std::fs::write(&config, yaml)
            .map_err(|e| CoreError::Internal(format!("cannot write {}: {e}", config.display())))?;

        log::info!("[hev] starting sidecar (socks {socks}, mtu {})", cfg.tun.mtu);

        let child = Command::new(&exe)
            .arg(&config)
            .creation_flags(CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                CoreError::Internal(format!("cannot start {}: {e}", exe.display()))
            })?;

        Ok((child, config, log))
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        let _lifecycle = self.lifecycle.lock();

        // A previous engine must be gone before another one takes the adapter —
        // and if it died on its own, its routing still has to come down.
        let stale = {
            let mut slot = self.active.lock();
            if slot
                .as_mut()
                .is_some_and(|active| matches!(active.child.try_wait(), Ok(None)))
            {
                return Err(CoreError::Internal(
                    "hev-socks5-tunnel is already running".into(),
                ));
            }
            slot.take()
        };
        if let Some(stale) = stale {
            remove_temp(&stale.config, &stale.log);
            platform::restore(stale.undo, Duration::from_millis(250));
        }

        let mut attempt = 0;
        loop {
            attempt += 1;
            let (mut child, config, log) = self.launch(cfg, endpoints)?;

            // Give a broken engine the chance to fail before the interface is
            // configured for it; configure() then waits for the adapter itself.
            std::thread::sleep(START_PROBE);
            match child.try_wait() {
                Ok(Some(status)) => {
                    let tail = log_tail(&log);
                    if attempt < MAX_ATTEMPTS && could_not_open_device(&tail) {
                        log::warn!(
                            "[hev] the engine could not open its device; removing the stale \
                             `{}` adapter and retrying",
                            cfg.tun.name
                        );
                        remove_stale_adapter(&cfg.tun.name);
                        let _ = std::fs::remove_file(&config);
                        let _ = std::fs::remove_file(&log);
                        continue;
                    }
                    let _ = std::fs::remove_file(&config);
                    let _ = std::fs::remove_file(&log);
                    return Err(CoreError::Internal(format!(
                        "hev-socks5-tunnel exited during startup ({status}){tail}"
                    )));
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = std::fs::remove_file(&config);
                    return Err(CoreError::Internal(format!(
                        "cannot poll the hev-socks5-tunnel process: {e}"
                    )));
                }
            }

            let undo = match platform::configure(cfg, endpoints.peer_ip.as_deref()) {
                Ok(undo) => undo,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let tail = log_tail(&log);
                    let _ = std::fs::remove_file(&config);
                    let _ = std::fs::remove_file(&log);
                    return Err(CoreError::Internal(format!("{e}{tail}")));
                }
            };

            // Configuring the interface takes up to seconds; the engine may have
            // died meanwhile, and reporting a live tunnel would be a lie.
            if let Ok(Some(status)) = child.try_wait() {
                platform::restore(undo, Duration::from_millis(250));
                let tail = log_tail(&log);
                let _ = std::fs::remove_file(&config);
                let _ = std::fs::remove_file(&log);
                return Err(CoreError::Internal(format!(
                    "hev-socks5-tunnel exited during startup ({status}){tail}"
                )));
            }

            *self.active.lock() = Some(Active {
                child,
                config,
                log,
                undo,
            });
            log::info!("[hev] up (mtu {})", cfg.tun.mtu);
            return Ok(());
        }
    }

    fn abort(&self) {
        let _lifecycle = self.lifecycle.lock();

        // Non-blocking by contract: the child is terminated outright (a killed
        // MSYS process leaves nothing behind but its adapter, which the next
        // start retries around) and the routing is undone right here, since no
        // later stop may arrive to do it.
        if let Some(mut active) = self.active.lock().take() {
            terminate(&mut active.child);
            // Reaping a terminated process is bounded by the OS, not by the
            // engine's shutdown path, so undoing the routing after it is safe.
            let _ = active.child.wait();
            remove_temp(&active.config, &active.log);
            platform::restore(active.undo, Duration::from_millis(250));
        }
    }

    fn stop(&self, timeout: Duration) {
        let _lifecycle = self.lifecycle.lock();

        if let Some(mut active) = self.active.lock().take() {
            if !stop_child(&mut active.child, timeout) {
                log::warn!("[hev] engine did not stop within {timeout:?}; terminating it");
                terminate(&mut active.child);
                let _ = active.child.wait();
            }
            remove_temp(&active.config, &active.log);
            platform::restore(active.undo, timeout);
            log::info!("[hev] down");
        }
    }

    fn is_running(&self) -> bool {
        match self.active.lock().as_mut() {
            Some(active) => matches!(active.child.try_wait(), Ok(None)),
            None => false,
        }
    }
}

/// Where the engine's temporary files live.
fn work_dir() -> PathBuf {
    std::env::temp_dir().join("fcaevpn")
}

/// The engine executable: an explicit override, else beside our own binary,
/// which is where packaging installs it.
fn resolve_exe(dir: Option<&Path>, override_path: Option<&str>) -> Option<PathBuf> {
    if let Some(path) = override_path {
        let path = PathBuf::from(path.trim());
        if path.is_file() {
            return Some(path);
        }
    }
    let exe = dir?.join(SIDECAR_EXE);
    exe.is_file().then_some(exe)
}

fn exe_path() -> Option<PathBuf> {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let override_path = std::env::var(SIDECAR_ENV).ok();
    resolve_exe(dir.as_deref(), override_path.as_deref())
}

/// True when the engine executable is installed, i.e. this build can run it.
pub fn is_available() -> bool {
    exe_path().is_some()
}

/// Deliver a console Ctrl+C to the engine.
///
/// An MSYS build turns that into `SIGINT`, which the engine's CLI handles by
/// stopping the tunnel — and a clean exit is what removes the wintun adapter.
/// The event reaches the console the child was created with, so this attaches
/// to it first and shields this process from its own event.
fn request_stop(pid: u32) -> bool {
    unsafe {
        if AttachConsole(pid) == 0 {
            return false;
        }
        SetConsoleCtrlHandler(None, 1);
        let raised = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0;
        SetConsoleCtrlHandler(None, 0);
        FreeConsole();
        raised
    }
}

/// Stop the engine cleanly, then by force. `true` = the process exited.
fn stop_child(child: &mut Child, timeout: Duration) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return true;
    }
    request_stop(child.id());

    let deadline = Instant::now() + timeout.min(TERMINATE_GRACE);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

/// Terminate the engine without waiting for a clean shutdown.
fn terminate(child: &mut Child) {
    let _ = child.kill();
}

/// Remove a leftover adapter of `name`.
///
/// Only used after the engine reported it could not open its device: at that
/// point nothing is attached to the adapter, and a killed engine leaves one
/// behind precisely because Wintun only removes adapters on a clean close.
fn remove_stale_adapter(name: &str) {
    let script = format!(
        "Remove-NetAdapter -Name '{}' -Confirm:$false -ErrorAction SilentlyContinue",
        name.replace('\'', "''")
    );
    let removed = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !removed {
        log::debug!("[hev] could not remove a stale `{name}` adapter");
    }
}

/// Whether an engine log tail says the device could not be opened.
fn could_not_open_device(tail: &str) -> bool {
    let tail = tail.to_ascii_lowercase();
    tail.contains("tunnel open") || tail.contains("wintun")
}

fn log_tail(path: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    let start = text.len().saturating_sub(LOG_TAIL_BYTES);
    let start = (start..text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    format!("\nengine log: {}", &text[start..])
}

fn remove_temp(config: &Path, log: &Path) {
    let _ = std::fs::remove_file(config);
    let _ = std::fs::remove_file(log);
}

/// Fill [`CONFIG`] in: the values that differ per session, and nothing else.
///
/// A single pass, so a value that happens to contain braces is never read back
/// as one of the placeholders.
fn render_config(cfg: &SessionConfig, socks: SocketAddr, log: &str) -> String {
    let mut out = String::with_capacity(CONFIG.len() + 128);
    let mut rest = CONFIG;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        out.push_str(&rest[..open]);
        match &after[..close] {
            "name" => out.push_str(&scalar(&cfg.tun.name)),
            "mtu" => out.push_str(&cfg.tun.mtu.to_string()),
            "ipv4" => out.push_str(bare_address(&cfg.tun.ipv4)),
            "ipv6" => out.push_str(match &cfg.tun.ipv6 {
                Some(ipv6) => bare_address(ipv6),
                // Empty, not a placeholder like `false`: the engine runs
                // `inet_pton` over this value and treats a parse failure as a
                // tunnel it could not open. An empty string is what its own
                // getter reads as "this adapter has no IPv6".
                None => "",
            }),
            "port" => out.push_str(&socks.port().to_string()),
            "address" => out.push_str(&socks.ip().to_string()),
            "level" => out.push_str(log_level(cfg.tun.t2s_log_level)),
            "log" => out.push_str(&scalar(log)),
            other => {
                out.push('{');
                out.push_str(other);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// A single-quoted YAML scalar for text that comes from outside — the adapter
/// name and the log path: backslashes stay literal, and the quote is the only
/// character that has to be doubled.
fn scalar(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GUID is pinned in the config the engine is handed, and it is the one
    /// the other engines give wintun.
    #[test]
    fn the_hardcoded_config_pins_the_shared_adapter_guid() {
        let rendered = render_config(
            &SessionConfig::default(),
            "127.0.0.1:1819".parse().expect("endpoint"),
            r"C:\Temp\fcae\hev.log",
        );

        assert!(
            rendered.contains("\n  guid: 24198F4C-7895-434C-AD65-9E29A92DDC61\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("\n  guid: {}\n", crate::WINTUN_ADAPTER_GUID)),
            "{rendered}"
        );
    }

    /// Everything the engine needs from the session, and nothing left over: the
    /// adapter it creates is the one the platform layer goes on to configure.
    #[test]
    fn the_hardcoded_config_carries_the_session_into_the_engine() {
        let mut cfg = SessionConfig::default();
        cfg.tun.name = "FCAE'S VPN".into();
        cfg.tun.mtu = 1420;
        cfg.tun.ipv4 = "198.18.0.1/24".into();
        cfg.tun.ipv6 = None;
        cfg.tun.t2s_log_level = 5;

        let rendered = render_config(
            &cfg,
            "127.0.0.1:1819".parse().expect("endpoint"),
            r"C:\Users\fcae\hev.log",
        );

        assert!(rendered.contains("\n  name: 'FCAE''S VPN'\n"), "{rendered}");
        assert!(rendered.contains("\n  mtu: 1420\n"), "{rendered}");
        assert!(rendered.contains("\n  ipv4: 198.18.0.1\n"), "{rendered}");
        assert!(rendered.contains("\n  ipv6: ''\n"), "{rendered}");
        assert!(rendered.contains("\n  port: 1819\n"), "{rendered}");
        assert!(rendered.contains("\n  address: '127.0.0.1'\n"), "{rendered}");
        assert!(rendered.contains("\n  log-level: 'debug'\n"), "{rendered}");
        assert!(
            rendered.contains(r"  log-file: 'C:\Users\fcae\hev.log'"),
            "{rendered}"
        );
        assert!(!rendered.contains('{'), "a placeholder was left: {rendered}");
    }

    #[test]
    fn the_executable_is_looked_up_beside_our_own_binary() {
        let dir = std::env::temp_dir().join(format!("fcae-hev-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let exe = dir.join(SIDECAR_EXE);

        assert_eq!(resolve_exe(Some(&dir), None), None);
        std::fs::write(&exe, b"stub").expect("write exe");
        assert_eq!(resolve_exe(Some(&dir), None), Some(exe.clone()));

        // An override that does not exist must not shadow a real installation.
        assert_eq!(resolve_exe(Some(&dir), Some("C:\\nope\\hev.exe")), Some(exe));
        assert_eq!(resolve_exe(None, None), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_an_open_failure_is_worth_retrying() {
        assert!(could_not_open_device("\nengine log: socks5 tunnel open (File exists)"));
        assert!(could_not_open_device("wintun adapter guid (zzz)"));
        assert!(!could_not_open_device(""));
        assert!(!could_not_open_device("\nengine log: socks5 client handshake"));
    }

    #[test]
    fn a_missing_log_reads_as_no_diagnosis() {
        let path = std::env::temp_dir().join("fcae-hev-absent.log");
        std::fs::remove_file(&path).ok();
        assert_eq!(log_tail(&path), "");
    }

    /// Nothing is up, so a stop must not wait for anything or touch routing.
    #[test]
    fn stopping_an_idle_bridge_is_a_no_op() {
        let bridge = HevSocks5TunnelBridge::new();
        assert!(!bridge.is_running());
        assert!(bridge.stats().is_none());
        bridge.stop(Duration::from_millis(1));
        bridge.abort();
        assert!(!bridge.is_running());
    }
}
