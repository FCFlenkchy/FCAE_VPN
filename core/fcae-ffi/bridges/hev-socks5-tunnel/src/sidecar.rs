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

use crate::socks5p;
use crate::socks5t;
use crate::{bare_address, log_level, HevStats};

const SIDECAR_EXE: &str = "hev-socks5-tunnel.exe";
const SIDECAR_ENV: &str = "FCAE_HEV_SIDECAR";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

const CTRL_C_EVENT: u32 = 0;

const START_PROBE: Duration = Duration::from_millis(250);
const MAX_ATTEMPTS: u32 = 2;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const TERMINATE_GRACE: Duration = Duration::from_secs(2);
const LOG_TAIL_BYTES: usize = 600;

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
  udp: 'udp'

misc:
  log-level: '{level}'
  log-file: '{log}'
";

const _: () = assert!(
    contains(CONFIG.as_bytes(), crate::WINTUN_ADAPTER_GUID.as_bytes()),
    "the hardcoded engine config no longer carries the shared adapter GUID"
);

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

struct Active {
    child: Child,
    config: PathBuf,
    log: PathBuf,
    undo: platform::TunUndo,
    _psiphon: Option<socks5p::Adapter>,
    _tor: Option<socks5t::Adapter>,
}

pub struct HevSocks5TunnelBridge {
    lifecycle: Mutex<()>,
    active: Mutex<Option<Active>>,
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

    pub fn set_android_fd(&self, _fd: i32) {}
    pub fn clear_android_fd(&self) {}
    pub fn android_fd(&self) -> Option<i32> {
        None
    }
    pub fn stats(&self) -> Option<HevStats> {
        None
    }

    fn launch(
        &self,
        cfg: &SessionConfig,
        socks: SocketAddr,
    ) -> Result<(Child, PathBuf, PathBuf)> {
        let exe = exe_path().ok_or_else(|| {
            CoreError::Internal(format!(
                "{SIDECAR_EXE} is missing from the installation (set {SIDECAR_ENV} to override)"
            ))
        })?;

        platform::ensure_wintun(None)?;

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
            .map_err(|e| CoreError::Internal(format!("cannot start {}: {e}", exe.display())))?;

        Ok((child, config, log))
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        let _lifecycle = self.lifecycle.lock();

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

        let base_socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        let psiphon_adapter = if endpoints.psiphon_dns {
            Some(socks5p::Adapter::start(base_socks).map_err(|e| {
                CoreError::Internal(format!("hev socks5p adapter: {e}"))
            })?)
        } else {
            None
        };

        let tor_adapter = if psiphon_adapter.is_none() && cfg.tor.is_exit() {
            Some(socks5t::Adapter::start(base_socks).map_err(|e| {
                CoreError::Internal(format!("hev socks5t adapter: {e}"))
            })?)
        } else {
            None
        };

        let effective_socks = psiphon_adapter
            .as_ref()
            .map(|a| a.endpoint())
            .or_else(|| tor_adapter.as_ref().map(|a| a.endpoint()))
            .unwrap_or(base_socks);

        if psiphon_adapter.is_some() {
            log::info!("[hev] socks5p: native Psiphon DNS gateway, no direct DNS fallback");
        } else if tor_adapter.is_some() {
            log::info!("[hev] socks5t: DNS-over-TCP through Tor SOCKS");
        }

        let mut attempt = 0;
        let mut psiphon_holder = psiphon_adapter;
        let mut tor_holder = tor_adapter;

        loop {
            attempt += 1;
            let (mut child, config, log) = self.launch(cfg, effective_socks)?;

            std::thread::sleep(START_PROBE);
            match child.try_wait() {
                Ok(Some(status)) => {
                    let tail = log_tail(&log);
                    if attempt < MAX_ATTEMPTS && could_not_open_device(&tail) {
                        log::warn!(
                            "[hev] the engine could not open its device; removing the stale `{}` adapter and retrying",
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
                Ok(u) => u,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let tail = log_tail(&log);
                    let _ = std::fs::remove_file(&config);
                    let _ = std::fs::remove_file(&log);
                    return Err(CoreError::Internal(format!("{e}{tail}")));
                }
            };

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
                _psiphon: psiphon_holder.take(),
                _tor: tor_holder.take(),
            });
            log::info!("[hev] up (mtu {})", cfg.tun.mtu);
            return Ok(());
        }
    }

    fn abort(&self) {
        let _lifecycle = self.lifecycle.lock();
        if let Some(mut active) = self.active.lock().take() {
            terminate(&mut active.child);
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

fn work_dir() -> PathBuf {
    std::env::temp_dir().join("fcaevpn")
}

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

pub fn is_available() -> bool {
    exe_path().is_some()
}

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

fn terminate(child: &mut Child) {
    let _ = child.kill();
}

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
        .map(|s| s.success())
        .unwrap_or(false);
    if !removed {
        log::debug!("[hev] could not remove a stale `{name}` adapter");
    }
}

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

fn scalar(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            resolve_exe(Some(&dir), Some("C:\\nope\\hev.exe")),
            Some(exe)
        );
        assert_eq!(resolve_exe(None, None), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_an_open_failure_is_worth_retrying() {
        assert!(could_not_open_device(
            "\nengine log: socks5 tunnel open (File exists)"
        ));
        assert!(could_not_open_device("wintun adapter guid (zzz)"));
        assert!(!could_not_open_device(""));
        assert!(!could_not_open_device(
            "\nengine log: socks5 client handshake"
        ));
    }

    #[test]
    fn a_missing_log_reads_as_no_diagnosis() {
        let path = std::env::temp_dir().join("fcae-hev-absent.log");
        std::fs::remove_file(&path).ok();
        assert_eq!(log_tail(&path), "");
    }

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
