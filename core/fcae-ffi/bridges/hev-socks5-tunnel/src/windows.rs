use std::io::{BufRead, BufReader, Write};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::windows_dll::EmbeddedFiles;
use fcae_runtime::windows_tun::TunGuard;
use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, CREATE_NO_WINDOW};

use crate::{socks5p, socks5t, HevStats};

const HOST: &str = "fcae-hev-host.exe";
#[cfg(hev_dynamic)]
const FILES: &[(&str, &[u8])] = &[
    (HOST, include_bytes!(concat!(env!("OUT_DIR"), "/engine/fcae-hev-host.exe"))),
    ("libhev-socks5-tunnel.dll", include_bytes!(concat!(env!("OUT_DIR"), "/engine/libhev-socks5-tunnel.dll"))),
    ("libyaml.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/libyaml.so"))),
    ("liblwip.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/liblwip.so"))),
    ("libhev-task-system.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/libhev-task-system.so"))),
    ("msys-2.0.dll", include_bytes!(concat!(env!("OUT_DIR"), "/engine/msys-2.0.dll"))),
    #[cfg(wintun_staged)]
    ("wintun.dll", include_bytes!(env!("FCAE_HEV_WINTUN_DLL"))),
];
static FILE_SET: OnceLock<std::result::Result<EmbeddedFiles, String>> = OnceLock::new();

pub fn unavailable_reason() -> Option<&'static str> {
    if !cfg!(all(hev_dynamic, wintun_staged)) {
        return Some("HEV Windows helper or Wintun was not embedded in this build");
    }
    FILE_SET.get().and_then(|result| result.as_ref().err().map(String::as_str))
}

pub fn is_supported() -> bool { unavailable_reason().is_none() }

fn files() -> Result<&'static EmbeddedFiles> {
    #[cfg(all(hev_dynamic, wintun_staged))]
    {
        FILE_SET.get_or_init(|| EmbeddedFiles::stage(FILES).map_err(|e| e.to_string()))
            .as_ref().map_err(|e| CoreError::Internal(e.clone()))
    }
    #[cfg(not(all(hev_dynamic, wintun_staged)))]
    { Err(CoreError::Internal("HEV Windows helper or Wintun was not embedded in this build".into())) }
}

struct StopEvent { handle: usize, name: String }
impl StopEvent {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..4 {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let name = format!("Local\\FCAE_HEV_{}_{}_{}", std::process::id(), stamp, NEXT.fetch_add(1, Ordering::Relaxed));
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
            if handle.is_null() { return Err(CoreError::Internal(format!("create HEV stop event: {}", std::io::Error::last_os_error()))); }
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS { unsafe { CloseHandle(handle); } continue; }
            return Ok(Self { handle: handle as usize, name });
        }
        Err(CoreError::Internal("cannot create a unique HEV stop event".into()))
    }
    fn signal(&self) {
        if unsafe { SetEvent(self.handle as HANDLE) } == 0 {
            log::warn!("cannot signal HEV shutdown: {}", std::io::Error::last_os_error());
        }
    }
}
impl Drop for StopEvent { fn drop(&mut self) { unsafe { CloseHandle(self.handle as HANDLE); } } }

struct Active {
    child: Child,
    event: StopEvent,
    output: Option<JoinHandle<()>>,
    network: Option<TunGuard>,
    stats: Arc<Mutex<HevStats>>,
    _psiphon: Option<socks5p::Adapter>,
    _tor: Option<socks5t::Adapter>,
}

impl Active {
    fn check(&mut self) -> Result<()> {
        match self.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(CoreError::Internal(format!("HEV helper exited: {status}"))),
            Err(e) => Err(CoreError::Internal(format!("cannot query HEV helper: {e}"))),
        }
    }

    fn stop(&mut self, timeout: Duration) {
        drop(self.network.take());
        self.event.signal();
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => {
                    if let Err(error) = self.child.kill() { log::warn!("cannot terminate HEV helper: {error}"); }
                    if let Err(error) = self.child.wait() { log::warn!("cannot reap HEV helper: {error}"); }
                    break;
                }
            }
        }
        if let Some(output) = self.output.take() { let _ = output.join(); }
    }
}
impl Drop for Active { fn drop(&mut self) { self.stop(Duration::ZERO); } }

pub struct HevSocks5TunnelBridge {
    active: Mutex<Option<Active>>,
    external_fd: AtomicI32,
}

impl Default for HevSocks5TunnelBridge { fn default() -> Self { Self::new() } }

impl HevSocks5TunnelBridge {
    pub fn new() -> Self { Self { active: Mutex::new(None), external_fd: AtomicI32::new(-1) } }
    pub fn set_android_fd(&self, fd: i32) { self.external_fd.store(fd, Ordering::SeqCst); }
    pub fn clear_android_fd(&self) { self.external_fd.store(-1, Ordering::SeqCst); }
    pub fn android_fd(&self) -> Option<i32> { let fd = self.external_fd.load(Ordering::SeqCst); (fd >= 0).then_some(fd) }
    pub fn stats(&self) -> Option<HevStats> {
        let mut slot = self.active.lock();
        let active = slot.as_mut()?;
        active.check().ok()?;
        Some(*active.stats.lock())
    }
}

fn read_output(output: impl std::io::Read, stats: Arc<Mutex<HevStats>>) {
    for line in BufReader::new(output).lines() {
        let Ok(line) = line else { break; };
        if let Some(sample) = parse_stats(&line) {
            *stats.lock() = sample;
        } else if !line.is_empty() {
            log::info!("[hev] {line}");
        }
    }
}

fn parse_stats(line: &str) -> Option<HevStats> {
    let mut fields = line.strip_prefix("FCAE_HEV_STATS ")?.split_whitespace();
    let stats = HevStats {
        tx_packets: fields.next()?.parse().ok()?,
        tx_bytes: fields.next()?.parse().ok()?,
        rx_packets: fields.next()?.parse().ok()?,
        rx_bytes: fields.next()?.parse().ok()?,
    };
    fields.next().is_none().then_some(stats)
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        fcae_runtime::windows_tun::validate_backend(cfg, endpoints.peer_ip.as_deref())?;
        let socks = endpoints.socks.ok_or_else(|| CoreError::InvalidConfig("HEV requires a SOCKS endpoint".into()))?;
        let mut slot = self.active.lock();
        if let Some(active) = slot.as_mut() {
            if active.check().is_ok() { return Err(CoreError::AlreadyRunning); }
        }
        drop(slot.take());
        let files = files()?;
        let psiphon = if endpoints.psiphon_dns { Some(socks5p::Adapter::start(socks).map_err(|e| CoreError::Internal(format!("HEV DNS adapter: {e}")))?) } else { None };
        let tor = if psiphon.is_none() && cfg.tor.is_exit() { Some(socks5t::Adapter::start(socks).map_err(|e| CoreError::Internal(format!("HEV Tor adapter: {e}")))?) } else { None };
        let socks = psiphon.as_ref().map(|a| a.endpoint()).or_else(|| tor.as_ref().map(|a| a.endpoint())).unwrap_or(socks);
        let (_, yaml) = crate::generate_config(cfg, socks)?;
        let event = StopEvent::new()?;
        let child = Command::new(files.directory().join(HOST))
            .arg(&event.name).current_dir(files.directory())
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().map_err(|e| CoreError::Internal(format!("cannot start HEV helper: {e}")))?;
        let stats = Arc::new(Mutex::new(HevStats::default()));
        let mut active = Active { child, event, output: None, network: None, stats: stats.clone(), _psiphon: psiphon, _tor: tor };
        let output = active.child.stdout.take().ok_or_else(|| CoreError::Internal("HEV stdout pipe missing".into()))?;
        active.output = Some(std::thread::Builder::new().name("hev-output".into()).spawn(move || read_output(output, stats))
            .map_err(|e| CoreError::Internal(format!("cannot monitor HEV output: {e}")))?);
        let mut input = active.child.stdin.take().ok_or_else(|| CoreError::Internal("HEV stdin pipe missing".into()))?;
        input.write_all(yaml.as_bytes()).map_err(|e| CoreError::Internal(format!("cannot configure HEV helper: {e}")))?;
        drop(input);
        match TunGuard::configure(cfg, endpoints.peer_ip.as_deref()) {
            Ok(network) => active.network = Some(network),
            Err(error) => { active.check()?; return Err(error); }
        }
        active.check()?;
        *slot = Some(active);
        Ok(())
    }

    fn stop(&self, timeout: Duration) {
        let mut slot = self.active.lock();
        if let Some(mut active) = slot.take() { active.stop(timeout); }
        self.clear_android_fd();
    }

    fn abort(&self) { self.stop(Duration::ZERO); }

    fn is_running(&self) -> bool {
        self.active.lock().as_mut().is_some_and(|active| active.check().is_ok())
    }

    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        let mut slot = self.active.lock();
        let active = slot.as_mut().ok_or_else(|| CoreError::Internal("HEV helper is not running".into()))?;
        active.check()?;
        active.network.as_ref().ok_or_else(|| CoreError::Internal("HEV routing is not configured".into()))?.check_health()
    }

    fn preauthorised_fd(&self) -> Option<i32> { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stats_protocol_rejects_partial_or_foreign_output() {
        assert!(parse_stats("FCAE_HEV_STATS 1 2 3").is_none());
        assert!(parse_stats("FCAE_HEV_STATS 1 2 3 4 extra").is_none());
        assert!(parse_stats("untrusted log 1 2 3 4").is_none());
        assert_eq!(parse_stats("FCAE_HEV_STATS 1 2 3 4").unwrap().rx_bytes, 4);
    }
}
