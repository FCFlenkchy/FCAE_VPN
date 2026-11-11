use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, SetInformationJobObject};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use crate::backend::Endpoints;
use crate::config::SessionConfig;
use crate::error::{CoreError, Result};
use crate::socks5p;
use crate::windows_dll::EmbeddedFiles;
use crate::windows_tun::TunGuard;

struct ConfigFile { path: PathBuf, file: Option<File> }
impl ConfigFile {
    fn new(label: &str, text: &str) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join("FCAE_VPN").join("sessions");
        std::fs::create_dir_all(&dir).map_err(|e| CoreError::Internal(format!("cannot create sidecar config directory: {e}")))?;
        for _ in 0..100 {
            let path = dir.join(format!("{}-{}-{}.conf", label, std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let file = OpenOptions::new().write(true).create_new(true).share_mode(FILE_SHARE_READ).open(&path);
            match file {
                Ok(mut file) => {
                    let result = file.write_all(text.as_bytes()).and_then(|_| file.flush());
                    if let Err(e) = result { drop(file); let _ = std::fs::remove_file(&path); return Err(CoreError::Internal(format!("cannot write sidecar config: {e}"))); }
                    return Ok(Self { path, file: Some(file) });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(CoreError::Internal(format!("cannot create sidecar config: {e}"))),
            }
        }
        Err(CoreError::Internal("cannot allocate sidecar config name".into()))
    }
}
impl Drop for ConfigFile {
    fn drop(&mut self) { drop(self.file.take()); let _ = std::fs::remove_file(&self.path); }
}

struct Job(HANDLE);
unsafe impl Send for Job {}
impl Job {
    fn attach(child: &mut Child) -> Result<Self> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() { return Err(CoreError::Internal(format!("cannot create sidecar job: {}", std::io::Error::last_os_error()))); }
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(h, JobObjectExtendedLimitInformation, (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of_val(&info) as u32) != 0
                && AssignProcessToJobObject(h, child.as_raw_handle() as HANDLE) != 0;
            if !ok { let error = std::io::Error::last_os_error(); CloseHandle(h); return Err(CoreError::Internal(format!("cannot supervise sidecar process: {error}"))); }
            Ok(Self(h))
        }
    }
}
impl Drop for Job { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }

struct Active {
    child: Child,
    _job: Job,
    _files: EmbeddedFiles,
    _config: ConfigFile,
    _psiphon: Option<socks5p::Adapter>,
    network: Option<TunGuard>,
}
impl Drop for Active {
    fn drop(&mut self) {
        drop(self.network.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Sidecar {
    label: &'static str,
    executable: &'static str,
    assets: &'static [(&'static str, &'static [u8])],
    lifecycle: Mutex<()>,
    active: Mutex<Option<Active>>,
    closing: AtomicBool,
    fd: AtomicI32,
}

impl Sidecar {
    pub fn new(label: &'static str, executable: &'static str, assets: &'static [(&'static str, &'static [u8])]) -> Self {
        Self { label, executable, assets, lifecycle: Mutex::new(()), active: Mutex::new(None), closing: AtomicBool::new(false), fd: AtomicI32::new(-1) }
    }
    pub fn set_fd(&self, fd: i32) { self.fd.store(fd, Ordering::SeqCst); }
    pub fn fd(&self) -> Option<i32> { let fd = self.fd.load(Ordering::SeqCst); (fd >= 0).then_some(fd) }

    pub fn launch(&self, cfg: &SessionConfig, endpoints: &Endpoints, render: impl FnOnce(&SessionConfig, std::net::SocketAddr, bool) -> Result<String>, args: &[&str]) -> Result<()> {
        crate::windows_tun::validate_backend(cfg, endpoints.peer_ip.as_deref())?;
        let _lifecycle = self.lifecycle.lock();
        if self.active.lock().is_some() { return Err(CoreError::Internal(format!("{} sidecar is already active", self.label))); }
        self.closing.store(false, Ordering::SeqCst);
        let base = endpoints.socks.ok_or_else(|| CoreError::Internal("TUN needs SOCKS endpoint".into()))?;
        let psiphon = if endpoints.psiphon_dns {
            let resolvers = crate::tun_dns::psiphon_resolvers(cfg)?;
            Some(socks5p::Adapter::start(self.label, base, resolvers).map_err(|e| CoreError::Internal(format!("{} socks5p: {e}", self.label)))?)
        } else { None };
        let socks = psiphon.as_ref().map(|p| p.endpoint()).unwrap_or(base);
        let config = ConfigFile::new(self.label, &render(cfg, socks, endpoints.udp || psiphon.is_some())?)?;
        let files = EmbeddedFiles::stage(self.label, self.assets)?;
        if self.closing.load(Ordering::SeqCst) { return Err(CoreError::Internal("TUN start cancelled".into())); }
        let mut command = Command::new(files.directory().join(self.executable));
        command.current_dir(files.directory()).args(args).arg(&config.path)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().map_err(|e| CoreError::Internal(format!("cannot start {} sidecar: {e}", self.label)))?;
        let job = match Job::attach(&mut child) {
            Ok(job) => job,
            Err(error) => { let _ = child.kill(); let _ = child.wait(); return Err(error); }
        };
        for stream in [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)].into_iter().flatten() {
            let label = self.label;
            std::thread::spawn(move || for line in BufReader::new(stream).lines().map_while(std::result::Result::ok) {
                if line.contains("[err]") || line.contains("[E]") || line.contains("panic:") {
                    log::error!("[{label}] {line}");
                } else if line.contains("[warn]") || line.contains("[W]") {
                    log::warn!("[{label}] {line}");
                } else if line.contains("[debug]") || line.contains("[D]") {
                    log::debug!("[{label}] {line}");
                } else {
                    log::info!("[{label}] {line}");
                }
            });
        }
        *self.active.lock() = Some(Active { child, _job: job, _files: files, _config: config, _psiphon: psiphon, network: None });
        let configured = (|| -> Result<()> {
            if self.closing.load(Ordering::SeqCst) { return Err(CoreError::Internal("TUN start cancelled".into())); }
            let guard = TunGuard::configure(cfg, endpoints.peer_ip.as_deref())?;
            let mut active = self.active.lock();
            let a = active.as_mut().ok_or_else(|| CoreError::Internal("TUN start cancelled".into()))?;
            if let Some(status) = a.child.try_wait().map_err(|e| CoreError::Internal(format!("cannot inspect {} sidecar: {e}", self.label)))? {
                return Err(CoreError::Internal(format!("{} sidecar exited during startup: {status}", self.label)));
            }
            if self.closing.load(Ordering::SeqCst) { return Err(CoreError::Internal("TUN start cancelled".into())); }
            a.network = Some(guard);
            Ok(())
        })();
        if configured.is_err() { drop(self.active.lock().take()); }
        configured
    }
    pub fn abort(&self) {
        self.closing.store(true, Ordering::SeqCst);
        if let Some(mut active) = self.active.try_lock() { if let Some(a) = active.as_mut() { let _ = a.child.kill(); } }
        self.set_fd(-1);
    }
    pub fn stop(&self, _timeout: Duration) {
        self.closing.store(true, Ordering::SeqCst);
        let _lifecycle = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);
        drop(self.active.lock().take());
        self.set_fd(-1);
    }
    pub fn is_running(&self) -> bool {
        if self.closing.load(Ordering::SeqCst) { return false; }
        self.active.lock().as_mut().is_some_and(|a| matches!(a.child.try_wait(), Ok(None)))
    }
    pub fn check_health(&self) -> Result<()> {
        let mut active = self.active.lock();
        let a = active.as_mut().ok_or_else(|| CoreError::Internal(format!("{} sidecar stopped", self.label)))?;
        match a.child.try_wait() {
            Ok(None) => (),
            Ok(Some(status)) => return Err(CoreError::Internal(format!("{} sidecar exited: {status}", self.label))),
            Err(e) => return Err(CoreError::Internal(format!("cannot inspect {} sidecar: {e}", self.label))),
        }
        if let Some(guard) = &a.network { guard.check_health()?; }
        Ok(())
    }
}
