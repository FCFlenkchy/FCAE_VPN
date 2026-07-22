use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::process::Child;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

static mut LOG_CB: Option<unsafe extern "C" fn(i32, *const c_char, *mut std::ffi::c_void)> = None;
static mut LOG_USER_DATA: *mut std::ffi::c_void = std::ptr::null_mut();

struct TelemetryState {
    state: u32,
    mode: u32,
    lan_enabled: bool,
    rtt_ms: u32,
    rx_bytes_sec: u64,
    tx_bytes_sec: u64,
    total_rx: u64,
    total_tx: u64,
    connected_peer: String,
    lan_ip: String,
    status_message: String,
    last_error: String,
}

impl TelemetryState {
    const fn new() -> Self {
        Self {
            state: 0,
            mode: 0,
            lan_enabled: false,
            rtt_ms: 0,
            rx_bytes_sec: 0,
            tx_bytes_sec: 0,
            total_rx: 0,
            total_tx: 0,
            connected_peer: String::new(),
            lan_ip: String::new(),
            status_message: String::new(),
            last_error: String::new(),
        }
    }
}

static TELEMETRY: Mutex<TelemetryState> = Mutex::new(TelemetryState::new());
static CHILD: Mutex<Option<Child>> = Mutex::new(None);

use std::ffi::c_void;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AetherCfgRaw {
    pub protocol: i32,
    pub mode: i32,
    pub lan_sharing: bool,
    pub scan_mode: i32,
    pub ip_version: i32,
    pub quick_reconnect: bool,
    pub noize_profile: *const c_char,
    pub fragment_enabled: bool,
    pub frag_min_size: u32,
    pub frag_max_size: u32,
    pub frag_min_delay: u32,
    pub frag_max_delay: u32,
    pub socks_port: u16,
    pub http_port: u16,
    pub force_peer: *const c_char,
    pub config_path: *const c_char,
}

#[repr(C)]
pub struct AetherTelemetryOut {
    pub state: u32,
    pub mode: u32,
    pub lan_enabled: bool,
    pub rtt_ms: u32,
    pub rx_bytes_sec: u64,
    pub tx_bytes_sec: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub connected_peer: [u8; 64],
    pub lan_ip: [u8; 64],
    pub status_message: [u8; 128],
    pub last_error: [u8; 256],
}

unsafe fn log_msg(level: i32, msg: &str) {
    if let Some(cb) = LOG_CB {
        if let Ok(c) = CString::new(msg) {
            cb(level, c.as_ptr(), LOG_USER_DATA);
        }
    }
}

fn copy_str_to_buf(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf[len] = 0;
}

fn detect_lan_ip() -> String {
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("1.1.1.1:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn protocol_to_env(p: i32) -> &'static str {
    match p {
        0 => "masque",
        1 => "wg",
        2 => "gool",
        _ => "masque",
    }
}

fn scan_mode_to_env(s: i32) -> &'static str {
    match s {
        0 => "turbo",
        1 => "balanced",
        2 => "thorough",
        3 => "stealth",
        4 => "ironclad",
        _ => "balanced",
    }
}

fn ip_version_to_env(v: i32) -> &'static str {
    match v {
        4 => "v4",
        6 => "v6",
        10 => "both",
        _ => "v4",
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn is_runnable(path: &Path) -> bool {
    path.is_file()
}

/// Locate the bundled aether engine binary next to the GUI (or Android native lib dir).
fn resolve_aether_bin() -> PathBuf {
    if let Ok(p) = std::env::var("AETHER_BIN_PATH") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return pb;
        }
    }

    let dir = exe_dir();
    let mut candidates: Vec<PathBuf> = Vec::new();

    if cfg!(target_os = "windows") {
        candidates.push(dir.join("aether.exe"));
        candidates.push(dir.join("aether"));
        candidates.push(dir.join("libaether.exe"));
    } else if cfg!(target_os = "android") {
        // Packaged as libaether.so in jniLibs → extracted under nativeLibraryDir
        candidates.push(dir.join("libaether.so"));
        candidates.push(dir.join("aether"));
        if let Ok(nd) = std::env::var("AETHER_NATIVE_LIB_DIR") {
            candidates.push(PathBuf::from(&nd).join("libaether.so"));
            candidates.push(PathBuf::from(&nd).join("aether"));
        }
    } else {
        candidates.push(dir.join("aether"));
        candidates.push(dir.join("libaether.so"));
    }

    // Also try cwd (dev builds)
    candidates.push(PathBuf::from(if cfg!(target_os = "windows") {
        "aether.exe"
    } else {
        "aether"
    }));

    for c in &candidates {
        if is_runnable(c) {
            return c.clone();
        }
        // Android may ship libaether.so without +x; still try to exec
        if c.is_file() {
            return c.clone();
        }
    }

    // Default path used in error messages
    if cfg!(target_os = "windows") {
        dir.join("aether.exe")
    } else if cfg!(target_os = "android") {
        dir.join("libaether.so")
    } else {
        dir.join("aether")
    }
}

async fn kill_child() {
    let mut guard = CHILD.lock();
    if let Some(mut child) = guard.take() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

#[no_mangle]
pub extern "C" fn aether_init(
    log_cb: Option<unsafe extern "C" fn(i32, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) {
    unsafe {
        LOG_CB = log_cb;
        LOG_USER_DATA = user_data;
    }

    let default_filter = if std::env::var("AETHER_VERBOSE").is_ok() {
        "info,aether=debug"
    } else {
        "info"
    };
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_filter),
    )
    .format_timestamp_millis()
    .try_init();

    {
        let mut t = TELEMETRY.lock();
        t.state = 0;
        t.status_message = "Disconnected".to_string();
        t.lan_ip = detect_lan_ip();
    }

    INITIALIZED.store(true, Ordering::SeqCst);
    unsafe {
        log_msg(4, "[ffi] aether_init completed");
        let bin = resolve_aether_bin();
        log_msg(
            4,
            &format!(
                "[ffi] engine binary: {} (exists={})",
                bin.display(),
                bin.is_file()
            ),
        );
    }
}

#[no_mangle]
pub extern "C" fn aether_start(config: *const AetherCfgRaw) -> bool {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }
    if RUNNING.load(Ordering::SeqCst) {
        return false;
    }

    let cfg = unsafe {
        if config.is_null() {
            return false;
        }
        *config
    };

    RUNNING.store(true, Ordering::SeqCst);
    SHUTDOWN.store(false, Ordering::SeqCst);

    {
        let mut t = TELEMETRY.lock();
        t.state = 1;
        t.mode = cfg.mode as u32;
        t.lan_enabled = cfg.lan_sharing;
        t.status_message = "Provisioning...".to_string();
        t.last_error.clear();
        t.connected_peer.clear();
        t.rtt_ms = 0;
        t.rx_bytes_sec = 0;
        t.tx_bytes_sec = 0;
    }

    unsafe {
        log_msg(4, "[ffi] aether_start called");
    }

    std::env::set_var("AETHER_PROTOCOL", protocol_to_env(cfg.protocol));
    std::env::set_var("AETHER_SCAN", scan_mode_to_env(cfg.scan_mode));
    std::env::set_var("AETHER_IP", ip_version_to_env(cfg.ip_version));

    let socks_addr = if cfg.lan_sharing {
        format!("0.0.0.0:{}", cfg.socks_port)
    } else {
        format!("127.0.0.1:{}", cfg.socks_port)
    };
    std::env::set_var("AETHER_SOCKS", &socks_addr);

    let noize = unsafe {
        if (*config).noize_profile.is_null() {
            "balanced"
        } else {
            CStr::from_ptr((*config).noize_profile)
                .to_str()
                .unwrap_or("balanced")
        }
    };
    std::env::set_var("AETHER_NOIZE", noize);

    if cfg.quick_reconnect {
        std::env::set_var("AETHER_QUICK_RECONNECT", "1");
    } else {
        std::env::set_var("AETHER_QUICK_RECONNECT", "0");
    }

    if cfg.fragment_enabled {
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        std::env::set_var(
            "AETHER_MASQUE_H2_FRAGMENT_SIZE",
            &format!("{}-{}", cfg.frag_min_size, cfg.frag_max_size),
        );
        std::env::set_var(
            "AETHER_MASQUE_H2_FRAGMENT_DELAY",
            &format!("{}-{}", cfg.frag_min_delay, cfg.frag_max_delay),
        );
    }

    unsafe {
        if !(*config).force_peer.is_null() {
            if let Ok(p) = CStr::from_ptr((*config).force_peer).to_str() {
                if !p.is_empty() {
                    std::env::set_var("AETHER_PEER", p);
                }
            }
        }
    }

    let config_path = unsafe {
        if !(*config).config_path.is_null() {
            CStr::from_ptr((*config).config_path)
                .to_str()
                .unwrap_or("aether.toml")
        } else {
            "aether.toml"
        }
    };
    std::env::set_var("AETHER_CONFIG", config_path);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aether-ffi")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            {
                let mut t = TELEMETRY.lock();
                t.state = 5;
                t.last_error = format!("Failed to build tokio runtime: {e}");
                t.status_message = "Error".to_string();
            }
            unsafe {
                log_msg(1, &format!("[ffi] runtime build failed: {e}"));
            }
            RUNNING.store(false, Ordering::SeqCst);
            return false;
        }
    };

    let _ = std::thread::Builder::new()
        .name("aether-engine".to_string())
        .spawn(move || {
            rt.block_on(async move {
                if let Err(e) = aether_core_run().await {
                    unsafe {
                        log_msg(1, &format!("[ffi] engine error: {e}"));
                    }
                    let mut t = TELEMETRY.lock();
                    t.state = 5;
                    t.last_error = format!("{e}");
                    t.status_message = "Error".to_string();
                }
            });
            RUNNING.store(false, Ordering::SeqCst);
            unsafe {
                log_msg(4, "[ffi] engine thread exiting");
            }
        });

    true
}

async fn aether_core_run() -> anyhow::Result<()> {
    {
        let mut t = TELEMETRY.lock();
        t.state = 2;
        t.status_message = "Scanning gateways...".to_string();
    }
    unsafe {
        log_msg(3, "[ffi] entering aether_core_run");
    }

    let aether_bin = resolve_aether_bin();
    if !aether_bin.is_file() {
        return Err(anyhow::anyhow!(
            "aether engine not found at {}. Reinstall or set AETHER_BIN_PATH.",
            aether_bin.display()
        ));
    }

    unsafe {
        log_msg(
            3,
            &format!("[ffi] launching aether engine: {}", aether_bin.display()),
        );
    }

    let mut cmd = tokio::process::Command::new(&aether_bin);
    // Keep PATH / system env for TLS certs etc., but ensure our AETHER_* win.
    for (key, val) in std::env::vars() {
        if key.starts_with("AETHER_") || key.starts_with("RUST_LOG") {
            cmd.env(&key, &val);
        }
    }
    cmd.env("AETHER_VERBOSE", "1");

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to spawn aether binary at {}: {e}",
                aether_bin.display()
            )
        })?;

    {
        let mut t = TELEMETRY.lock();
        t.state = 3;
        t.status_message = "Connecting...".to_string();
        t.connected_peer = std::env::var("AETHER_PEER").unwrap_or_default();
    }

    let stderr = child.stderr.take();
    let stdout = child.stdout.take();
    *CHILD.lock() = Some(child);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_err = shutdown.clone();
    let shutdown_out = shutdown.clone();

    let stderr_task = tokio::spawn(async move {
        if let Some(reader) = stderr {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if shutdown_err.load(Ordering::SeqCst) {
                    break;
                }
                unsafe {
                    log_msg(3, &line);
                }

                let line_lower = line.to_lowercase();
                {
                    let mut t = TELEMETRY.lock();
                    if line_lower.contains("socks5") && line_lower.contains("listening") {
                        t.state = 4;
                        t.status_message = "Connected — SOCKS5 active".to_string();
                    }
                    if line_lower.contains("connected") || line_lower.contains("tunnel ready") {
                        t.state = 4;
                        t.status_message = "Connected".to_string();
                    }
                    if let Some(idx) = line.find("gateway ") {
                        let rest = &line[idx + 8..];
                        if let Some(end) = rest.find(' ') {
                            t.connected_peer = rest[..end].to_string();
                        }
                    }
                }
            }
        }
    });

    let stdout_task = tokio::spawn(async move {
        if let Some(reader) = stdout {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if shutdown_out.load(Ordering::SeqCst) {
                    break;
                }
                unsafe {
                    log_msg(4, &line);
                }
            }
        }
    });

    // Poll child + SHUTDOWN flag
    let status = loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            shutdown.store(true, Ordering::SeqCst);
            kill_child().await;
            break Ok(None);
        }

        let mut guard = CHILD.lock();
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(Some(s)) => {
                    *guard = None;
                    break Ok(Some(s));
                }
                Ok(None) => {}
                Err(e) => {
                    *guard = None;
                    break Err(e);
                }
            }
        } else {
            break Ok(None);
        }
        drop(guard);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    shutdown.store(true, Ordering::SeqCst);
    stderr_task.abort();
    stdout_task.abort();
    *CHILD.lock() = None;

    match status {
        Ok(None) => {
            unsafe {
                log_msg(3, "[ffi] aether engine stopped");
            }
            let mut t = TELEMETRY.lock();
            t.state = 0;
            t.status_message = "Disconnected".to_string();
            Ok(())
        }
        Ok(Some(s)) if s.success() => {
            unsafe {
                log_msg(3, "[ffi] aether engine exited cleanly");
            }
            let mut t = TELEMETRY.lock();
            t.state = 0;
            t.status_message = "Disconnected".to_string();
            Ok(())
        }
        Ok(Some(s)) => {
            let msg = format!("aether engine exited with status: {s}");
            unsafe {
                log_msg(1, &msg);
            }
            Err(anyhow::anyhow!(msg))
        }
        Err(e) => {
            let msg = format!("aether engine process error: {e}");
            unsafe {
                log_msg(1, &msg);
            }
            Err(anyhow::anyhow!(msg))
        }
    }
}

#[no_mangle]
pub extern "C" fn aether_stop() {
    if !RUNNING.load(Ordering::SeqCst) && CHILD.lock().is_none() {
        return;
    }
    SHUTDOWN.store(true, Ordering::SeqCst);
    unsafe {
        log_msg(4, "[ffi] aether_stop called");
    }

    // Best-effort sync kill (engine thread also watches SHUTDOWN)
    if let Some(mut child) = CHILD.lock().take() {
        let _ = child.start_kill();
    }

    let mut t = TELEMETRY.lock();
    t.state = 0;
    t.status_message = "Disconnected".to_string();
    t.connected_peer.clear();
    t.rtt_ms = 0;
    t.rx_bytes_sec = 0;
    t.tx_bytes_sec = 0;
}

#[no_mangle]
pub extern "C" fn aether_get_telemetry(out: *mut AetherTelemetryOut) {
    if out.is_null() {
        return;
    }

    let t = TELEMETRY.lock();
    unsafe {
        (*out).state = t.state;
        (*out).mode = t.mode;
        (*out).lan_enabled = t.lan_enabled;
        (*out).rtt_ms = t.rtt_ms;
        (*out).rx_bytes_sec = t.rx_bytes_sec;
        (*out).tx_bytes_sec = t.tx_bytes_sec;
        (*out).total_rx = t.total_rx;
        (*out).total_tx = t.total_tx;
        copy_str_to_buf(&mut (*out).connected_peer, &t.connected_peer);
        copy_str_to_buf(&mut (*out).lan_ip, &t.lan_ip);
        copy_str_to_buf(&mut (*out).status_message, &t.status_message);
        copy_str_to_buf(&mut (*out).last_error, &t.last_error);
    }
}

#[no_mangle]
pub extern "C" fn aether_set_android_tun_fd(tun_fd: i32) {
    unsafe {
        log_msg(4, &format!("[ffi] aether_set_android_tun_fd(fd={tun_fd})"));
    }
    std::env::set_var("AETHER_TUN_FD", tun_fd.to_string());
}

#[no_mangle]
pub extern "C" fn aether_free() {
    SHUTDOWN.store(true, Ordering::SeqCst);
    if let Some(mut child) = CHILD.lock().take() {
        let _ = child.start_kill();
    }
    RUNNING.store(false, Ordering::SeqCst);
    INITIALIZED.store(false, Ordering::SeqCst);
    unsafe {
        LOG_CB = None;
        LOG_USER_DATA = std::ptr::null_mut();
        log_msg(4, "[ffi] aether_free completed");
    }
}
