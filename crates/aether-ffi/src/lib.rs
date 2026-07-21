use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);

static mut LOG_CB: Option<unsafe extern "C" fn(i32, *const c_char, *mut std::ffi::c_void)> = None;
static mut LOG_USER_DATA: *mut std::ffi::c_void = std::ptr::null_mut();

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

use std::ffi::c_void;

#[repr(C)]
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

// ── Helpers ──────────────────────────────────────────────────────────────

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

// ── FFI exports ──────────────────────────────────────────────────────────

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
    unsafe { log_msg(4, "[ffi] aether_init completed"); }
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
        t.state = 1; // Provisioning
        t.mode = cfg.mode as u32;
        t.lan_enabled = cfg.lan_sharing;
        t.status_message = "Provisioning...".to_string();
        t.last_error.clear();
        t.connected_peer.clear();
        t.rtt_ms = 0;
        t.rx_bytes_sec = 0;
        t.tx_bytes_sec = 0;
    }

    unsafe { log_msg(4, "[ffi] aether_start called"); }

    // ── Map config into environment variables (aether CLI convention) ────
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
        if config.is_null() || (*config).noize_profile.is_null() {
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
    }

    if cfg.frag_enabled {
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

    // ── Also accept quick-reconnect from config ──────────────────────────
    if cfg.quick_reconnect {
        std::env::set_var("AETHER_QUICK_RECONNECT", "1");
    } else {
        std::env::set_var("AETHER_QUICK_RECONNECT", "0");
    }

    // ── Accept forced peer from config ───────────────────────────────────
    unsafe {
        if !(*config).force_peer.is_null() {
            if let Ok(p) = CStr::from_ptr((*config).force_peer).to_str() {
                if !p.is_empty() {
                    std::env::set_var("AETHER_PEER", p);
                }
            }
        }
    }

    // ── Accept config path from config ───────────────────────────────────
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

    // ── Launch the async engine on a dedicated tokio runtime ──────────────
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aether-ffi")
        .build();

    let rt = match rt {
        Ok(r) => r,
        Err(e) => {
            {
                let mut t = TELEMETRY.lock();
                t.state = 5; // Error
                t.last_error = format!("Failed to build tokio runtime: {e}");
                t.status_message = "Error".to_string();
            }
            unsafe { log_msg(1, &format!("[ffi] runtime build failed: {e}")); }
            RUNNING.store(false, Ordering::SeqCst);
            return false;
        }
    };

    std::thread::Builder::new()
        .name("aether-engine".to_string())
        .spawn(move || {
            rt.block_on(async move {
                if let Err(e) = aether_core_run().await {
                    unsafe { log_msg(1, &format!("[ffi] engine error: {e}")); }
                    let mut t = TELEMETRY.lock();
                    t.state = 5;
                    t.last_error = format!("{e}");
                    t.status_message = "Error".to_string();
                }
            });
            RUNNING.store(false, Ordering::SeqCst);
            unsafe { log_msg(4, "[ffi] engine thread exiting"); }
        });

    true
}

// ── Core tunnel orchestration (sets env vars, then delegates to aether) ──
//
// This function bridges the FFI layer to the existing aether binary logic.
// Because `aether` is a binary crate (not a library), we re-create its core
// orchestration here using only the public types we can import, and invoke
// the engine via environment-variable-driven initialization.
//
// The actual tunnel work is done by calling into `aether::main()` after
// setting the right environment variables. We run it on a fresh tokio
// runtime and communicate state via the TELEMETRY mutex.

async fn aether_core_run() -> anyhow::Result<()> {
    {
        let mut t = TELEMETRY.lock();
        t.state = 2; // Scanning
        t.status_message = "Scanning gateways...".to_string();
    }
    unsafe { log_msg(3, "[ffi] entering aether_core_run"); }

    // The aether binary crate reads env vars at startup. Since we already
    // set all AETHER_* vars in aether_start(), calling main() will use
    // our config. However, aether::main() calls process::exit() and
    // reads CLI args which would fail here.
    //
    // Instead, we use the approach of spawning the aether binary as a
    // subprocess with all our env vars pre-set. This is the cleanest
    // boundary between the FFI GUI and the CLI engine.

    let aether_bin = std::env::var("AETHER_BIN_PATH")
        .unwrap_or_else(|_| {
            // Default: look next to this library
            let mut p = std::env::current_exe()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            p.pop();
            if cfg!(target_os = "windows") {
                p.push("aether.exe");
            } else {
                p.push("aether");
            }
            p.to_string_lossy().to_string()
        });

    unsafe { log_msg(3, &format!("[ffi] launching aether engine: {aether_bin}")); }

    let mut cmd = tokio::process::Command::new(&aether_bin);
    cmd.env_clear();
    // Forward all AETHER_* env vars we set
    for (key, val) in std::env::vars() {
        if key.starts_with("AETHER_") || key.starts_with("RUST_LOG") {
            cmd.env(&key, &val);
        }
    }
    // Always set verbose for GUI logging
    cmd.env("AETHER_VERBOSE", "1");

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn aether binary at {aether_bin}: {e}"))?;

    // Mark connected once spawned
    {
        let mut t = TELEMETRY.lock();
        t.state = 4; // Connected
        t.status_message = "Connected".to_string();
        t.connected_peer = std::env::var("AETHER_PEER").unwrap_or_default();
    }

    // Read stderr/stdout for log lines and telemetry
    let stderr = child.stderr.take();
    let stdout = child.stdout.take();

    let stderr_task = tokio::spawn(async move {
        if let Some(reader) = stderr {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                unsafe { log_msg(3, &line); }

                // Parse log lines for telemetry updates
                let line_lower = line.to_lowercase();
                {
                    let mut t = TELEMETRY.lock();
                    if line_lower.contains("socks5") && line_lower.contains("listening") {
                        t.state = 4;
                        t.status_message = "Connected — SOCKS5 active".to_string();
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
                unsafe { log_msg(4, &line); }
            }
        }
    });

    // Wait for the child process
    let status = child.wait().await;

    stderr_task.abort();
    stdout_task.abort();

    match status {
        Ok(s) if s.success() => {
            unsafe { log_msg(3, "[ffi] aether engine exited cleanly"); }
            let mut t = TELEMETRY.lock();
            t.state = 0;
            t.status_message = "Disconnected".to_string();
            Ok(())
        }
        Ok(s) => {
            let msg = format!("aether engine exited with status: {s}");
            unsafe { log_msg(1, &msg); }
            Err(anyhow::anyhow!(msg))
        }
        Err(e) => {
            let msg = format!("aether engine process error: {e}");
            unsafe { log_msg(1, &msg); }
            Err(anyhow::anyhow!(msg))
        }
    }
}

#[no_mangle]
pub extern "C" fn aether_stop() {
    if !RUNNING.load(Ordering::SeqCst) {
        return;
    }
    SHUTDOWN.store(true, Ordering::SeqCst);
    unsafe { log_msg(4, "[ffi] aether_stop called"); }

    // Send SIGTERM to child processes if any (the engine thread will handle cleanup)
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
    unsafe { log_msg(4, &format!("[ffi] aether_set_android_tun_fd(fd={tun_fd})")); }
    // Pass to the running engine via env var (the engine will pick it up)
    std::env::set_var("AETHER_TUN_FD", tun_fd.to_string());
}

#[no_mangle]
pub extern "C" fn aether_free() {
    SHUTDOWN.store(true, Ordering::SeqCst);
    RUNNING.store(false, Ordering::SeqCst);
    INITIALIZED.store(false, Ordering::SeqCst);
    unsafe {
        LOG_CB = None;
        LOG_USER_DATA = std::ptr::null_mut();
    }
    unsafe { log_msg(4, "[ffi] aether_free completed"); }
}
