use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

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
    pub h2_enabled: bool,
    pub ech_enabled: bool,
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

struct GuiLogger;

impl log::Log for GuiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            log::Level::Error => 1,
            log::Level::Warn => 2,
            log::Level::Info => 3,
            log::Level::Debug | log::Level::Trace => 4,
        };
        let msg = format!("{}", record.args());
        unsafe {
            log_msg(level, &msg);
        }

        // Lightweight telemetry hooks from engine log lines
        let line_lower = msg.to_lowercase();
        let mut t = TELEMETRY.lock();
        if line_lower.contains("socks5") && line_lower.contains("listen") {
            t.state = 4;
            t.status_message = "Connected — SOCKS5 active".to_string();
        }
        if line_lower.contains("http proxy listening") {
            t.state = 4;
            if !t.status_message.contains("HTTP") {
                t.status_message = "Connected — SOCKS5 + HTTP proxy".to_string();
            }
        }
        // Capture scan RTT from engine logs: "rtt=12.3ms" or "rtt 12ms" / Duration Debug
        if let Some(ms) = parse_rtt_ms_from_log(&msg) {
            if ms > 0 {
                t.rtt_ms = ms;
                aether_engine::set_rtt_ms(ms as u64);
            }
        }
        if line_lower.contains("identity ready") || line_lower.contains("using cloudflare edge") {
            if t.state < 4 {
                t.state = 3;
                t.status_message = "Connecting...".to_string();
            }
        }
        if line_lower.contains("scanning") || line_lower.contains("probe") {
            if t.state < 3 {
                t.state = 2;
                t.status_message = "Scanning gateways...".to_string();
            }
        }
        if let Some(idx) = msg.find("gateway ") {
            let rest = &msg[idx + 8..];
            if let Some(end) = rest.find(|c: char| c.is_whitespace() || c == ',') {
                t.connected_peer = rest[..end].to_string();
            }
        }
        if let Some(idx) = msg.find("edge ") {
            let rest = &msg[idx + 5..];
            let peer: String = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == '(' || c == ')')
                .to_string();
            if !peer.is_empty() {
                t.connected_peer = peer;
            }
        }
    }

    fn flush(&self) {}
}

static GUI_LOGGER: GuiLogger = GuiLogger;

fn parse_rtt_ms_from_log(msg: &str) -> Option<u32> {
    // Matches: rtt=1.234s, rtt=45ms, rtt=450µs, rtt 12.3ms, (rtt 12ms)
    let lower = msg.to_lowercase();
    let idx = lower.find("rtt")?;
    let rest = &lower[idx + 3..];
    let rest = rest.trim_start_matches(|c: char| c == '=' || c == ':' || c.is_whitespace() || c == '(');
    // Duration Debug formats like "12.345ms" or "1.2s"
    let mut num = String::new();
    let mut unit = String::new();
    let mut seen_dot = false;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            if unit.is_empty() {
                num.push(c);
            } else {
                break;
            }
        } else if c == '.' && !seen_dot && unit.is_empty() {
            seen_dot = true;
            num.push(c);
        } else if c.is_alphabetic() || c == 'µ' || c == 'μ' {
            unit.push(c);
        } else if !unit.is_empty() {
            break;
        } else if !num.is_empty() {
            break;
        }
    }
    if num.is_empty() {
        return None;
    }
    let v: f64 = num.parse().ok()?;
    let ms = match unit.as_str() {
        "s" | "sec" | "secs" => v * 1000.0,
        "ms" | "msec" => v,
        "us" | "µs" | "μs" | "micros" => v / 1000.0,
        "ns" => v / 1_000_000.0,
        _ => v, // bare number → assume ms
    };
    Some(ms.round().max(1.0) as u32)
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

fn apply_config_env(cfg: &AetherCfgRaw) {
    std::env::set_var("AETHER_PROTOCOL", protocol_to_env(cfg.protocol));
    std::env::set_var("AETHER_SCAN", scan_mode_to_env(cfg.scan_mode));
    std::env::set_var("AETHER_IP", ip_version_to_env(cfg.ip_version));

    let socks_addr = if cfg.lan_sharing {
        format!("0.0.0.0:{}", cfg.socks_port)
    } else {
        format!("127.0.0.1:{}", cfg.socks_port)
    };
    std::env::set_var("AETHER_SOCKS", &socks_addr);

    // HTTP CONNECT proxy (GUI default 1820)
    if cfg.http_port != 0 && cfg.http_port != cfg.socks_port {
        let http_addr = if cfg.lan_sharing {
            format!("0.0.0.0:{}", cfg.http_port)
        } else {
            format!("127.0.0.1:{}", cfg.http_port)
        };
        std::env::set_var("AETHER_HTTP", &http_addr);
        std::env::set_var("AETHER_HTTP_PORT", cfg.http_port.to_string());
    } else {
        std::env::remove_var("AETHER_HTTP");
        std::env::remove_var("AETHER_HTTP_PORT");
    }

    let noize = unsafe {
        if cfg.noize_profile.is_null() {
            "balanced"
        } else {
            CStr::from_ptr(cfg.noize_profile)
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
    } else {
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
    }

    unsafe {
        if !cfg.force_peer.is_null() {
            if let Ok(p) = CStr::from_ptr(cfg.force_peer).to_str() {
                if !p.is_empty() {
                    std::env::set_var("AETHER_PEER", p);
                } else {
                    std::env::remove_var("AETHER_PEER");
                }
            }
        } else {
            std::env::remove_var("AETHER_PEER");
        }
    }

    let config_path = unsafe {
        if !cfg.config_path.is_null() {
            CStr::from_ptr(cfg.config_path)
                .to_str()
                .unwrap_or("aether.toml")
        } else {
            "aether.toml"
        }
    };
    std::env::set_var("AETHER_CONFIG", config_path);
    std::env::set_var("AETHER_VERBOSE", "1");
    // GUI never prompts on stdin
    std::env::set_var("AETHER_NONINTERACTIVE", "1");

    if cfg.h2_enabled {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    } else {
        std::env::remove_var("AETHER_MASQUE_HTTP2");
    }

    if cfg.ech_enabled {
        // "auto" is accepted by resolve_ech() in the engine
        std::env::set_var("AETHER_ECH", "auto");
    } else {
        std::env::remove_var("AETHER_ECH");
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

    // Install a logger that forwards into the GUI. Ignore if already set.
    let _ = log::set_logger(&GUI_LOGGER).map(|()| log::set_max_level(log::LevelFilter::Debug));

    {
        let mut t = TELEMETRY.lock();
        t.state = 0;
        t.status_message = "Disconnected".to_string();
        t.lan_ip = detect_lan_ip();
    }

    INITIALIZED.store(true, Ordering::SeqCst);
    unsafe {
        log_msg(4, "[ffi] aether_init completed (in-process engine)");
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

    apply_config_env(&cfg);
    aether_engine::reset_stats();
    unsafe {
        log_msg(4, "[ffi] aether_start — launching in-process engine");
    }

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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();

    let _ = std::thread::Builder::new()
        .name("aether-engine".to_string())
        .spawn(move || {
            // Watch SHUTDOWN from aether_stop and abort the runtime.
            let watch = std::thread::spawn({
                let shutdown_flag = shutdown_flag.clone();
                move || {
                    while !SHUTDOWN.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    shutdown_flag.store(true, Ordering::SeqCst);
                }
            });

            {
                let mut t = TELEMETRY.lock();
                t.state = 2;
                t.status_message = "Scanning gateways...".to_string();
            }

            let result = rt.block_on(async {
                // Race engine against shutdown flag
                let engine = aether_engine::run_from_env();
                tokio::pin!(engine);
                loop {
                    if SHUTDOWN.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    tokio::select! {
                        biased;
                        r = &mut engine => return r.map_err(|e| anyhow::anyhow!("{e:#}")),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                            if SHUTDOWN.load(Ordering::SeqCst) {
                                return Ok(());
                            }
                        }
                    }
                }
            });

            SHUTDOWN.store(true, Ordering::SeqCst);
            let _ = watch.join();

            match result {
                Ok(()) => {
                    let mut t = TELEMETRY.lock();
                    if !matches!(t.state, 5) {
                        t.state = 0;
                        t.status_message = "Disconnected".to_string();
                    }
                    unsafe {
                        log_msg(3, "[ffi] engine finished");
                    }
                }
                Err(e) => {
                    unsafe {
                        log_msg(1, &format!("[ffi] engine error: {e:#}"));
                    }
                    let mut t = TELEMETRY.lock();
                    t.state = 5;
                    t.last_error = format!("{e:#}");
                    t.status_message = "Error".to_string();
                }
            }

            RUNNING.store(false, Ordering::SeqCst);
            unsafe {
                log_msg(4, "[ffi] engine thread exiting");
            }
        });

    true
}

#[no_mangle]
pub extern "C" fn aether_stop() {
    if !RUNNING.load(Ordering::SeqCst) {
        // still clear telemetry
    }
    SHUTDOWN.store(true, Ordering::SeqCst);
    unsafe {
        log_msg(4, "[ffi] aether_stop called");
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

    // Refresh live traffic counters from the engine
    let (rx_bps, tx_bps) = aether_engine::rates();
    let total_rx = aether_engine::total_rx();
    let total_tx = aether_engine::total_tx();
    let rtt = aether_engine::rtt_ms() as u32;

    let mut t = TELEMETRY.lock();
    t.rx_bytes_sec = rx_bps;
    t.tx_bytes_sec = tx_bps;
    t.total_rx = total_rx;
    t.total_tx = total_tx;
    if rtt > 0 {
        t.rtt_ms = rtt;
    }

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
    RUNNING.store(false, Ordering::SeqCst);
    INITIALIZED.store(false, Ordering::SeqCst);
    unsafe {
        LOG_CB = None;
        LOG_USER_DATA = std::ptr::null_mut();
        log_msg(4, "[ffi] aether_free completed");
    }
}
