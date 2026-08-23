use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::atomic::AtomicU8;

use parking_lot::Mutex;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// Use AtomicPtr instead of static mut to avoid undefined behavior when
// log_msg() reads from the engine thread while aether_init() writes
// from the main thread.
static mut LOG_CB: Option<unsafe extern "C" fn(i32, *const c_char, *mut std::ffi::c_void)> = None;
static mut LOG_USER_DATA: *mut std::ffi::c_void = std::ptr::null_mut();

// Ensure aether_init() is called exactly once even from multiple threads.
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

// Serializes concurrent aether_start() calls (the JNI layer can invoke
// start from a different thread than the UI).  STOP_GUARD below only
// protects the short flag-flip + handle-swap critical sections.
static START_LOCK: Mutex<()> = Mutex::new(());

// Guard to prevent concurrent aether_stop() / aether_free() calls.
// On Windows the DISCONNECT button spawns a detached thread that calls
// aether_stop() while ui_shutdown() calls aether_stop()+aether_free()
// from the main thread.  On Android nativeStop/nativeFree can overlap.
static STOP_GUARD: Mutex<()> = Mutex::new(());

// Wakes the engine thread's select! loop the instant shutdown is
// requested, instead of it waking on a 200ms timer for the entire
// lifetime of the connection (previously a real, continuous battery
// drain on Android: a periodic timer wakeup fights Doze/idle CPU
// states for as long as the tunnel stays connected — hours at a time).
// notify_one() stores a permit if called before anyone is waiting, so
// a stop requested a hair before the engine thread reaches `.notified()`
// is never lost.
static SHUTDOWN_NOTIFY: once_cell::sync::Lazy<tokio::sync::Notify> =
    once_cell::sync::Lazy::new(tokio::sync::Notify::new);

// Store the engine thread handle so aether_free() can join it before
// tearing down LOG_CB and other statics.  Without this, the engine
// thread can still be dropping the tokio runtime (cancelling tasks,
// logging) while aether_free() nulls out LOG_CB → crash.
static ENGINE_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

// Windows force-cleanup dedupe state machine: 0 = idle, 1 = running, 2 = done.
//
// The old AtomicBool was check-then-act: aether_stop() (UI thread) and the
// engine thread's post-runtime cleanup could both pass the check before
// either set it, running two full PowerShell cleanups CONCURRENTLY (the
// "runs twice cleanup" symptom: racing DNS restores + adapter removals).
// compare_exchange makes the claim atomic; late callers wait bounded for
// the in-flight run instead of starting a second one.
#[cfg(target_os = "windows")]
static WIN_CLEANUP_STATE: AtomicU8 = AtomicU8::new(0);

/// Synchronously ensure the Windows cleanup (DNS restore, route cleanup,
/// adapter deletion) runs exactly once per session.
///
/// - already done            → return immediately
/// - in progress elsewhere   → wait up to `timeout_secs` for it to finish
/// - nobody started it       → run it (on a helper thread) and wait up to
///                             `timeout_secs` plus a short grace period
///
/// Returns true if the cleanup completed (by this thread or another).
/// The helper thread is detached: if PowerShell hangs we must not hang the
/// UI thread (aether_stop) or process exit (aether_free) with it — the old
/// code joined it forever, which froze the app when PowerShell stalled.
#[cfg(target_os = "windows")]
fn cleanup_windows_sync(name: &str, timeout_secs: u64) -> bool {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // Already done?
    if WIN_CLEANUP_STATE.load(Ordering::SeqCst) == 2 {
        unsafe {
            log_msg(4, "[ffi] cleanup_windows_sync: already done, skipping");
        }
        return true;
    }

    // Try to become the single runner (idle → running).
    if WIN_CLEANUP_STATE
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        unsafe {
            log_msg(4, "[ffi] cleanup_windows_sync: already in progress, waiting");
        }
        return wait_cleanup_done(timeout_secs.max(5));
    }

    let name = name.to_string();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    unsafe {
        log_msg(4, &format!("[ffi] cleanup_windows_sync: starting (timeout={}s)", timeout_secs));
    }

    // Detached by design (see doc comment above): it keeps running and
    // finishes the DNS restore even if we stop waiting for it.
    thread::spawn(move || {
        aether_engine::tun_t2s::force_cleanup_windows(&name);
        completed_clone.store(true, Ordering::SeqCst);
        WIN_CLEANUP_STATE.store(2, Ordering::SeqCst);
    });

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let grace = Duration::from_secs(5); // extra room past the diagnostic timeout
    let mut timed_out_logged = false;

    loop {
        if completed.load(Ordering::SeqCst) {
            unsafe {
                log_msg(4, "[ffi] cleanup_windows_sync: completed successfully");
            }
            return true;
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout && !timed_out_logged {
            timed_out_logged = true;
            unsafe {
                log_msg(2, &format!(
                    "[ffi] cleanup_windows_sync: TIMEOUT after {}s — still waiting (bounded)",
                    timeout_secs
                ));
            }
        }
        if elapsed >= timeout + grace {
            unsafe {
                log_msg(1, &format!(
                    "[ffi] cleanup_windows_sync: NOT finished after {}s — detaching (cleanup continues in background)",
                    elapsed.as_secs()
                ));
            }
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Wait (bounded) for a cleanup started by another thread to finish.
#[cfg(target_os = "windows")]
fn wait_cleanup_done(secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if WIN_CLEANUP_STATE.load(Ordering::SeqCst) == 2 {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    WIN_CLEANUP_STATE.load(Ordering::SeqCst) == 2
}

/// Re-arm the cleanup guard at the start of a new engine session. Without
/// this, the flag stayed true forever after the first disconnect and the
/// NEXT session's disconnect skipped DNS restore entirely.
#[cfg(target_os = "windows")]
fn reset_cleanup_state() {
    WIN_CLEANUP_STATE.store(0, Ordering::SeqCst);
}

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

// ── Version check state ─────────────────────────────────────────────────

struct UpdateState {
    check_in_progress: bool,
    check_done: bool,
    result: Option<aether_engine::version_checker::UpdateCheckResult>,
    status_message: String,
}

impl UpdateState {
    const fn new() -> Self {
        Self {
            check_in_progress: false,
            check_done: false,
            result: None,
            status_message: String::new(),
        }
    }
}

static UPDATE_STATE: Mutex<UpdateState> = Mutex::new(UpdateState::new());

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
    pub dns_server: *const c_char,
    pub dns_mode: i32,
    pub doh_url: *const c_char,
    pub dns_ip_prefer: i32,
    pub tls_groups: *const c_char,
    pub udp_buf_kb: u32,
    pub sni: *const c_char,
    pub sys_profile: i32,   // 0=Auto, 1=Low, 2=Medium, 3=High
    pub routes_file: *const c_char,
    pub routes_inline: *const c_char,
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
        // Drop Trace; keep Debug only when verbose
        metadata.level() <= log::Level::Info
            || (metadata.level() <= log::Level::Debug
                && std::env::var_os("AETHER_VERBOSE").is_some())
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
        // Bound message size to limit GUI memory pressure
        let mut msg = format!("{}", record.args());
        if msg.len() > 200 {
            msg.truncate(200);
            msg.push_str("…");
        }
        unsafe {
            log_msg(level, &msg);
        }

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
        if let Some(ms) = parse_rtt_ms_from_log(&msg) {
            if ms > 0 {
                t.rtt_ms = ms;
                aether_engine::set_rtt_ms(ms as u64);
            }
        }
        // Live data-plane validated — mark CONNECTED.  This fires after
        // validate_live_stack() succeeds, which happens BEFORE local proxies
        // are spawned.  In TUN mode without LAN sharing no proxies are
        // started, so the log-based "socks5 server listening" transition
        // never fires — this is the authoritative CONNECTED signal.
        if line_lower.contains("data-plane ok") {
            if t.state < 4 {
                t.state = 4;
                t.status_message = "Connected".to_string();
            }
        }
        // Tunnel failed / reconnecting — drop back to SCANNING so the UI
        // doesn't stay frozen on "CONNECTING" while the engine retries.
        if line_lower.contains("reconnecting") || line_lower.contains("rescanning") {
            if t.state >= 3 {
                t.state = 2;
                t.status_message = "Reconnecting...".to_string();
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
    use std::time::Duration;
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return "127.0.0.1".to_string();
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(200)));
    if socket.connect("1.1.1.1:80").is_ok() {
        if let Ok(addr) = socket.local_addr() {
            return addr.ip().to_string();
        }
    }
    "127.0.0.1".to_string()
}

fn cstr_opt(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p).to_str().ok().map(|s| s.trim().to_string()) }
        .filter(|s| !s.is_empty())
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
        // Ironclad is a validation mode, not a scan speed — use thorough
        // scanning underneath, and set AETHER_VALIDATE=ironclad separately.
        4 => "thorough",
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

/// Parse inline routes string in format: [direct]ip1,cidr2,domain3 [block]entry4,...
/// Entries are comma or newline separated. Returns (block_list, direct_list) as newline-separated.
fn parse_inline_routes(input: &str) -> (String, String) {
    let mut block = String::new();
    let mut direct = String::new();
    // Use an enum to track current section instead of a mutable reference,
    // avoiding borrow-checker conflicts between `current` and `direct`/`block`.
    enum Section {
        Block,
        Direct,
    }
    let mut current_section: Option<Section> = None;

    // Split by comma first, then by newline within each segment to handle both formats
    for segment in input.split(',') {
        for line in segment.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let lowered = trimmed.to_lowercase();
            if lowered == "[block]" {
                current_section = Some(Section::Block);
                continue;
            }
            if lowered == "[direct]" {
                current_section = Some(Section::Direct);
                continue;
            }
            if lowered.starts_with('[') {
                current_section = None;
                continue;
            }
            let target = match current_section {
                Some(Section::Block) => &mut block,
                _ => &mut direct, // Default to direct if no section specified
            };
            if !target.is_empty() {
                target.push('\n');
            }
            target.push_str(trimmed);
        }
    }
    (block, direct)
}

fn apply_config_env(cfg: &AetherCfgRaw) {
    std::env::set_var("AETHER_PROTOCOL", protocol_to_env(cfg.protocol));
    std::env::set_var("AETHER_SCAN", scan_mode_to_env(cfg.scan_mode));
    // Ironclad mode: deep HTTP validation after scan (mode 4)
    if cfg.scan_mode == 4 {
        std::env::set_var("AETHER_VALIDATE", "ironclad");
    } else {
        std::env::remove_var("AETHER_VALIDATE");
    }
    std::env::set_var("AETHER_IP", ip_version_to_env(cfg.ip_version));

    // SOCKS5 proxy
    if cfg.socks_port != 0 {
        let socks_addr = if cfg.lan_sharing {
            format!("0.0.0.0:{}", cfg.socks_port)
        } else {
            format!("127.0.0.1:{}", cfg.socks_port)
        };
        std::env::set_var("AETHER_SOCKS", &socks_addr);
        std::env::remove_var("AETHER_SOCKS_DISABLED");
    } else {
        std::env::set_var("AETHER_SOCKS", "0.0.0.0:0");
        std::env::set_var("AETHER_SOCKS_DISABLED", "1");
    }

    // HTTP CONNECT proxy (GUI default 1820)
    if cfg.http_port != 0 && cfg.http_port != cfg.socks_port {
        let http_addr = if cfg.lan_sharing {
            format!("0.0.0.0:{}", cfg.http_port)
        } else {
            format!("127.0.0.1:{}", cfg.http_port)
        };
        std::env::set_var("AETHER_HTTP", &http_addr);
        std::env::set_var("AETHER_HTTP_PORT", cfg.http_port.to_string());
        std::env::remove_var("AETHER_HTTP_DISABLED");
    } else {
        std::env::set_var("AETHER_HTTP", "0.0.0.0:0");
        std::env::set_var("AETHER_HTTP_PORT", "0");
        std::env::set_var("AETHER_HTTP_DISABLED", "1");
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
    // Do NOT force AETHER_VERBOSE — it floods the GUI log buffer and RAM on Windows.
    // Enable only if the user already set it in the environment.
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

    // DNS / TLS / buffers — only apply when pointers look sane (null-safe).
    // Invalid TLS groups must never hard-fail probes (scanner would find 0 endpoints).
    if let Some(dns) = cstr_opt(cfg.dns_server) {
        std::env::set_var("AETHER_DNS", dns);
    } else {
        std::env::remove_var("AETHER_DNS");
    }
    // dns_mode: 0/unknown = classic UDP, 1 = DoH. Ignore garbage large values.
    match cfg.dns_mode {
        1 => std::env::set_var("AETHER_DNS_MODE", "doh"),
        _ => {
            std::env::remove_var("AETHER_DNS_MODE");
        }
    }
    if let Some(url) = cstr_opt(cfg.doh_url) {
        std::env::set_var("AETHER_DOH_URL", url);
    } else {
        std::env::remove_var("AETHER_DOH_URL");
    }
    let prefer = match cfg.dns_ip_prefer {
        4 => "v4",
        6 => "v6",
        10 => "both",
        0 => match cfg.ip_version {
            6 => "v6",
            10 => "both",
            _ => "v4",
        },
        // garbage → default v4
        _ => "v4",
    };
    std::env::set_var("AETHER_DNS_IP", prefer);
    match cstr_opt(cfg.tls_groups) {
        Some(g)
            if g.contains("X25519")
                || g.contains("P-256")
                || g.contains("P-384")
                || g.contains(':') =>
        {
            std::env::set_var("AETHER_TLS_GROUPS", g);
        }
        Some(g) => {
            unsafe {
                log_msg(2, &format!("[ffi] ignoring invalid tls_groups={g:?}"));
            }
            std::env::remove_var("AETHER_TLS_GROUPS");
        }
        None => std::env::remove_var("AETHER_TLS_GROUPS"),
    }
    if cfg.udp_buf_kb >= 64 && cfg.udp_buf_kb <= 8192 {
        std::env::set_var("AETHER_UDP_BUF_KB", cfg.udp_buf_kb.to_string());
    } else {
        std::env::remove_var("AETHER_UDP_BUF_KB");
    }
    if let Some(sni) = cstr_opt(cfg.sni) {
        std::env::set_var("AETHER_SNI", sni);
    } else {
        std::env::remove_var("AETHER_SNI");
    }
    // Sysprofile: 0=Auto, 1=Low, 2=Medium, 3=High
    match cfg.sys_profile {
        1 => std::env::set_var("AETHER_PERF_PROFILE", "low"),
        2 => std::env::set_var("AETHER_PERF_PROFILE", "medium"),
        3 => std::env::set_var("AETHER_PERF_PROFILE", "high"),
        _ => std::env::set_var("AETHER_PERF_PROFILE", "auto"),
    }
    // TUN mode flag for engine (Android sets fd separately via aether_set_android_tun_fd)
    if cfg.mode == 1 {
        std::env::set_var("AETHER_MODE", "tun");
    } else {
        std::env::set_var("AETHER_MODE", "proxy");
    }
    // LAN sharing flag — when TUN mode is active, proxies are only needed
    // if LAN sharing is on (other devices on the network use them).
    if cfg.lan_sharing {
        std::env::set_var("AETHER_LAN_SHARING", "1");
    } else {
        std::env::remove_var("AETHER_LAN_SHARING");
    }
    // Routing rules: file path and inline rules (comma-separated [direct]/[block] format)
    if let Some(rf) = cstr_opt(cfg.routes_file) {
        std::env::set_var("AETHER_ROUTES_FILE", rf);
    } else {
        std::env::remove_var("AETHER_ROUTES_FILE");
    }
    if let Some(ri) = cstr_opt(cfg.routes_inline) {
        // Parse inline format: [direct]entry1,entry2,... [block]entry3,...
        // Split into block and direct lists, set AETHER_ROUTE_BLOCK / AETHER_ROUTE_DIRECT
        let (block, direct) = parse_inline_routes(&ri);
        if !block.is_empty() {
            std::env::set_var("AETHER_ROUTE_BLOCK", &block);
        } else {
            std::env::remove_var("AETHER_ROUTE_BLOCK");
        }
        if !direct.is_empty() {
            std::env::set_var("AETHER_ROUTE_DIRECT", &direct);
        } else {
            std::env::remove_var("AETHER_ROUTE_DIRECT");
        }
    } else {
        std::env::remove_var("AETHER_ROUTE_BLOCK");
        std::env::remove_var("AETHER_ROUTE_DIRECT");
    }
}

#[no_mangle]
pub extern "C" fn aether_init(
    log_cb: Option<unsafe extern "C" fn(i32, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) {
    // Ensure aether_init() body runs exactly once, even if called from
    // multiple threads (the JNI g_inited is not atomic).
    INIT_ONCE.call_once(|| {
        unsafe {
            LOG_CB = log_cb;
            LOG_USER_DATA = user_data;
        }

        // Default Info: Debug floods the UI and RAM (especially on Windows).
        let max = if std::env::var_os("AETHER_VERBOSE").is_some() {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };
        let _ = log::set_logger(&GUI_LOGGER).map(|()| log::set_max_level(max));

        // Prefer detecting LAN IP off the critical path; use 127.0.0.1 initially.
        {
            let mut t = TELEMETRY.lock();
            t.state = 0;
            t.status_message = "Disconnected".to_string();
            t.lan_ip = "127.0.0.1".to_string();
        }
        std::thread::spawn(|| {
            let ip = detect_lan_ip();
            let mut t = TELEMETRY.lock();
            t.lan_ip = ip;
        });

        INITIALIZED.store(true, Ordering::SeqCst);
    });
    unsafe {
        log_msg(4, "[ffi] aether_init completed (in-process engine)");
    }
}

#[no_mangle]
pub extern "C" fn aether_start(config: *const AetherCfgRaw) -> bool {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }

    // Serialize concurrent aether_start() calls (JNI can call from another
    // thread). STOP_GUARD is NOT held for this whole body anymore: it used
    // to be, which meant aether_free()/ui_shutdown() could block behind the
    // up-to-5s drain loop below when the app was closed right after a stop.
    let _start_lock = START_LOCK.lock();

    // Previous engine still running.  If SHUTDOWN was signaled (i.e.
    // aether_stop() was called), wait up to 5 s for it to drain.
    // This covers the case where the service was killed while the
    // engine was still running (e.g. notification disconnect with
    // app in background), and the user re-opens the app quickly.
    if RUNNING.load(Ordering::SeqCst) {
        if SHUTDOWN.load(Ordering::SeqCst) {
            for _ in 0..50 {
                if !RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        if RUNNING.load(Ordering::SeqCst) {
            return false;
        }
    }

    // Re-arm per-session state. In particular the Windows cleanup guard
    // must be reset or the next disconnect would skip DNS restore
    // (stale "done" flag from the previous session).
    #[cfg(target_os = "windows")]
    reset_cleanup_state();

    let cfg = unsafe {
        if config.is_null() {
            return false;
        }
        *config
    };

    // Hold STOP_GUARD across the flag flips + spawn + handle store so
    // aether_free() cannot take the handle / set SHUTDOWN in the middle of
    // a fresh start (that race used to kill the brand-new engine).
    let _stop_guard = STOP_GUARD.lock();
    // Take any leftover JoinHandle from a previous run.
    let _ = ENGINE_THREAD.lock().take();

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
        .worker_threads(4)
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

    let handle = match std::thread::Builder::new()
        .name("aether-engine".to_string())
        .spawn(move || {
            {
                let mut t = TELEMETRY.lock();
                t.state = 2;
                t.status_message = "Scanning gateways...".to_string();
            }

            // Catch panics from the engine so they don't unwind through
            // the tokio runtime drop (which can crash the process).
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt.block_on(async {
                    // Race engine against shutdown flag
                    let engine = aether_engine::run_from_env();
                    tokio::pin!(engine);
                    // Shutdown may already have been requested before this
                    // thread got scheduled (aether_stop() racing
                    // aether_start()) — check once up front rather than
                    // relying solely on the (permit-based) notify below.
                    if SHUTDOWN.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    // Loop to drain stale SHUTDOWN_NOTIFY permits from a
                    // previous aether_free()/aether_stop().  A stale permit
                    // fires immediately but SHUTDOWN is false, so we just
                    // discard it and keep running.
                    loop {
                        tokio::select! {
                            biased;
                            r = &mut engine => break r.map_err(|e| anyhow::anyhow!("{e:#}")),
                            _ = SHUTDOWN_NOTIFY.notified() => {
                                if SHUTDOWN.load(Ordering::SeqCst) {
                                    break Ok(());
                                }
                                // Stale permit — loop and re-enter select.
                            },
                        }
                    }
                })
            })).unwrap_or_else(|_| Err(anyhow::anyhow!("engine panicked")));

            // Drop the tokio runtime inside catch_unwind — this cancels all
            // spawned tasks and waits for workers to finish.  If a task's
            // Drop impl panics during cancellation, catch_unwind prevents
            // the thread from dying (which would leave RUNNING=true forever).
            //
            // CRITICAL: close_all_fds() MUST run before drop(rt).  The TUN
            // read task uses spawn_blocking which blocks on file.read().
            // Runtime drop waits for spawn_blocking tasks to complete, but
            // the read task won't return until the fd is closed — causing
            // a deadlock if we close fds after the runtime drop.
            //
            // ALSO: force-kill tun2socks and clean up Windows TUN adapters
            // BEFORE dropping the runtime.  The tokio task that normally
            // does this cleanup will be cancelled during runtime drop.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                SHUTDOWN.store(true, Ordering::SeqCst);
                aether_engine::tun::close_all_fds();

                RUNNING.store(false, Ordering::SeqCst);
                rt.shutdown_timeout(std::time::Duration::from_secs(1));
            }));

            // Force-kill tun2socks and clean up Windows TUN adapters AFTER
            // the runtime has been dropped. These shell out to PowerShell/
            // netsh/route and can take seconds; cleanup_windows_sync()
            // dedupes against the stop-finalizer / aether_free() paths so
            // only ONE cleanup actually runs per session.
            #[cfg(target_os = "windows")]
            {
                // Cancel any TUN configuration that a dropped task left
                // running (disconnect-during-connect) so it stops applying
                // DNS/route overrides and the cleanup below can proceed.
                aether_engine::tun_t2s::cancel_tun_configuration();
                // Kill tun2socks synchronously (fast) so it's dead before
                // we start the DNS restore.
                aether_engine::tun_t2s::kill_tun2socks_processes();
                // DNS restore and route cleanup — synchronous with timeout.
                // This ensures DNS is restored before the FFI returns to the caller,
                // preventing the "no DNS restore" issue.
                let _ = cleanup_windows_sync("FCAE-VPN", 5);
            }

            // Now that the runtime is dropped, update telemetry — this
            // runs outside the runtime.
            if SHUTDOWN.load(Ordering::SeqCst) {
            match result {
                Ok(()) => {
                    let mut t = TELEMETRY.lock();
                    if !matches!(t.state, 5) {
                        t.state = 0;
                        t.status_message = "Disconnected".to_string();
                    }
                }
                Err(e) => {
                    let mut t = TELEMETRY.lock();
                    t.state = 5;
                    t.last_error = format!("{e:#}");
                    t.status_message = "Error".to_string();
                    drop(t);
                    unsafe {
                        log_msg(1, &format!("[engine] error: {e:#}"));
                    }
                }
            }
        }
        
        })
    {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                log_msg(1, &format!("[ffi] failed to spawn engine thread: {e}"));
            }
            RUNNING.store(false, Ordering::SeqCst);
            return false;
        }
    };

    // Store the handle so aether_free() can join it.
    *ENGINE_THREAD.lock() = Some(handle);

    true
}

#[no_mangle]
pub extern "C" fn aether_stop() {
    if !RUNNING.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        return;
    }

    SHUTDOWN.store(true, Ordering::SeqCst);
    SHUTDOWN_NOTIFY.notify_one();

    // ── Emergency cleanup: force-close TUN fds immediately ──────────────
    // On Android this interrupts the blocking read() in tun::run() instantly
    // so the VpnService fd is released before the engine thread finishes
    // its graceful shutdown. Without this the VPN notification lingers
    // for seconds because the kernel keeps the TUN device alive until
    // the last dup'd fd is closed. (No-op on Windows: TUN is a tun2socks
    // subprocess there.)
    aether_engine::tun::close_all_fds();

    // Abort any in-flight TUN adapter configuration (netsh/PowerShell can
    // run for many seconds during connect) so it stops overriding DNS and
    // adding routes while we tear everything down.
    aether_engine::tun_t2s::cancel_tun_configuration();

    // Update telemetry immediately so the UI shows DISCONNECTED without
    // waiting for the engine thread to finish. Keep state=5 (ERROR) and
    // its message intact: on Android the VPN-service watchdog reacts to
    // an engine error by calling stop — clobbering the error here would
    // erase the reason the engine died from the UI.
    {
        let mut t = TELEMETRY.lock();
        if t.state != 5 {
            t.state = 0;
            t.status_message = "Disconnected".to_string();
        }
        t.connected_peer.clear();
        t.rtt_ms = 0;
        t.rx_bytes_sec = 0;
        t.tx_bytes_sec = 0;
    }

    // ── Windows: cleanup runs on a background thread, NEVER here ────────
    // aether_stop() is called directly from the UI thread (DISCONNECT
    // button). The kill + PowerShell cleanup (DNS restore, adapter
    // removal) takes 5–20 s and can hang if PowerShell stalls — running
    // it inline froze the whole window ("Not Responding"). A detached
    // finalizer performs the exactly-once cleanup; the engine thread's
    // post-runtime path and aether_free() dedupe against it via
    // WIN_CLEANUP_STATE, so nothing runs twice.
    #[cfg(target_os = "windows")]
    {
        std::thread::Builder::new()
            .name("aether-stop-finalizer".to_string())
            .spawn(|| {
                aether_engine::tun_t2s::kill_tun2socks_processes();
                let _ = cleanup_windows_sync("FCAE-VPN", 5);
            })
            .ok();
    }
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

/// Read cached traffic stats without consuming the rate window.
/// Used by the notification poll so it doesn't steal data from the
/// primary UI telemetry caller.
#[no_mangle]
pub extern "C" fn aether_get_cached_telemetry(out: *mut AetherTelemetryOut) {
    if out.is_null() {
        return;
    }

    let (rx_bps, tx_bps) = aether_engine::cached_rates();
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
    aether_engine::tun::set_fd(tun_fd);
}

// ── Version checker FFI ──────────────────────────────────────────────────

#[repr(C)]
pub struct AetherUpdateInfoOut {
    pub update_available: bool,
    pub check_in_progress: bool,
    pub check_done: bool,
    pub latest_version: [u8; 32],
    pub release_notes: [u8; 1024],
    pub download_url: [u8; 512],
    pub status_message: [u8; 256],
}

#[no_mangle]
pub extern "C" fn aether_check_update_async(current_version: *const c_char) {
    let cur_ver = cstr_opt(current_version).unwrap_or_else(|| "dev".to_string());

    // Mark check as in progress
    {
        let mut state = UPDATE_STATE.lock();
        if state.check_in_progress {
            return; // already running
        }
        state.check_in_progress = true;
        state.check_done = false;
        state.result = None;
        state.status_message = "Checking for updates...".to_string();
    }

    // Spawn async check in background thread (reqwest needs tokio runtime)
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                let mut state = UPDATE_STATE.lock();
                state.check_in_progress = false;
                state.check_done = true;
                state.status_message = format!("Failed: {e}");
                return;
            }
        };

        let result = rt.block_on(async {
            match aether_engine::version_checker::fetch_latest_version().await {
                Ok(info) => {
                    let r = aether_engine::version_checker::compare_versions(&cur_ver, &info);
                    Ok(r)
                }
                Err(e) => Err(e),
            }
        });

        let mut state = UPDATE_STATE.lock();
        state.check_in_progress = false;
        state.check_done = true;
        match result {
            Ok(r) => {
                if r.update_available {
                    state.status_message =
                        format!("Update available: {}", r.latest_version);
                } else {
                    state.status_message = format!("Up to date ({})", r.current_version);
                }
                state.result = Some(r);
            }
            Err(e) => {
                state.status_message = e;
            }
        }
    });
}

#[no_mangle]
pub extern "C" fn aether_poll_update(out: *mut AetherUpdateInfoOut) -> bool {
    if out.is_null() {
        return false;
    }

    let state = UPDATE_STATE.lock();
    unsafe {
        (*out).check_in_progress = state.check_in_progress;
        (*out).check_done = state.check_done;
    }

    if let Some(ref r) = state.result {
        unsafe {
            (*out).update_available = r.update_available;
            copy_str_to_buf(&mut (*out).latest_version, &r.latest_version);
            copy_str_to_buf(&mut (*out).release_notes, &r.release_notes);
            copy_str_to_buf(&mut (*out).download_url, &r.download_url);
        }
    } else {
        unsafe {
            (*out).update_available = false;
        }
    }

    unsafe {
        copy_str_to_buf(&mut (*out).status_message, &state.status_message);
    }

    state.check_done
}

/// Parse version JSON fetched by Kotlin/Android (which handles HTTP natively).
/// This avoids reqwest/DNS issues in native threads on Android.
#[no_mangle]
pub extern "C" fn aether_check_update_from_json(
    current_version: *const c_char,
    json: *const c_char,
) -> bool {
    let cur = cstr_opt(current_version).unwrap_or_else(|| "dev".to_string());
    let json_str = match cstr_opt(json) {
        Some(s) => s,
        None => {
            let mut state = UPDATE_STATE.lock();
            state.check_in_progress = false;
            state.check_done = true;
            state.result = None;
            state.status_message = "No JSON provided".to_string();
            return false;
        }
    };

    match aether_engine::version_checker::check_from_json(&cur, &json_str) {
        Ok(r) => {
            let mut state = UPDATE_STATE.lock();
            state.check_in_progress = false;
            state.check_done = true;
            if r.update_available {
                state.status_message = format!("Update available: {}", r.latest_version);
            } else {
                state.status_message = format!("Up to date ({})", r.current_version);
            }
            state.result = Some(r);
            true
        }
        Err(e) => {
            let mut state = UPDATE_STATE.lock();
            state.check_in_progress = false;
            state.check_done = true;
            state.result = None;
            state.status_message = e;
            false
        }
    }
}

/// Check if the current process is running with administrator/root privileges.
/// Required for TUN mode on all platforms.
#[no_mangle]
pub extern "C" fn aether_is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        aether_engine::tun_t2s::is_admin()
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Linux/macOS, check if we're root
        unsafe { libc::geteuid() == 0 }
    }
}

#[no_mangle]
pub extern "C" fn aether_free() {
    // Signal shutdown under STOP_GUARD so a fresh aether_start() cannot
    // slip in between the handle take and the flag flip (that race used
    // to kill the brand-new engine with a stale SHUTDOWN=true).
    {
        let _guard = STOP_GUARD.lock();
        // Take the handle but DO NOT join it.
        // Dropping the handle detaches the thread so it finishes in the background
        // without blocking the Java FFI cleanup thread.
        let _handle = ENGINE_THREAD.lock().take();

        SHUTDOWN.store(true, Ordering::SeqCst);
        if RUNNING.load(Ordering::SeqCst) {
            SHUTDOWN_NOTIFY.notify_one();
        }
    }

    // Abort any in-flight TUN configuration before cleaning up.
    aether_engine::tun_t2s::cancel_tun_configuration();

    // Safety net: close TUN fds and force-cleanup Windows TUN adapters.
    // close_all_fds() uses atomic swap so double-close is impossible.
    aether_engine::tun::close_all_fds();
    #[cfg(target_os = "windows")]
    {
        // Final exit path (ui_shutdown → ExitProcess). Run the exactly-once
        // cleanup synchronously but BOUNDED: it either performs the DNS
        // restore itself or waits for the in-progress one (from the engine
        // thread / stop finalizer) to finish. The old version joined the
        // cleanup thread forever, which could hang process exit when
        // PowerShell stalled.
        aether_engine::tun_t2s::kill_tun2socks_processes();
        let _ = cleanup_windows_sync("FCAE-VPN", 5);
        // The FFI-side cleanup above may have been a no-op because the
        // engine-side cleanup (spawned when the tun2socks task was
        // dropped/cancelled) already claimed the work. Wait for that one
        // too — ExitProcess() right after this would otherwise kill it
        // mid-PowerShell and lose the DNS restore.
        if !aether_engine::tun_t2s::wait_tun_cleanup_bounded(std::time::Duration::from_secs(10)) {
            unsafe {
                log_msg(2, "[ffi] aether_free: engine TUN cleanup still running at exit — giving up (bounded)");
            }
        }
    }

    let mut t = TELEMETRY.lock();
    if t.state == 5 {
        // Keep the error visible: aether_free() often runs as a REACTION
        // to the engine erroring (Android service teardown); resetting
        // here would erase the error message the user is looking at.
        t.connected_peer.clear();
        t.rtt_ms = 0;
        t.rx_bytes_sec = 0;
        t.tx_bytes_sec = 0;
    } else {
        t.state = 0;
        t.status_message = "Disconnected".to_string();
        t.connected_peer.clear();
        t.rtt_ms = 0;
        t.rx_bytes_sec = 0;
        t.tx_bytes_sec = 0;
        t.total_rx = 0;
        t.total_tx = 0;
        t.last_error.clear();
    }
}
