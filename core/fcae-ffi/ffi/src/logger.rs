//! Bridges Rust's `log` facade to the host's C callback.
//!
//! Differences from the old GUI logger:
//!
//! * It no longer **parses** log lines to infer connection state or RTT.
//!   That was load-bearing behaviour keyed on message wording; state now
//!   comes from the backend explicitly and counters from `Backend::counters`.
//! * The callback pointer lives behind an atomic rather than a `static mut`,
//!   so `fcae_shutdown` racing an engine thread's log call is defined.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

/// General log messages stay short; Psiphon notices have a separate larger limit.
const MAX_MSG: usize = 512;

static CALLBACK: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static USER_DATA: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static MAX_LEVEL: AtomicU8 = AtomicU8::new(fcae_abi::FcaeLogLevel::Info as u8);
static FIREFOX_LEVEL: AtomicU8 = AtomicU8::new(0);
static URNETWORK_LEVEL: AtomicU8 = AtomicU8::new(0);

static ACTIVE_CALLS: AtomicUsize = AtomicUsize::new(0);

type RawCb = unsafe extern "C" fn(fcae_abi::FcaeLogLevel, *const std::ffi::c_char, *mut c_void);

struct FcaeLogger;

impl log::Log for FcaeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if let Some(max) = backend_level(metadata.target()) {
            return max != 0 && level_to_u8(metadata.level()) <= max;
        }
        let max = MAX_LEVEL.load(Ordering::Relaxed);
        metadata.target() == fcae_runtime::proxy_cores::CORE_LOG_TARGET
            || level_to_u8(metadata.level()) <= max
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Track in-flight callbacks so uninstall() can synchronize cleanly
        ACTIVE_CALLS.fetch_add(1, Ordering::SeqCst);

        let ptr = CALLBACK.load(Ordering::SeqCst);
        let ud = USER_DATA.load(Ordering::SeqCst);

        let mut msg = record.args().to_string();
        if backend_level(record.target()).is_some() { msg = redact_backend(&msg); }
        let limit = if msg.starts_with("[psiphon] {") { 1024 * 1024 } else { MAX_MSG };
        if msg.len() > limit {
            let mut end = limit;
            while end > 0 && !msg.is_char_boundary(end) {
                end -= 1;
            }
            msg.truncate(end);
            msg.push('…');
        }
        // Interior NULs would truncate the C string; replace them.
        let msg = msg.replace('\0', "?");
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        crate::crash_log::record_log(&msg);

        if !ptr.is_null() {
            // SAFETY: only ever stored from `install` with a valid fn pointer.
            let cb: RawCb = unsafe { std::mem::transmute(ptr) };
            if let Ok(c) = CString::new(msg) {
                unsafe { cb(abi_level(record.level()), c.as_ptr(), ud) };
            }
        }

        ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
    }

    fn flush(&self) {}
}

pub fn set_backend_level(backend: u32, level: u8) {
    match backend {
        2 => FIREFOX_LEVEL.store(level.min(4), Ordering::Relaxed),
        6 => URNETWORK_LEVEL.store(level.min(4), Ordering::Relaxed),
        _ => {},
    }
}
fn backend_level(target: &str) -> Option<u8> {
    if target == "fcae_firefox" || target.starts_with("fcae_firefox::")
        || target == "fcae_firefox_bridge" || target.starts_with("fcae_firefox_bridge::") {
        Some(FIREFOX_LEVEL.load(Ordering::Relaxed))
    } else if target == "fcae.urnetwork" || target.starts_with("fcae_bridge_tun2socks::urnetwork") {
        Some(URNETWORK_LEVEL.load(Ordering::Relaxed))
    } else { None }
}
fn redact_backend(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let stop = ["authorization", "password", "bearer ", "token", "jwt", "secret",
        "verification_code", "auth_code", "message=", "message:"]
        .iter().filter_map(|key| lower.find(key)).min().unwrap_or(message.len());
    let mut output = message[..stop].split_whitespace().map(|word| {
        if word.contains('@') || word.contains("eyJ")
            || word.split(|c: char| !c.is_ascii_hexdigit()).any(|part| part.len() >= 32) {
            "[redacted]"
        } else { word }
    }).collect::<Vec<_>>().join(" ");
    if stop < message.len() { output.push_str(" [sensitive details omitted]"); }
    output
}

fn level_to_u8(l: log::Level) -> u8 {
    match l {
        log::Level::Error => 1,
        log::Level::Warn => 2,
        log::Level::Info => 3,
        log::Level::Debug => 4,
        log::Level::Trace => 5,
    }
}

fn abi_level(l: log::Level) -> fcae_abi::FcaeLogLevel {
    match l {
        log::Level::Error => fcae_abi::FcaeLogLevel::Error,
        log::Level::Warn => fcae_abi::FcaeLogLevel::Warn,
        log::Level::Info => fcae_abi::FcaeLogLevel::Info,
        _ => fcae_abi::FcaeLogLevel::Debug,
    }
}

static LOGGER: FcaeLogger = FcaeLogger;

/// Install the host callback and register the global logger (once).
pub fn install(cb: fcae_abi::FcaeLogCallback, user_data: *mut c_void, max_level: fcae_abi::FcaeLogLevel) {
    USER_DATA.store(user_data, Ordering::SeqCst);
    MAX_LEVEL.store(max_level as u8, Ordering::SeqCst);
    CALLBACK.store(
        cb.map(|f| f as *mut c_void).unwrap_or(std::ptr::null_mut()),
        Ordering::SeqCst,
    );

    // `set_logger` can only succeed once per process; ignore a second
    // attempt (e.g. init → shutdown → init).
    let _ = log::set_logger(&LOGGER);
    // Keep core Debug records reachable; enabled() still filters general logs.
    log::set_max_level(log::LevelFilter::Debug);
}

/// Detach the host callback and wait for in-flight callbacks. Desktop
/// diagnostic logging remains active after the callback is detached.
pub fn uninstall() {
    CALLBACK.store(std::ptr::null_mut(), Ordering::SeqCst);
    USER_DATA.store(std::ptr::null_mut(), Ordering::SeqCst);

    // Spin/yield until any callback already past the null check has completed
    while ACTIVE_CALLS.load(Ordering::SeqCst) > 0 {
        std::thread::yield_now();
    }
}
