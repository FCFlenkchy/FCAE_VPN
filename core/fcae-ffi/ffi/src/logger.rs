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

/// Longest message forwarded to the UI; the old code's unbounded strings
/// were a real memory-pressure source on Windows.
const MAX_MSG: usize = 512;

static CALLBACK: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static USER_DATA: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static MAX_LEVEL: AtomicU8 = AtomicU8::new(fcae_abi::FcaeLogLevel::Info as u8);
static ACTIVE_CALLS: AtomicUsize = AtomicUsize::new(0);

type RawCb = unsafe extern "C" fn(fcae_abi::FcaeLogLevel, *const std::ffi::c_char, *mut c_void);

struct FcaeLogger;

impl log::Log for FcaeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let max = MAX_LEVEL.load(Ordering::Relaxed);
        (level_to_u8(metadata.level())) <= max
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Track in-flight callbacks so uninstall() can synchronize cleanly
        ACTIVE_CALLS.fetch_add(1, Ordering::SeqCst);

        let ptr = CALLBACK.load(Ordering::SeqCst);
        if ptr.is_null() {
            ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        let ud = USER_DATA.load(Ordering::SeqCst);

        // SAFETY: only ever stored from `install` with a valid fn pointer.
        let cb: RawCb = unsafe { std::mem::transmute(ptr) };

        let mut msg = record.args().to_string();
        if msg.len() > MAX_MSG {
            let mut end = MAX_MSG;
            while end > 0 && !msg.is_char_boundary(end) {
                end -= 1;
            }
            msg.truncate(end);
            msg.push('…');
        }
        // Interior NULs would truncate the C string; replace them.
        let msg = msg.replace('\0', "?");

        if let Ok(c) = CString::new(msg) {
            unsafe { cb(abi_level(record.level()), c.as_ptr(), ud) };
        }

        ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
    }

    fn flush(&self) {}
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
    log::set_max_level(match max_level {
        fcae_abi::FcaeLogLevel::Error => log::LevelFilter::Error,
        fcae_abi::FcaeLogLevel::Warn => log::LevelFilter::Warn,
        fcae_abi::FcaeLogLevel::Info => log::LevelFilter::Info,
        fcae_abi::FcaeLogLevel::Debug => log::LevelFilter::Debug,
    });
}

/// Detach the host callback. The logger stays registered but becomes a no-op,
/// waiting for any concurrent callback invocation to finish before returning.
pub fn uninstall() {
    CALLBACK.store(std::ptr::null_mut(), Ordering::SeqCst);
    USER_DATA.store(std::ptr::null_mut(), Ordering::SeqCst);

    // Spin/yield until any callback already past the null check has completed
    while ACTIVE_CALLS.load(Ordering::SeqCst) > 0 {
        std::thread::yield_now();
    }
}
