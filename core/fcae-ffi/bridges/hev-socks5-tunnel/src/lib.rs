//! # fcae-bridge-hev-socks5-tunnel — TUN bridge over the hev-socks5-tunnel engine
//!
//! Implements [`fcae_runtime::session::TunBridge`] with **hev-socks5-tunnel**, a
//! C SOCKS5 tunnel engine (coroutine I/O over lwip) that converts the local
//! SOCKS5 endpoint a backend already exposes into a TUN device. It is a drop-in
//! sibling of `fcae-go-bridge` and `fcae-bridge-zeptun`: no Go runtime,
//! no subprocess, and every engine shares one wintun adapter identity
//! (see [`WINTUN_ADAPTER_GUID`]).
//!
//! ## Backends
//!
//! | platform | backend | why |
//! |----------|---------|-----|
//! | Linux, macOS, Android | linked in-process, C ABI | the engine's own TUN code compiles for these |
//! | Windows | linked in-process, C ABI | Wintun remains a separate runtime DLL/driver |
//!
//! ## Build requirements
//!
//! Build the engine and dependency archives outside Cargo, or set
//! `FCAE_HEV_LIBDIR` to a directory containing them. The Windows CI build
//! stages MinGW-targeted archives there; Wintun is still staged separately.
//!
//! Do not ship a stub build: it reports the engine as unavailable in the UI.

mod engine;

/// Platform glue: the Wintun DLL staging is Windows-only and cfg-gated
/// inside the module. The admin/root probe lives in [`fcae_runtime::privilege`].
pub mod platform;

pub use engine::{HevSocks5TunnelBridge, unavailable_reason};

/// The requested Wintun identity shared by FCAE's Windows TUN engines.
pub use fcae_runtime::config::WINTUN_ADAPTER_GUID;

/// True when this build can actually run the engine: the C engine is linked
/// in and, on Windows, Wintun is staged.
pub fn is_supported() -> bool {
    engine::is_supported()
}

/// Traffic statistics from the engine.
///
/// The in-process backend reads the engine's counters directly, on every
/// platform including Windows (the engine runs inside this process).
#[derive(Default, Clone, Copy, Debug)]
pub struct HevStats {
    pub tx_packets: usize,
    pub tx_bytes: usize,
    pub rx_packets: usize,
    pub rx_bytes: usize,
}

/// `tunnel.ipv4`/`tunnel.ipv6` take bare addresses: the engine derives the
/// netmask itself (`inet_pton` plus a fixed /32 and /128), so a CIDR from the
/// session config is reduced to its address.
#[cfg(target_os = "android")]
pub(crate) fn bare_address(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

/// True when the user asked for no engine logging at all: `FcaeT2sLog`
/// 0 = default (which is silent for this engine) and 1 = silent. In that
/// case nothing may touch the filesystem — not even the temp spool.
pub(crate) fn engine_log_silent(t2s_log_level: u8) -> bool {
    matches!(t2s_log_level, 0 | 1)
}

/// Map the UI's TUN log knob onto the engine's levels.
///
/// `FcaeT2sLog`: 0 = default, 1 = silent, 2 = error, 3 = warn, 4 = info,
/// 5 = debug. The engine takes exactly `debug`, `info`, `warn`, `error` (and
/// falls back to warn); silent levels are handled before this is consulted,
/// so a quiet non-silent setting still keeps failures — the log is what a
/// failed startup is diagnosed from.
pub(crate) fn log_level(t2s_log_level: u8) -> &'static str {
    match t2s_log_level {
        5 => "debug",
        4 => "info",
        3 => "warn",
        _ => "error",
    }
}

/// Runs the engine's `main`, absorbing a stale stop request.
///
/// `hev_socks5_tunnel_quit` latches `SYNC_STOP` whenever no run is live, and
/// the next run consumes it by returning 0 before it starts. A quit racing
/// the previous engine's own exit therefore makes this run end at once; a
/// clean exit nobody in this generation asked for is exactly that latch.
pub(crate) fn run_engine(closing: &std::sync::atomic::AtomicBool, mut main: impl FnMut() -> std::ffi::c_int) -> std::ffi::c_int {
    let code = main();
    if code != 0 || closing.load(std::sync::atomic::Ordering::SeqCst) {
        return code;
    }
    log::debug!("[hev] discarding a stop latched by the previous engine");
    main()
}

/// The `misc.log-file` path for the engine: a session-local spool in the
/// temp directory. The engine (a C library that cannot call back into FCAE)
/// writes its diagnostics there; [`relay_engine_log`] tails the spool and
/// re-emits every line into the app's normal logging path, so `logs.txt`
/// stays the single place that holds everything. The spool is removed when
/// the session ends.
fn hev_log_path() -> String {
    std::env::temp_dir()
        .join(format!("fcae-hev-{}.log", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Re-emits new lines from the engine's own log file into FCAE's diagnostic
/// log (`logs.txt` on desktop via the crash logger; the host log callback on
/// Android), so a TUN session that comes up with no traffic can be diagnosed
/// from the same place as everything else. The engine writes the spool file
/// itself; this only tails it and never blocks the engine.
pub(crate) struct LogRelay {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    path: std::path::PathBuf,
}

impl LogRelay {
    /// Stops the tail, drains whatever the engine wrote before its exit, and
    /// removes the spool. Call only after the engine thread has joined.
    pub(crate) fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // Best effort: the spool is redundant once drained into logs.txt.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Starts the relay that mirrors the engine's spool into the app log.
/// Lines already present in the spool when the relay starts are skipped
/// (the spool is named per process, so they can only be from a previous
/// run of this PID). When the engine log is silent there is no spool to
/// tail, and this deliberately creates nothing.
pub(crate) fn relay_engine_log(t2s_log_level: u8) -> Option<LogRelay> {
    if engine_log_silent(t2s_log_level) {
        return None;
    }
    let path = std::path::PathBuf::from(hev_log_path());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = std::sync::Arc::clone(&stop);
    let thread_path = path.clone();
    let thread = std::thread::Builder::new()
        .name("hev-log".into())
        .spawn(move || {
            use std::io::{Read as _, Seek as _, SeekFrom};
            let mut offset = std::fs::metadata(&thread_path).map(|m| m.len()).unwrap_or(0);
            let mut carry = String::new();
            loop {
                let stopping = thread_stop.load(std::sync::atomic::Ordering::SeqCst);
                match std::fs::File::open(&thread_path) {
                    Ok(mut file) => {
                        let len = file.metadata().map(|m| m.len()).unwrap_or(offset);
                        if len < offset {
                            // Truncated or replaced: start over.
                            offset = 0;
                            carry.clear();
                        }
                        if len > offset {
                            if file.seek(SeekFrom::Start(offset)).is_ok() {
                                let mut buf = Vec::new();
                                let mut limited = file.take(len - offset);
                                if limited.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                                    offset = len;
                                    carry.push_str(&String::from_utf8_lossy(&buf));
                                    while let Some(index) = carry.find('\n') {
                                        let line = carry[..index].trim_end_matches(&['\r', '\n'][..]);
                                        if !line.is_empty() {
                                            log::info!("[hev] {line}");
                                        }
                                        carry.drain(..=index);
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
                if stopping {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let trailing = carry.trim();
            if !trailing.is_empty() {
                log::info!("[hev] {trailing}");
            }
        })
        .ok()?;
    Some(LogRelay { stop, thread: Some(thread), path })
}

pub(crate) fn generate_config(cfg: &fcae_runtime::config::SessionConfig, socks: std::net::SocketAddr) -> fcae_runtime::error::Result<(std::net::SocketAddr, String)> {
    #[cfg(not(target_os = "android"))]
    if cfg.tun.name.is_empty() || cfg.tun.name.len() > 63 || cfg.tun.name.chars().any(char::is_control) {
        return Err(fcae_runtime::error::CoreError::InvalidConfig(
            "HEV TUN name must be 1–63 UTF-8 bytes without control characters".into(),
        ));
    }
    let mut yaml = String::with_capacity(256);
    yaml.push_str("tunnel:\n");
    yaml.push_str(&format!("  name: '{}'\n", cfg.tun.name.replace('\'', "''")));
    #[cfg(windows)]
    yaml.push_str(&format!("  guid: {}\n", crate::WINTUN_ADAPTER_GUID));
    yaml.push_str(&format!("  mtu: {}\n", cfg.tun.mtu));
    yaml.push_str("  multi-queue: false\n");
    #[cfg(target_os = "android")]
    {
        yaml.push_str(&format!("  ipv4: {}\n", bare_address(&cfg.tun.ipv4)));
        if let Some(ipv6) = &cfg.tun.ipv6 {
            yaml.push_str(&format!("  ipv6: '{}'\n", bare_address(ipv6)));
        }
    }
    yaml.push_str("  icmp: 'off'\n\n");
    yaml.push_str("socks5:\n");
    yaml.push_str(&format!("  port: {}\n", socks.port()));
    yaml.push_str(&format!("  address: {}\n", socks.ip()));
    yaml.push_str("  udp: 'udp'\n");
    yaml.push_str("\nmisc:\n");
    if engine_log_silent(cfg.tun.t2s_log_level) {
        // Silent means silent: hand the engine 'null' and no file is
        // created at all — not even the temp spool. Anything else would
        // leave a stray file behind on every run just to catch lines the
        // user asked not to see.
        yaml.push_str("  log-level: 'error'\n");
        yaml.push_str("  log-file: 'null'\n");
        log::info!("[hev] engine config: name='{}' mtu={} (engine log silent)", cfg.tun.name, cfg.tun.mtu);
    } else {
        yaml.push_str(&format!("  log-level: '{}'\n", log_level(cfg.tun.t2s_log_level)));
        // The C library logs to stderr only when `log-file` is unset, and a GUI
        // process has no stderr — every engine diagnostic used to vanish. It
        // writes a small spool in the temp dir; `relay_engine_log` mirrors every
        // line into the app's normal logging path (logs.txt) while the session is
        // up, then removes the spool.
        let spool = hev_log_path();
        yaml.push_str(&format!("  log-file: '{}'\n", spool.replace('\'', "''")));
        log::info!("[hev] engine config: name='{}' mtu={}", cfg.tun.name, cfg.tun.mtu);
    }
    Ok((socks, yaml))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "android"))]
    fn desktop_host_guard_owns_address_configuration() {
        let config = fcae_runtime::config::SessionConfig::default();
        let (_, yaml) = generate_config(&config, "127.0.0.1:1080".parse().unwrap()).unwrap();
        assert!(!yaml.contains("  ipv4:"));
        assert!(!yaml.contains("  ipv6:"));
        assert!(yaml.contains("  mtu:"));
    }

    #[test]
    #[cfg(windows)]
    fn windows_config_uses_the_shared_adapter_identity() {
        let config = fcae_runtime::config::SessionConfig::default();
        let (_, yaml) = generate_config(&config, "127.0.0.1:1080".parse().unwrap()).unwrap();
        assert!(yaml.contains(&format!("  guid: {}\n", fcae_runtime::config::WINTUN_ADAPTER_GUID)));
        assert!(yaml.contains(&format!("  name: '{}'\n", config.tun.name.replace('\'', "''"))));
    }

    #[test]
    #[cfg(not(target_os = "android"))]
    fn invalid_names_do_not_reach_the_native_engine() {
        let mut config = fcae_runtime::config::SessionConfig::default();
        let socks = "127.0.0.1:1080".parse().unwrap();
        for name in [String::new(), "x".repeat(64), "bad\nname".to_owned(), "é".repeat(32)] {
            config.tun.name = name;
            assert!(generate_config(&config, socks).is_err());
        }
        config.tun.name = "x".repeat(63);
        assert!(generate_config(&config, socks).is_ok());
        config.tun.name = "test's".into();
        assert!(generate_config(&config, socks).unwrap().1.contains("name: 'test''s'"));
    }

    /// Only levels the engine understands may be emitted: an unknown string
    /// silently becomes `warn`, which would hide the errors a failed start is
    /// diagnosed from.
    #[test]
    fn the_engine_log_level_follows_the_ui_knob() {
        for level in [0u8, 1, 2, 3, 4, 5] {
            let emitted = log_level(level);
            assert!(
                ["debug", "info", "warn", "error"].contains(&emitted),
                "level {level} became {emitted}"
            );
        }
        assert_eq!(log_level(5), "debug");
        assert_eq!(log_level(4), "info");
        assert_eq!(log_level(3), "warn");
        assert_eq!(log_level(2), "error");
        assert_eq!(log_level(0), "error");
    }
}
