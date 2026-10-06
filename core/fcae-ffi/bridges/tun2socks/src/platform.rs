//! OS-level TUN configuration: addresses, routes, DNS — and undoing them.
//!
//! Lifted out of the old `aether-engine/src/tun_t2s.rs`, where it was tangled
//! up with subprocess management. Two structural fixes:
//!
//! 1. **Undo is data, not code.** `configure` returns a [`TunUndo`] describing
//!    exactly what was changed; `restore` reverses precisely that. The old
//!    code re-derived what to clean up from the config and global statics,
//!    which is why a cleanup could run twice, or run against the wrong
//!    adapter after a reconnect.
//! 2. **Exactly-once is enforced by ownership.** Because the bridge holds the
//!    single `TunUndo` value and `stop()` takes it out of the mutex, the
//!    three-way race between the UI thread, the engine thread and process
//!    exit (previously handled with an `AtomicU8` state machine, a detached
//!    "finalizer" thread and bounded polling) cannot occur.

use std::time::Duration;

use fcae_runtime::config::SessionConfig;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use fcae_runtime::error::CoreError;
use fcae_runtime::error::Result;

/// Record of the system changes made when the device came up.
#[derive(Default)]
pub struct TunUndo {
    #[cfg(windows)]
    pub windows: Option<fcae_runtime::windows_tun::TunGuard>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unix: Option<fcae_runtime::unix_tun::TunGuard>,
}

/// True when the process can create a TUN device.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Probing a privileged path is cheaper and more reliable than the
        // token API dance, and matches what the old code concluded.
        std::fs::OpenOptions::new()
            .write(true)
            .open("\\\\.\\PHYSICALDRIVE0")
            .is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Apply addresses, routes and DNS for a freshly created device.
pub fn configure(cfg: &SessionConfig, peer_ip: Option<&str>) -> Result<TunUndo> {
    #[cfg(target_os = "android")]
    {
        let _ = (cfg, peer_ip);
        log::info!("[tun2socks] Android: VpnService owns routing/DNS; nothing to configure natively");
        Ok(TunUndo::default())
    }
    #[cfg(windows)]
    {
        Ok(TunUndo { windows: Some(fcae_runtime::windows_tun::TunGuard::configure(cfg, peer_ip)?) })
    }
    #[cfg(target_os = "linux")]
    {
        let name = &cfg.tun.name;
        if !fcae_runtime::unix_tun::wait_for_device(name, false, Duration::from_secs(3)) {
            return Err(CoreError::Internal(format!("TUN device `{name}` did not appear")));
        }
        Ok(TunUndo { unix: Some(fcae_runtime::unix_tun::TunGuard::configure(cfg, name, peer_ip, true)?) })
    }
    #[cfg(target_os = "macos")]
    {
        let name = fcae_runtime::unix_tun::utun_devices()
            .pop()
            .ok_or_else(|| CoreError::Internal("tun2socks created no utun device".into()))?;
        Ok(TunUndo { unix: Some(fcae_runtime::unix_tun::TunGuard::configure(cfg, &name, peer_ip, true)?) })
    }
    #[cfg(not(any(target_os = "android", windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (cfg, peer_ip);
        Ok(TunUndo::default())
    }
}

/// Reverse exactly what [`configure`] did.
pub fn restore(undo: TunUndo, _timeout: Duration) {
    drop(undo);
}

// ── Windows ─────────────────────────────────────────────────────────────

#[cfg(windows)]
pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> Result<()> {
    fcae_runtime::windows_dll::ensure_wintun(bytes)
}
