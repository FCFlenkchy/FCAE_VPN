//! # fcae-bridge-hev-socks5-tunnel — TUN bridge over the hev-socks5-tunnel engine
//!
//! Implements [`fcae_runtime::session::TunBridge`] with **hev-socks5-tunnel**, a
//! C SOCKS5 tunnel engine (coroutine I/O over lwip) that converts the local
//! SOCKS5 endpoint a backend already exposes into a TUN device. It is a drop-in
//! sibling of `fcae-bridge-tun2socks` and `fcae-bridge-zeptun`: no Go runtime,
//! no subprocess, and every engine shares one wintun adapter identity
//! (see [`WINTUN_ADAPTER_GUID`]).
//!
//! ## Backends
//!
//! | platform | backend | why |
//! |----------|---------|-----|
//! | Linux, macOS, Android | linked in-process, C ABI | the engine's own TUN code compiles for these |
//! | Windows | DLL loaded in-process at runtime | the engine's Windows backend is `__MSYS__`-only and links the MSYS runtime, which the MinGW build cannot link; a DLL is the one MSYS2 artifact a native process can host |
//!
//! Windows is the odd one out: the engine's Windows backend (tun device, the
//! hev-task-system IOCP reactor, Win64 ABI assembly, the wintun session) is
//! behind `__MSYS__`, so it needs the MSYS runtime. No Rust target produces
//! MSYS binaries and the MinGW link cannot take the archive (those code paths
//! are compiled out and the remaining sources need POSIX socket headers MinGW
//! does not ship). So MSYS2 builds the engine as a DLL (`make shared`, by the
//! `build-hev-windows` job) and the app loads it next to the executable with
//! `LoadLibraryExW` at first use: same process and same wintun adapter
//! (name and GUID) as the in-process engines use everywhere else. The DLL
//! drags its `msys-2.0.dll` runtime and third-party imports along, so the app
//! itself stays a plain MinGW binary.
//!
//! Loading is lazy and isolated: a missing or unloadable DLL surfaces as
//! "engine unavailable" (or a specific start error) instead of taking the app
//! down at startup.
//!
//! ## Build requirements
//!
//! * in-process: an archive built outside the cargo graph (see `build.rs`), i.e.
//!   `make -C core/hev-socks5-tunnel static`, or `FCAE_HEV_LIBDIR=<dir>`.
//! * Windows: `FCAE_HEV_DLL=<path to libhev-socks5-tunnel.dll>` during the
//!   build tells the crate the DLL is part of the install. At runtime it is
//!   loaded from beside the executable, or from the path in `FCAE_HEV_DLL`
//!   when that variable is set. Without the build-time variable a Windows
//!   build must use the stub:
//!   `cargo build --features fcae-bridge-hev-socks5-tunnel/stub`.
//!
//! Do not ship a stub build: it reports the engine as unavailable in the UI.

mod socks5p;

#[cfg(not(windows))]
mod engine;
#[cfg(windows)]
#[path = "windows.rs"]
mod engine;

/// Platform glue: the privilege probe compiles on every target (the FFI
/// layer's `fcae_is_privileged()` reaches it as
/// `fcae_bridge_hev_socks5_tunnel::platform::is_privileged`), the Wintun
/// DLL staging is Windows-only and cfg-gated inside the module.
pub mod platform;

pub use engine::{HevSocks5TunnelBridge, unavailable_reason};

/// The wintun adapter GUID every FCAE TUN engine pins.
///
/// Wintun identifies an adapter by name *and* GUID: the GUID decides the NLA
/// entry and the NetCfgInstanceId, so a stable one keeps the firewall profile,
/// DNS assignment and registered-network settings across engines, sessions and
/// reinstalls, and makes repeated creation idempotent instead of accruing
/// `FCAE_VPN 2`, `FCAE_VPN 3` duplicates. `fcae-bridge-tun2socks` passes it in
/// the device URL, `fcae-bridge-zeptun` through `zeptun_set_adapter_guid`, and
/// the hev engine (every platform) receives it as `tunnel.guid` in the config
/// this bridge renders.
pub const WINTUN_ADAPTER_GUID: &str = "24198F4C-7895-434C-AD65-9E29A92DDC61";

/// True when this build can actually run the engine: the C engine is linked
/// in, or (Windows) the engine DLL loads from beside the running binary.
pub fn is_supported() -> bool {
    engine::is_supported()
}

/// Re-exported so the FFI layer's `fcae_is_privileged()` covers hev-only
/// builds too.
pub fn is_privileged() -> bool {
    platform::is_privileged()
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
pub(crate) fn bare_address(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

/// Map the UI's TUN log knob onto the engine's levels.
///
/// `FcaeT2sLog`: 0 = default, 1 = silent, 2 = error, 3 = warn, 4 = info,
/// 5 = debug. The engine takes exactly `debug`, `info`, `warn`, `error` (and
/// falls back to warn), so a quiet setting still keeps failures — the log is
/// what a failed startup is diagnosed from.
pub(crate) fn log_level(t2s_log_level: u8) -> &'static str {
    match t2s_log_level {
        5 => "debug",
        4 => "info",
        3 => "warn",
        _ => "error",
    }
}

pub(crate) fn generate_config(cfg: &fcae_runtime::config::SessionConfig, socks: std::net::SocketAddr) -> fcae_runtime::error::Result<(std::net::SocketAddr, String)> {
    let mut yaml = String::with_capacity(256);
    yaml.push_str("tunnel:\n");
    yaml.push_str(&format!("  name: '{}'\n", cfg.tun.name.replace('\'', "''")));
    #[cfg(windows)]
    yaml.push_str(&format!("  guid: {}\n", crate::WINTUN_ADAPTER_GUID));
    yaml.push_str(&format!("  mtu: {}\n", cfg.tun.mtu));
    yaml.push_str("  multi-queue: false\n");
    yaml.push_str(&format!("  ipv4: {}\n", bare_address(&cfg.tun.ipv4)));
    if let Some(ipv6) = &cfg.tun.ipv6 {
        yaml.push_str(&format!("  ipv6: '{}'\n", bare_address(ipv6)));
    }
    yaml.push_str("  icmp: 'off'\n\n");
    yaml.push_str("socks5:\n");
    yaml.push_str(&format!("  port: {}\n", socks.port()));
    yaml.push_str(&format!("  address: {}\n", socks.ip()));
    yaml.push_str("  udp: 'udp'\n");
    yaml.push_str("\nmisc:\n");
    yaml.push_str(&format!("  log-level: '{}'\n", log_level(cfg.tun.t2s_log_level)));
    Ok((socks, yaml))
}


#[cfg(test)]
mod tests {
    use super::*;

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
