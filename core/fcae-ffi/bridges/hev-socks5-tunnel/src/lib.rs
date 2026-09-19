//! # fcae-bridge-hev-socks5-tunnel — TUN bridge over the hev-socks5-tunnel engine
//!
//! Implements [`fcae_runtime::session::TunBridge`] with **hev-socks5-tunnel**, a
//! C SOCKS5 tunnel engine (coroutine I/O over lwip) that converts the local
//! SOCKS5 endpoint a backend already exposes into a TUN device. It is a drop-in
//! sibling of `fcae-bridge-tun2socks` and `fcae-bridge-zeptun`: no Go runtime,
//! no subprocess overhead, and every engine shares one wintun adapter identity
//! (see [`WINTUN_ADAPTER_GUID`]).
//!
//! ## Backends
//!
//! | platform | backend | why |
//! |----------|---------|-----|
//! | Linux, macOS, Android | [`engine`] — in-process, C ABI | the engine's own TUN code compiles for these |
//! | Windows | [`sidecar`] — upstream's executable beside the app | the engine has no native Windows port to link |
//!
//! Windows is the odd one out: the engine's Windows backend (tun device, the
//! hev-task-system IOCP reactor, Win64 ABI assembly, the wintun session) is
//! behind `__MSYS__`, so it needs the MSYS runtime to own the process, upstream
//! ships `msys-2.0.dll` beside its own win64 binary, and no Rust target produces
//! MSYS binaries. Cross-building it against MinGW cannot work: those code paths
//! are compiled out and the remaining sources need POSIX socket headers MinGW
//! does not ship. So Windows runs upstream's `hev-socks5-tunnel.exe` — built with
//! MSYS2 by the `build-hev-windows` job and installed next to the app — as a
//! child process with the same config file, the same adapter and the same GUID
//! as the in-process engines use elsewhere.
//!
//! ## Build requirements
//!
//! * in-process: an archive built outside the cargo graph (see `build.rs`), i.e.
//!   `make -C core/hev-socks5-tunnel static`, or `FCAE_HEV_LIBDIR=<dir>`.
//! * Windows sidecar: `FCAE_HEV_SIDECAR_EXE=<path to hev-socks5-tunnel.exe>`
//!   during the build tells the crate the executable is part of the install.
//!   Without it a Windows build must use the stub:
//!   `cargo build --features fcae-bridge-hev-socks5-tunnel/stub`.
//!
//! Do not ship a stub build: it reports the engine as unavailable in the UI.

#[cfg(not(all(windows, hev_sidecar)))]
mod engine;
#[cfg(all(windows, hev_sidecar))]
mod sidecar;

/// Wintun only; the in-process backend stages the driver DLL from here.
#[cfg(all(windows, not(hev_sidecar)))]
mod platform;

#[cfg(not(all(windows, hev_sidecar)))]
pub use engine::HevSocks5TunnelBridge;
#[cfg(all(windows, hev_sidecar))]
pub use sidecar::HevSocks5TunnelBridge;

/// The wintun adapter GUID every FCAE TUN engine pins.
///
/// Wintun identifies an adapter by name *and* GUID: the GUID decides the NLA
/// entry and the NetCfgInstanceId, so a stable one keeps the firewall profile,
/// DNS assignment and registered-network settings across engines, sessions and
/// reinstalls, and makes repeated creation idempotent instead of accruing
/// `FCAE_VPN 2`, `FCAE_VPN 3` duplicates. `fcae-bridge-tun2socks` passes it in
/// the device URL and `fcae-bridge-zeptun` through `zeptun_set_adapter_guid`;
/// the Windows sidecar hands it to the engine as `tunnel.guid` (the copy in its
/// hardcoded config is checked against this constant at compile time).
pub const WINTUN_ADAPTER_GUID: &str = "24198F4C-7895-434C-AD65-9E29A92DDC61";

/// True when this build can actually run the engine: the C engine is linked in,
/// or (Windows) the sidecar executable is beside the running binary.
pub fn is_supported() -> bool {
    #[cfg(all(windows, hev_sidecar))]
    {
        return sidecar::is_available();
    }
    #[cfg(not(all(windows, hev_sidecar)))]
    {
        engine::is_supported()
    }
}

/// Traffic statistics from the engine.
///
/// The in-process backend reads the engine's counters directly. The Windows
/// sidecar reports `None`: the counters live in the engine process and the
/// engine's CLI exposes no channel for them.
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
