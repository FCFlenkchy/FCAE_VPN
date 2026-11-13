//! The single embedded copy of `wintun.dll`, shared by every Windows TUN
//! engine (zeptun, tun2socks and hev-socks5-tunnel).
//!
//! The DLL is staged once, by this crate's `build.rs` (via
//! `fcae_build::wintun::stage_and_emit`, which downloads and verifies it at
//! build time), and embedded here under `FCAE_WINTUN_DLL`. The bridges embed
//! nothing; they call [`wintun_bytes()`].

/// Bytes of the staged wintun.dll. Present only on Windows builds where the
/// DLL staged successfully (`wintun_staged` cfg emitted by this crate's
/// `build.rs`).
#[cfg(all(windows, wintun_staged))]
static WINTUN_DLL: &[u8] = include_bytes!(env!("FCAE_WINTUN_DLL"));

/// True when a wintun.dll was embedded at build time.
pub const WINTUN_AVAILABLE: bool = cfg!(all(windows, wintun_staged));

/// Bytes of the staged wintun.dll, or `None` when this build embedded none.
#[cfg(all(windows, wintun_staged))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    Some(WINTUN_DLL)
}

/// Bytes of the staged wintun.dll, or `None` when this build embedded none.
#[cfg(not(all(windows, wintun_staged)))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    None
}
