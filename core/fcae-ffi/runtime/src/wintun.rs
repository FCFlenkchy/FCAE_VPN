//! Windows Wintun staging glue shared by the engine bridges.

/// Expands to the staged-`wintun.dll` byte slice and its accessor, shared by
/// the engine bridges that embed the driver at build time.
///
/// The consuming crate's `build.rs` must stage the DLL (see
/// `fcae_build::wintun::stage_and_emit`) and emit `cargo:rustc-cfg=wintun_staged`
/// plus `cargo:rustc-env` pointing at it; the crate must register
/// `cargo::rustc-check-cfg=cfg(wintun_staged)` — all three build scripts do.
/// On non-Windows or unstaged builds nothing is emitted, mirroring the
/// hand-written version this replaces.
///
/// Usage:
/// ```ignore
/// fcae_runtime::wintun_bytes!("FCAE_WINTUN_DLL");         // private accessor
/// fcae_runtime::wintun_bytes!(pub "FCAE_HEV_WINTUN_DLL"); // public accessor
/// ```
#[macro_export]
macro_rules! wintun_bytes {
    (@impl $vis:vis, $env:literal) => {
        #[cfg(all(windows, wintun_staged))]
        static WINTUN_DLL: &[u8] = include_bytes!(env!($env));

        #[cfg(all(windows, wintun_staged))]
        $vis fn wintun_bytes() -> Option<&'static [u8]> { Some(WINTUN_DLL) }

        #[cfg(all(windows, not(wintun_staged)))]
        $vis fn wintun_bytes() -> Option<&'static [u8]> { None }
    };
    ($env:literal) => { $crate::wintun_bytes!(@impl , $env); };
    (pub $env:literal) => { $crate::wintun_bytes!(@impl pub, $env); };
}
