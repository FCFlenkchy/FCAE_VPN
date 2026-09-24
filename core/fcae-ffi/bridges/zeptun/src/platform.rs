//! Platform glue for the zeptun bridge.
//!
//! Deliberately thin: zeptun configures address/routes/DNS itself on desktop
//! (`configure`/`auto_route`), and on Android the VpnService owns the device,
//! so there is none of the shell-out undo machinery tun2socks needs.

/// True when building for the mobile preset (Android: VpnService-created fd).
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// zeptun creates its TUN device in-process through Wintun / the kernel TUN
/// driver; both need admin / root. Mirrors the tun2socks check so
/// `fcae_is_privileged()` answers for every TUN engine linked into the build.
/// The coarse `geteuid` / `net session` probes are enough: this only decides
/// whether the frontend shows its elevation prompt, and the engine reports a
/// precise error when the answer is wrong.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid is async-signal safe and takes no args.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Same cheap probe as tun2socks: opening PHYSICALDRIVE0 succeeds only
        // for Administrators, and `net session` lists only admin sessions.
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

#[cfg(windows)]
pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> fcae_runtime::error::Result<()> {
    fcae_runtime::windows_dll::ensure_wintun(bytes)
}

/// Close the device-fd dup after a failed `zeptun_create`: the engine never
/// saw it, so ownership is still ours.
pub fn close_dup(source: Option<i32>, config: &super::ZeptunConfig) {
    if source.is_some() && config.tun_fd >= 0 {
        unsafe { libc::close(config.tun_fd) };
    }
}
