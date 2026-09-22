//! Platform glue for the zeptun bridge.
//!
//! Deliberately thin: zeptun configures address/routes/DNS itself on desktop
//! (`configure`/`auto_route`), and on Android the VpnService owns the device,
//! so there is none of the shell-out undo machinery tun2socks needs.

/// True when building for the mobile preset (Android: VpnService-created fd).
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// 1.3.5.4 PATCH: zeptun creates its TUN device in-process via Wintun /
/// the Linux/Android kernel TUN driver; both require admin / root. Mirror
/// the tun2socks check so `fcae_is_privileged()` reports admin status for
/// every TUN engine that is actually linked into this build. The simpler
/// `geteuid` / `net session` probes are good enough: this only decides
/// whether the C++ frontend shows the UAC elevation prompt, and the
/// engine will surface a precise error if the answer is wrong.
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
