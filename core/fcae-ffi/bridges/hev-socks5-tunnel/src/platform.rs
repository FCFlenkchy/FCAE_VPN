//! Platform glue for the hev-socks5-tunnel bridge.

/// 1.3.5.4 PATCH: hev-socks5-tunnel runs as an in-process DLL/so on every
/// platform and opens its own TUN device. The C++ frontend calls
/// `fcae_is_privileged()` to decide whether to elevate first; with this
/// bridge alone linked (no `tun2socks`), that probe would have fallen
/// through to `false` and the user would see a confusing ERROR after
/// CONNECT instead of a clean UAC prompt. Match the tun2socks/zeptun
/// heuristic.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid is async-signal safe and takes no args.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
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
