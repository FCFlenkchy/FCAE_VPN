pub fn is_privileged() -> bool {
    #[cfg(unix)]
    { unsafe { libc::geteuid() == 0 } }
    #[cfg(windows)]
    { std::fs::OpenOptions::new().write(true).open("\\\\.\\PHYSICALDRIVE0").is_ok() }
    #[cfg(not(any(unix, windows)))]
    { false }
}

#[cfg(windows)]
pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> fcae_runtime::error::Result<()> {
    fcae_runtime::windows_dll::ensure_wintun(bytes)
}

#[cfg(all(windows, wintun_staged))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    Some(include_bytes!(env!("FCAE_HEV_WINTUN_DLL")))
}

#[cfg(all(windows, not(wintun_staged)))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    None
}
