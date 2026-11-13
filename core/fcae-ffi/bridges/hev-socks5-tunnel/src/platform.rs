//! Windows Wintun staging for the HEV engine (the engine LoadLibraryExW's
//! "wintun.dll" from the application directory or System32). The admin/root
//! probe lives in [`fcae_runtime::privilege`]; the DLL loader itself lives in
//! [`fcae_runtime::windows_dll`].

#[cfg(all(windows, wintun_staged))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    Some(include_bytes!(env!("FCAE_HEV_WINTUN_DLL")))
}

#[cfg(all(windows, not(wintun_staged)))]
pub fn wintun_bytes() -> Option<&'static [u8]> {
    None
}
