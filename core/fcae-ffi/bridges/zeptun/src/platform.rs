//! Platform glue for the zeptun bridge.
//!
//! Deliberately thin: on desktop the shared runtime guards (`windows_tun`,
//! `unix_tun`) own addressing, routes and DNS, and on Android the VpnService
//! owns the device. The admin/root probe lives in [`fcae_runtime::privilege`];
//! the Wintun DLL loader lives in [`fcae_runtime::windows_dll`].

/// True when building for the mobile preset (Android: VpnService-created fd).
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// Close the device-fd dup after a failed `zeptun_create`: the engine never
/// saw it, so ownership is still ours.
pub fn close_dup(source: Option<i32>, config: &super::ZeptunConfig) {
    if source.is_some() && config.tun_fd >= 0 {
        unsafe { libc::close(config.tun_fd) };
    }
}
