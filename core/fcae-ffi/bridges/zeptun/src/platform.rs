//! Platform glue for the zeptun bridge.
//!
//! Deliberately thin: zeptun configures address/routes/DNS itself on desktop
//! (`configure`/`auto_route`), and on Android the VpnService owns the device,
//! so there is none of the shell-out undo machinery tun2socks needs.

/// True when building for the mobile preset (Android: VpnService-created fd).
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// Make `wintun.dll` available to the loader inside the zeptun engine.
///
/// zeptun resolves it with
/// `LoadLibraryExW("wintun.dll", LOAD_LIBRARY_SEARCH_APPLICATION_DIR | SEARCH_SYSTEM32)`,
/// so the DLL must sit beside the executable (or in the data dir fallback
/// below). Mirrors the tun2socks bridge's staging, byte for byte the stock
/// driver — both engines share the "Wintun" adapter pool and, by adapter
/// name, the same physical device and GUID.
#[cfg(windows)]
pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> fcae_runtime::error::Result<()> {
    use fcae_runtime::error::CoreError;
    use std::io::Write;

    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir);
    let dest = dir.join("wintun.dll");

    if dest.is_file() {
        return Ok(());
    }

    if let Some(bytes) = bytes {
        if let Ok(mut f) = std::fs::File::create(&dest) {
            if f.write_all(bytes).is_ok() {
                log::info!("[tun] wintun.dll written to {}", dest.display());
                return Ok(());
            }
        }
        // Executable directory may be read-only (Program Files); fall back.
        let alt = std::env::temp_dir().join("fcaevpn");
        let _ = std::fs::create_dir_all(&alt);
        let alt_dll = alt.join("wintun.dll");
        if !alt_dll.is_file() {
            std::fs::write(&alt_dll, bytes).map_err(|e| {
                CoreError::Internal(format!("cannot write wintun.dll to {}: {e}", alt.display()))
            })?;
        }
        let path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{};{path}", alt.display()));
        log::info!("[tun] wintun.dll staged in {}", alt.display());
        return Ok(());
    }

    if std::path::Path::new("C:\\Windows\\System32\\wintun.dll").is_file() {
        return Ok(());
    }

    Err(CoreError::Internal(
        "wintun.dll is missing. Download it from https://www.wintun.net/ and place it \
         next to the executable."
            .into(),
    ))
}

#[cfg(not(windows))]
pub fn ensure_wintun(_bytes: Option<&'static [u8]>) -> fcae_runtime::error::Result<()> {
    Ok(())
}

/// Close the device-fd dup after a failed `zeptun_create`: the engine never
/// saw it, so ownership is still ours.
pub fn close_dup(source: Option<i32>, config: &super::ZeptunConfig) {
    if source.is_some() && config.tun_fd >= 0 {
        unsafe { libc::close(config.tun_fd) };
    }
}
