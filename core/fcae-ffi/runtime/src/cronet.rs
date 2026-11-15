//! The embedded `libcronet.dll`: the Chromium network stack sing-box's naive
//! outbound calls.
//!
//! Windows is the one platform where cronet cannot live inside the executable.
//! cronet-go publishes Linux and macOS as static archives, but Windows only as a
//! DLL (Chromium is built with MSVC there, and a cgo link can only use MinGW), so
//! the DLL travels inside the executable and is unpacked at run time — the same
//! arrangement as `wintun.dll` in [`crate::windows_dll`].
//!
//! Unpacking is not enough on its own: cronet-go's purego loader looks for the
//! DLL in the executable's directory and in `PATH`, nothing else. Hence
//! [`prepare`], which stages the DLL and puts its folder on `PATH` before
//! sing-box is started — before, because the Go side caches its first load
//! attempt, failures included.
//!
//! On the platforms that link cronet — Linux, macOS, Android — none of this
//! applies and [`CRONET_AVAILABLE`] is false.

#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::sync::OnceLock;

/// Bytes of the staged `libcronet.dll`, for Windows builds whose build script
/// staged one.
#[cfg(all(windows, cronet_staged))]
static CRONET_DLL: &[u8] = include_bytes!(env!("FCAE_CRONET_DLL"));

/// True when a `libcronet.dll` was embedded at build time.
pub const CRONET_AVAILABLE: bool = cfg!(all(windows, cronet_staged));

/// Bytes of the staged `libcronet.dll`, or `None` when this build embedded none.
#[cfg(all(windows, cronet_staged))]
pub fn cronet_bytes() -> Option<&'static [u8]> {
    Some(CRONET_DLL)
}

/// Bytes of the staged `libcronet.dll`, or `None` when this build embedded none.
#[cfg(not(all(windows, cronet_staged)))]
pub fn cronet_bytes() -> Option<&'static [u8]> {
    None
}

/// Unpack the embedded `libcronet.dll` and make it findable, once per process.
///
/// Returns whether the DLL is in place. A build that embedded none reports
/// `false`, and so does a failed unpack; a naive outbound then reports the
/// library as missing, which is what happened before the DLL was embedded.
/// The staged files stay write-locked for the life of the process, so a second
/// instance cannot replace a DLL this one has already loaded.
#[cfg(windows)]
pub fn prepare() -> bool {
    static STAGED: OnceLock<Option<crate::windows_dll::EmbeddedFiles>> = OnceLock::new();
    STAGED
        .get_or_init(|| {
            let staged = match cronet_bytes() {
                Some(bytes) => {
                    crate::windows_dll::EmbeddedFiles::stage("cronet", &[("libcronet.dll", bytes)])
                }
                None => return None,
            };
            let staged = match staged {
                Ok(staged) => staged,
                Err(error) => {
                    log::warn!("[cronet] cannot unpack libcronet.dll: {error}");
                    return None;
                }
            };
            if !expose(staged.directory()) {
                log::warn!(
                    "[cronet] cannot make {} searchable; sing-box's naive outbound will not load",
                    staged.directory().display()
                );
                return None;
            }
            log::info!("[cronet] libcronet.dll ready in {}", staged.directory().display());
            Some(staged)
        })
        .is_some()
}

/// Prepend `dir` to this process's `PATH`: that, and the executable's own
/// directory, is all cronet-go's loader searches. The Go side reads `PATH` when
/// it loads, so this has to happen before the first naive start — [`prepare`]
/// runs from exactly there.
#[cfg(windows)]
fn expose(dir: &Path) -> bool {
    use windows_sys::Win32::System::Environment::{
        GetEnvironmentVariableW, SetEnvironmentVariableW,
    };

    if !dir.is_dir() {
        return false;
    }
    let dir = dir.to_string_lossy();
    let name = wide("PATH");

    // The value can grow between the sizing call and the read, so read in a
    // loop until the buffer was large enough.
    let mut len = 4096usize;
    let current = loop {
        let mut buffer = vec![0u16; len];
        let written = unsafe {
            GetEnvironmentVariableW(name.as_ptr(), buffer.as_mut_ptr(), len as u32)
        };
        if written == 0 {
            return false;
        }
        let written = written as usize;
        if written < len {
            buffer.truncate(written);
            break String::from_utf16_lossy(&buffer);
        }
        len = written + 1;
    };

    let updated = if current.is_empty() {
        dir.into_owned()
    } else {
        format!("{dir};{current}")
    };
    let updated = wide(&updated);
    unsafe { SetEnvironmentVariableW(name.as_ptr(), updated.as_ptr()) != 0 }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Nothing to unpack where cronet is linked in.
#[cfg(not(windows))]
pub fn prepare() -> bool {
    CRONET_AVAILABLE
}
