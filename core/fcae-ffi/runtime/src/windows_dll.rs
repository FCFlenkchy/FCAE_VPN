use std::ffi::{CStr, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::LibraryLoader::{
    AddDllDirectory, GetProcAddress, LoadLibraryExW, SetDefaultDllDirectories,
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::error::{CoreError, Result};

pub struct Library {
    module: usize,
    _files: Vec<File>,
}

impl Library {
    fn load(path: &OsStr, flags: u32, files: Vec<File>) -> Result<Self> {
        let wide: Vec<u16> = path.encode_wide().chain(Some(0)).collect();
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags) };
        if module.is_null() {
            return Err(CoreError::Internal(format!(
                "cannot load {}: {}", path.to_string_lossy(), std::io::Error::last_os_error()
            )));
        }
        Ok(Self { module: module as usize, _files: files })
    }

    pub fn system(name: &str) -> Result<Self> {
        Self::load(OsStr::new(name), LOAD_LIBRARY_SEARCH_SYSTEM32, Vec::new())
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let path = path.canonicalize().map_err(|e| {
            CoreError::Internal(format!("cannot resolve {}: {e}", path.display()))
        })?;
        Self::load(path.as_os_str(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32, Vec::new())
    }

    /// The requested type must match the exported function's ABI and signature.
    pub unsafe fn symbol<T: Copy>(&self, name: &CStr) -> Result<T> {
        let proc = GetProcAddress(self.module as HMODULE, name.as_ptr().cast()).ok_or_else(|| {
            CoreError::Internal(format!("missing DLL export {}: {}", name.to_string_lossy(), std::io::Error::last_os_error()))
        })?;
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&proc));
        Ok(std::mem::transmute_copy(&proc))
    }

    pub fn embedded(label: &str, files: &[(&str, &[u8])], entry: &str) -> Result<Self> {
        if !files.iter().any(|(name, _)| *name == entry) {
            return Err(CoreError::Internal("embedded DLL entry is missing".into()));
        }
        let files = EmbeddedFiles::stage(label, files)?;
        register_search_directory(&files.dir);
        Self::load(files.dir.join(entry).as_os_str(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32, files.locks)
    }

}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module as HMODULE); }
    }
}

pub struct EmbeddedFiles {
    dir: PathBuf,
    locks: Vec<File>,
}

impl EmbeddedFiles {
    /// Unpacks `files` into `deps/<label>-<digest>/` beside the app (the temp
    /// directory when that is unusable) and holds them write-locked. Distinct
    /// byte sets get distinct folders, since a loaded copy cannot be replaced.
    pub fn stage(label: &str, files: &[(&str, &[u8])]) -> Result<Self> {
        let mut hash = Sha256::new();
        for (name, bytes) in files {
            if Path::new(name).file_name() != Some(OsStr::new(name)) {
                return Err(CoreError::Internal("invalid embedded filename".into()));
            }
            hash.update((name.len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        let digest = hash.finalize();
        let name = format!("{label}-{:016x}", u64::from_be_bytes(digest[..8].try_into().expect("32-byte digest")));
        let dir = match crate::deps::dir() {
            Some(deps) => deps.join(name),
            None => std::env::temp_dir().join("FCAE_VPN").join("native").join(name),
        };
        std::fs::create_dir_all(&dir).map_err(|e| {
            CoreError::Internal(format!("cannot create {}: {e}", dir.display()))
        })?;
        let mut locks = Vec::with_capacity(files.len());
        for (name, bytes) in files { locks.push(stage(&dir.join(name), bytes)?); }
        prune(label, &dir);
        Ok(Self { dir, locks })
    }

    pub fn directory(&self) -> &Path { &self.dir }
}

/// Delete the copies of a staged label that this build no longer uses.
///
/// The folder is named after the bytes it holds, which is what lets two
/// versions coexist without either being able to replace a mapped DLL -- and
/// what makes every update leave the previous one behind. A single-file app
/// that unpacks native libraries must not turn into a folder of them: an old
/// `wintun-<digest>/wintun.dll` is dead weight, and a pile of unsigned DLLs
/// beside the executable is exactly what a heuristic scanner counts.
///
/// Only directories this staging code could have created are touched -- the
/// label, a dash and sixteen hex digits -- and nothing here is fatal: a copy an
/// older instance still has mapped cannot be deleted on Windows, and that is
/// the one case where leaving it is right.
fn prune(label: &str, current: &Path) {
    let Some(parent) = current.parent() else { return };
    let prefix = format!("{label}-");
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.as_path() == current || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Some(digest) = path
            .file_name()
            .and_then(|sibling| sibling.to_str())
            .and_then(|sibling| sibling.strip_prefix(prefix.as_str()))
        else {
            continue;
        };
        if digest.len() != 16 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => log::info!("[deps] removed superseded {}", path.display()),
            Err(error) => log::debug!("[deps] kept {}: {error}", path.display()),
        }
    }
}

fn verified(path: &Path, bytes: &[u8]) -> std::io::Result<File> {
    let mut file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)?;
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "embedded DLL size mismatch"));
    }
    let mut buffer = [0u8; 65536];
    for expected in bytes.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..expected.len()])?;
        if &buffer[..expected.len()] != expected {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "embedded DLL content mismatch"));
        }
    }
    Ok(file)
}

fn stage(path: &Path, bytes: &[u8]) -> Result<File> {
    if let Ok(file) = verified(path, bytes) { return Ok(file); }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let staged: PathBuf = path.with_extension(format!("{}.{}.tmp", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let result = (|| -> std::io::Result<File> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = std::fs::rename(&staged, path) {
            // A concurrent process may have published and locked the same bytes.
            return verified(path, bytes).map_err(|_| error);
        }
        verified(path, bytes)
    })();
    let _ = std::fs::remove_file(&staged);
    result.map_err(|e| CoreError::Internal(format!("cannot stage {}: {e}", path.display())))
}

/// Make the staged copy answer to the bare name every engine loads:
/// `LoadLibraryExW(L"wintun.dll", …, APPLICATION_DIR | SYSTEM32)` in zeptun,
/// hev and Go's wintun bindings. Those flags exclude user directories, so the
/// directory is registered and the process defaults are widened to include
/// them; the module this process already loaded by full path still wins the
/// name lookup, which is what the engines then reach.
fn register_search_directory(dir: &Path) {
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) == 0 {
            log::warn!("[tun] cannot set the DLL search directories: {}", std::io::Error::last_os_error());
            return;
        }
        if AddDllDirectory(wide.as_ptr()).is_null() {
            log::warn!("[tun] cannot register {} for DLL search: {}", dir.display(), std::io::Error::last_os_error());
        }
    }
}

/// Wintun reports driver and device failures only through its own logger;
/// without it a failed `WintunCreateAdapter` leaves a bare Win32 code.
extern "system" fn relay(level: i32, _timestamp: u64, message: *const u16) {
    if message.is_null() { return; }
    let mut len = 0;
    while unsafe { *message.add(len) } != 0 { len += 1; }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(message, len) });
    match level {
        0 => log::info!("[wintun] {text}"),
        1 => log::warn!("[wintun] {text}"),
        _ => log::error!("[wintun] {text}"),
    }
}

type Logger = extern "system" fn(i32, u64, *const u16);
type SetLogger = unsafe extern "system" fn(logger: Option<Logger>);
type DriverVersion = unsafe extern "system" fn() -> u32;

/// Attach the logger and report the loaded driver, so the adapter step an
/// engine fails in is visible in the app log.
fn instrument(library: &Library) {
    match unsafe { library.symbol::<SetLogger>(c"WintunSetLogger") } {
        Ok(set) => unsafe { set(Some(relay)) },
        Err(error) => log::debug!("[tun] Wintun has no logger: {error}"),
    }
    match unsafe { library.symbol::<DriverVersion>(c"WintunGetRunningDriverVersion") }.map(|version| unsafe { version() }) {
        Ok(0) => log::debug!("[tun] no Wintun driver loaded yet"),
        Ok(version) => log::info!("[tun] Wintun driver {}.{} already running", version >> 16, version & 0xffff),
        Err(error) => log::debug!("[tun] Wintun driver version unavailable: {error}"),
    }
}

static WINTUN: OnceLock<std::result::Result<Library, String>> = OnceLock::new();

pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> Result<()> {
    WINTUN.get_or_init(|| {
        log::info!("[tun] initializing Wintun ({})", if bytes.is_some() { "embedded" } else { "application/system search" });
        let library = if let Some(bytes) = bytes {
            Library::embedded("wintun", &[("wintun.dll", bytes)], "wintun.dll")
        } else {
            Library::load(OsStr::new("wintun.dll"), LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32, Vec::new())
        };
        match &library {
            Ok(library) => {
                instrument(library);
                log::info!("[tun] Wintun library loaded");
            }
            Err(error) => log::error!("[tun] Wintun library load failed: {error}"),
        }
        library.map_err(|e| e.to_string())
    }).as_ref().map(|_| ()).map_err(|e| CoreError::Internal(e.clone()))
}

/// Resolve the LUID from the Wintun adapter the selected engine actually
/// opened, rather than assuming Windows used the requested creation GUID.
pub fn wintun_adapter_luid(name: &str) -> Result<windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH> {
    use std::ffi::c_void;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    let library = WINTUN.get().and_then(|result| result.as_ref().ok())
        .ok_or_else(|| CoreError::Internal("Wintun has not been loaded".into()))?;
    type Open = unsafe extern "system" fn(*const u16) -> *mut c_void;
    type GetLuid = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
    type Close = unsafe extern "system" fn(*mut c_void);
    let open: Open = unsafe { library.symbol(CStr::from_bytes_with_nul(b"WintunOpenAdapter\0").unwrap())? };
    let get_luid: GetLuid = unsafe { library.symbol(CStr::from_bytes_with_nul(b"WintunGetAdapterLUID\0").unwrap())? };
    let close: Close = unsafe { library.symbol(CStr::from_bytes_with_nul(b"WintunCloseAdapter\0").unwrap())? };
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let adapter = unsafe { open(name.as_ptr()) };
    if adapter.is_null() {
        return Err(CoreError::Internal(format!("cannot open the engine's Wintun adapter: {}", std::io::Error::last_os_error())));
    }
    let mut luid = NET_LUID_LH::default();
    unsafe { get_luid(adapter, &mut luid); close(adapter); }
    Ok(luid)
}

static DRIVER_RESET: OnceLock<std::result::Result<(), String>> = OnceLock::new();

/// Drop the stored Wintun driver so the next create installs the copy embedded
/// in this build.
///
/// Wintun replaces a stored driver only with a newer one, so a package that
/// cannot install a device fails every adapter with problem 31 and survives
/// every retry, reboot included. `WintunDeleteDriver` removes the adapters it
/// left in a problem state and then uninstalls the package. Once per process.
fn reset_driver() -> Result<()> {
    DRIVER_RESET
        .get_or_init(|| {
            type DeleteDriver = unsafe extern "system" fn() -> i32;
            let library = WINTUN
                .get()
                .and_then(|result| result.as_ref().ok())
                .ok_or_else(|| "Wintun has not been loaded".to_string())?;
            let delete: DeleteDriver = unsafe { library.symbol(c"WintunDeleteDriver") }.map_err(|e| e.to_string())?;
            if unsafe { delete() } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            log::info!("[tun] Wintun driver removed; the next adapter installs the embedded copy");
            Ok(())
        })
        .clone()
        .map_err(CoreError::Internal)
}

/// Run an adapter-creating start, reinstalling the Wintun driver once when the
/// adapter never appeared.
///
/// Every engine reports a failed device install as a bare start error, so the
/// missing adapter is the signal: when the adapter is openable the failure was
/// somewhere else and the driver stays untouched.
pub fn start_with_driver_repair<T>(adapter: &str, start: impl Fn() -> Result<T>) -> Result<T> {
    let error = match start() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if wintun_adapter_luid(adapter).is_ok() {
        return Err(error);
    }
    log::warn!("[tun] no Wintun adapter '{adapter}' after a failed start ({error}); reinstalling the driver");
    match reset_driver() {
        Ok(()) => {}
        Err(reset) => {
            log::error!("[tun] cannot reinstall the Wintun driver: {reset}");
            return Err(error);
        }
    }
    let retried = start();
    if retried.is_err() {
        log::error!(
            "[tun] '{adapter}' still cannot be installed; Windows is refusing the Wintun driver \
             (a device left in problem state may need removing by hand)"
        );
    }
    retried
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_rejects_same_length_corruption() {
        let path = std::env::temp_dir().join(format!("fcae-dll-test-{}", std::process::id()));
        std::fs::write(&path, b"wrong").unwrap();
        assert!(verified(&path, b"right").is_err());
        std::fs::write(&path, b"right").unwrap();
        drop(verified(&path, b"right").unwrap());
        std::fs::remove_file(path).unwrap();
    }
}
