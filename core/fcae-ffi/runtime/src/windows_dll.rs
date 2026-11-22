use std::ffi::{CStr, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use windows_sys::core::GUID;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DiUninstallDevice, SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiSetClassInstallParamsW, DIF_REMOVE,
    DI_REMOVEDEVICE_GLOBAL, GUID_DEVCLASS_NET, HDEVINFO, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA,
    SP_REMOVEDEVICE_PARAMS,
};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceGuidToLuid, FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::System::LibraryLoader::{
    AddDllDirectory, GetModuleFileNameW, GetProcAddress, LoadLibraryExW, SetDefaultDllDirectories,
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
    // Every engine opens the adapter before creating it, so the first call of
    // each session always misses; the create that follows is the real step.
    if text.starts_with("Failed to find matching adapter name") {
        log::debug!("[wintun] {text}");
        return;
    }
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

const ADAPTER_GUID: GUID = GUID::from_u128(crate::config::WINTUN_ADAPTER_GUID_U128);

/// `SetupDiGetClassDevsW` failure value (`INVALID_HANDLE_VALUE`).
const INVALID_DEVINFO: HDEVINFO = -1;

/// Whether Windows has an interface for the adapter, by the pinned GUID or by
/// the name the engine gave Wintun: the state a failed device install never
/// reaches.
fn adapter_present(adapter: &str) -> bool {
    let mut luid = NET_LUID_LH::default();
    if unsafe { ConvertInterfaceGuidToLuid(&ADAPTER_GUID, &mut luid) == 0 } {return true;}
    let mut table:*mut MIB_IF_TABLE2=std::ptr::null_mut();
    // An enumeration failure is unknown state, not proof of an absent device.
    if unsafe{GetIfTable2(&mut table)}!=0||table.is_null(){return true;}
    let wanted:Vec<u16>=adapter.encode_utf16().collect();
    let present=unsafe{
        let rows=std::slice::from_raw_parts((*table).Table.as_ptr(),(*table).NumEntries as usize);
        rows.iter().any(|row|{
            let length=row.Alias.iter().position(|v|*v==0).unwrap_or(row.Alias.len());
            let id=&row.InterfaceGuid;
            row.Alias[..length]==wanted[..] || (id.data1==ADAPTER_GUID.data1 && id.data2==ADAPTER_GUID.data2 && id.data3==ADAPTER_GUID.data3 && id.data4==ADAPTER_GUID.data4)
        })
    };
    unsafe{FreeMibTable(table.cast())};present
}

/// Wintun names every device instance after the requested creation GUID, and
/// every engine asks for the same one, so the GUID identifies the node across
/// the enumerator spellings Windows uses (`SWD\Wintun{…}` on Windows 10,
/// `ROOT\WINTUN\{…}` on Windows 7).
fn owns_instance(instance: &str) -> bool {
    { let id=instance.to_ascii_uppercase();
    (id.starts_with("SWD\\WINTUN") || id.starts_with("ROOT\\WINTUN"))
        && id.contains(crate::config::WINTUN_ADAPTER_GUID) }
}

/// Uninstall the Wintun device instances of this GUID that exist without an
/// interface, and report whether one was removed.
///
/// Such a node is a failed install Windows cannot bind again: every later
/// create re-uses it and fails with problem 31 and `STATUS_OBJECT_NAME_NOT_FOUND`
/// (Win32 2) before the engine can start, driver reinstall included. Wintun
/// clears these itself, but only from a work item queued by its own create and
/// close paths, so a device left by an interrupted install outlives the process
/// that could have removed it. Only instances with no interface are touched, so
/// a healthy adapter of a running session is never a candidate.
fn remove_unusable_adapter(adapter: &str) -> bool {
    if adapter_present(adapter) { return false; }
    let removed = remove_instances();
    if removed > 0 {
        log::info!("[tun] uninstalled {removed} Wintun device(s) for '{adapter}' that Windows could not bind");
    }
    removed > 0
}

fn remove_instances() -> usize {
    // Enumerate the class, not a partial device-instance path masquerading as
    // an enumerator. Ownership is checked on each complete instance ID below.
    let devices = unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, std::ptr::null(), std::ptr::null_mut(), 0) };
    if devices == INVALID_DEVINFO { return 0; }
    let mut removed = 0;
    let mut index = 0;
    loop {
        let mut data: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
        if unsafe { SetupDiEnumDeviceInfo(devices, index, &mut data) } == 0 { break; }
        index += 1;
        let mut id = [0u16; 512];
        if unsafe { SetupDiGetDeviceInstanceIdW(devices, &data, id.as_mut_ptr(), id.len() as u32, std::ptr::null_mut()) } == 0 {
            continue;
        }
        let len = id.iter().position(|unit| *unit == 0).unwrap_or(id.len());
        if !owns_instance(&String::from_utf16_lossy(&id[..len])) { continue; }
        if uninstall(devices, &data) { removed += 1; }
    }
    unsafe { SetupDiDestroyDeviceInfoList(devices) };
    removed
}

fn uninstall(devices: HDEVINFO, data: &SP_DEVINFO_DATA) -> bool {
    let mut reboot = 0;
    if unsafe { DiUninstallDevice(std::ptr::null_mut(), devices, data, 0, &mut reboot) } != 0 {
        if reboot != 0 { log::info!("[tun] a restart is needed to finish removing the Wintun device"); }
        return true;
    }
    // The class installer's remove is what Wintun itself uses.
    let params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };
    let size = std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32;
    let removed = unsafe {
        SetupDiSetClassInstallParamsW(devices, data, &params.ClassInstallHeader, size) != 0
            && SetupDiCallClassInstaller(DIF_REMOVE, devices, data) != 0
    };
    if !removed {
        log::warn!("[tun] cannot uninstall the unusable Wintun device: {}", std::io::Error::last_os_error());
    }
    removed
}

// No driver-package deletion: it is shared with other VPN applications.
// A replacement is scoped to the exact FCAE GUID and requested alias and only
// when Windows reports that it has no packet session attached.
fn owned_disconnected_adapter(adapter: &str) -> bool {
    use windows_sys::Win32::NetworkManagement::Ndis::MediaConnectStateDisconnected;
    let mut owned = NET_LUID_LH::default();
    if unsafe { ConvertInterfaceGuidToLuid(&ADAPTER_GUID, &mut owned) } != 0 {
        return false;
    }
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
        return false;
    }
    let wanted: Vec<u16> = adapter.encode_utf16().collect();
    let disconnected = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        rows.iter().any(|row| {
            let length = row
                .Alias
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(row.Alias.len());
            row.InterfaceLuid.Value == owned.Value
                && row.Alias[..length] == wanted[..]
                && row.MediaConnectState == MediaConnectStateDisconnected
        })
    };
    unsafe { FreeMibTable(table.cast()) };
    disconnected
}
fn adapter_start_error(error: &CoreError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    if [
        "access denied",
        "access is denied",
        "permission",
        "already running",
        "in use",
        "sharing violation",
        "configuration",
        "invalid config",
    ]
    .iter()
    .any(|text| message.contains(text))
    {
        return false;
    }
    [
        "wintun",
        "adapter",
        "create tun",
        "creating tun",
        "tun interface",
        "device install",
    ]
    .iter()
    .any(|text| message.contains(text))
}
/// One bounded, adapter-local recovery path shared by every Windows TUN
/// engine. The failing start must first release its partial core/handles.
pub fn start_with_adapter_repair<T>(
    adapter: &str,
    stopping: impl Fn() -> bool,
    start: impl Fn() -> Result<T>,
) -> Result<T> {
    let error = match start() {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if stopping() {
        return Err(error);
    }
    let removed;
    if adapter_present(adapter) {
        if !adapter_start_error(&error) || !owned_disconnected_adapter(adapter) {
            return Err(error);
        }
        log::warn!("[tun] replacing disconnected FCAE adapter '{adapter}' after adapter startup failure: {error}");
        // Recheck after logging and immediately before uninstalling.
        if stopping() || !owned_disconnected_adapter(adapter) {
            return Err(error);
        }
        removed = remove_instances() > 0;
        if !removed {
            return Err(error);
        }
        for _ in 0..40 {
            if stopping() {
                return Err(error);
            }
            if !adapter_present(adapter) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if adapter_present(adapter) {
            return Err(CoreError::StartFailed(format!("FCAE adapter removal is still pending; Windows may require a restart. Original failure: {error}")));
        }
    } else {
        removed = remove_unusable_adapter(adapter);
    }
    if !removed && !adapter_start_error(&error) {
        return Err(error);
    }
    if stopping() {
        return Err(error);
    }
    log::info!("[tun] retrying '{adapter}' once (FCAE adapter only; shared driver unchanged)");
    start().map_err(|retry|CoreError::StartFailed(format!("TUN startup failed after one adapter recovery attempt: {retry}; initial error: {error}")))
}

/// Resolve the LUID of the Wintun adapter the selected engine created, by its
/// interface name.
///
/// Read-only: `WintunCloseAdapter` uninstalls the device instance, so a lookup
/// that opened the adapter through Wintun would delete the adapter the engine
/// is using.
pub fn wintun_adapter_luid(name: &str) -> Result<NET_LUID_LH> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } != 0 {
        return Err(CoreError::Internal(format!(
            "cannot enumerate the network interfaces: {}",
            std::io::Error::last_os_error()
        )));
    }
    if table.is_null() { return Err(CoreError::Internal("Windows returned an empty interface table".into())); }
    let wanted: Vec<u16> = name.encode_utf16().collect();
    let found = (|| {
        let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        rows.iter().find_map(|row| {
            let len = row.Alias.iter().position(|unit| *unit == 0).unwrap_or(row.Alias.len());
            (row.Alias[..len] == wanted[..]).then_some(row.InterfaceLuid)
        })
    })();
    unsafe { FreeMibTable(table.cast()) };
    found.ok_or_else(|| CoreError::Internal(format!("no network interface named '{name}'")))
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

/// A separately refcounted handle to the exact image the host already loaded.
/// Zeptun releases its reference; the host retains its own for the process.
pub fn acquire_wintun_module() -> Result<HMODULE> {
    ensure_wintun(crate::wintun::wintun_bytes())?;
    let library=WINTUN.get().and_then(|result|result.as_ref().ok())
        .ok_or_else(||CoreError::Internal("shared Wintun module is unavailable".into()))?;
    let mut path=vec![0u16;32768];
    let length=unsafe{GetModuleFileNameW(library.module as HMODULE,path.as_mut_ptr(),path.len() as u32)};
    if length==0 || length as usize >= path.len() {
        return Err(CoreError::Internal(format!("cannot resolve shared Wintun image: {}",std::io::Error::last_os_error())));
    }
    let module=unsafe{LoadLibraryExW(path.as_ptr(),std::ptr::null_mut(),LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32)};
    if module.is_null() {return Err(CoreError::Internal(format!("cannot acquire shared Wintun image: {}",std::io::Error::last_os_error())));}
    Ok(module)
}
