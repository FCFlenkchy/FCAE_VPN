//! App-owned, demand-start kernel service. No command interpreter or external
//! installer is used. Existing services/catalogs are never adopted or replaced.
//! Caller must explicitly opt into the experimental pinned driver before use.
use super::windows_app_routing_driver::Driver;
use super::windows_split_driver_package::{bundled, verify_extracted, VerifiedPackage};
use std::{
    ffi::OsStr,
    fs::OpenOptions,
    io::{self, Write},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::*,
        Security::{Authorization::*, Cryptography::Catalog::*, *},
        Storage::FileSystem::*,
        System::{
            Rpc::{UuidCreate, RPC_S_UUID_LOCAL_ONLY},
            Services::*,
            SystemInformation::GetSystemDirectoryW,
        },
    },
};

const NAME: &str = "FCAESplitTunnel";
fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut v: Vec<_> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(io::Error::other("NUL in service path"));
    }
    v.push(0);
    Ok(v)
}
struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Catalog {
    admin: isize,
    context: isize,
}
impl Catalog {
    fn remove(&mut self) -> io::Result<()> {
        if self.context == 0 {
            return Ok(());
        }
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        if unsafe { CryptCATCatalogInfoFromContext(self.context, &mut info, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let end = info
            .wszCatalogFile
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| io::Error::other("unterminated catalog store path"))?;
        let start = info.wszCatalogFile[..end]
            .iter()
            .rposition(|c| *c == b'\\' as u16 || *c == b'/' as u16)
            .map_or(0, |n| n + 1);
        if start == end {
            return Err(io::Error::other("empty catalog basename"));
        }
        if unsafe {
            CryptCATAdminRemoveCatalog(self.admin, info.wszCatalogFile[start..].as_ptr(), 0)
        } == 0
        {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(),Some(x) if x==ERROR_FILE_NOT_FOUND as i32||x==ERROR_NOT_FOUND as i32||x==CRYPT_E_NOT_FOUND)
            {
                return Err(error);
            }
        }
        unsafe {
            CryptCATAdminReleaseCatalogContext(self.admin, self.context, 0);
        }
        self.context = 0;
        Ok(())
    }
}
impl Drop for Catalog {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            log::error!("[app-routing] catalog cleanup failed: {error}");
        }
        if self.context != 0 {
            unsafe {
                CryptCATAdminReleaseCatalogContext(self.admin, self.context, 0);
            }
        }
        unsafe {
            CryptCATAdminReleaseContext(self.admin, 0);
        }
    }
}

fn status(service: SC_HANDLE) -> io::Result<u32> {
    let mut value = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut value as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&value) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value.dwCurrentState)
}
fn wait(service: SC_HANDLE, target: u32) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let current = status(service)?;
        if current == target {
            return Ok(());
        }
        if Instant::now() >= deadline || (target == SERVICE_RUNNING && current == SERVICE_STOPPED) {
            return Err(io::Error::other(format!(
                "driver service did not reach state {target}; current state {current}"
            )));
        }
        thread::sleep(Duration::from_millis(50));
    }
}
fn private_directory() -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if n == 0 || n as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    use std::os::windows::ffi::OsStringExt;
    let system = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..n as usize]));
    let parent = system.join("drivers");
    // This is a system-owned parent, never a writable portable/cache directory.
    for ancestor in parent.ancestors() {
        let path = wide(ancestor.as_os_str())?;
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("unsafe system driver directory"));
        }
    }
    let mut id = GUID::default();
    let code = unsafe { UuidCreate(&mut id) };
    if code != 0 && code != RPC_S_UUID_LOCAL_ONLY {
        return Err(io::Error::other(
            "could not generate driver installation ID",
        ));
    }
    let suffix = format!(
        "FCAE-split-{:08x}-{:04x}-{:04x}-{:016x}",
        id.data1,
        id.data2,
        id.data3,
        u64::from_le_bytes(id.data4)
    );
    let path = parent.join(suffix);
    let path_w = wide(path.as_os_str())?;
    let sddl = wide(OsStr::new("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))?;
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(descriptor);
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // Never reuse an existing directory, even if its name looks app-owned.
    if unsafe { CreateDirectoryW(path_w.as_ptr(), &security) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(path)
}
fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn register_catalog(directory: &Path) -> io::Result<Catalog> {
    let mut admin = 0;
    let algorithm = wide(OsStr::new("SHA256"))?;
    if unsafe {
        CryptCATAdminAcquireContext2(&mut admin, ptr::null(), algorithm.as_ptr(), ptr::null(), 0)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut result = Catalog { admin, context: 0 };
    let path = wide(directory.join("mullvad-split-tunnel.cat").as_os_str())?;
    // UUID-specific basename prevents catalog-store replacement of another VPN.
    let name = directory
        .file_name()
        .ok_or_else(|| io::Error::other("missing driver directory name"))?
        .to_string_lossy();
    let basename = wide(OsStr::new(&format!("{name}.cat")))?;
    result.context = unsafe { CryptCATAdminAddCatalog(admin, path.as_ptr(), basename.as_ptr(), 0) };
    if result.context == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

pub struct OwnedDriverService {
    service: Option<Service>,
    catalog: Option<Catalog>,
    verified: Option<VerifiedPackage>,
    directory: PathBuf,
    // A running/unresponsive service must retain its image and trust material.
    may_be_running: bool,
    retain_directory: bool,
}
unsafe impl Send for OwnedDriverService {}
impl OwnedDriverService {
    pub fn install_experimental(acknowledge_kernel_crash_risk: bool) -> io::Result<Self> {
        if !acknowledge_kernel_crash_risk {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,"experimental driver requires explicit acknowledgement of upstream crash report #11487"));
        }
        if !crate::privilege::is_privileged() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "driver installation requires administrator permission",
            ));
        }
        let bundle = bundled().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no verified driver package was embedded in this build",
            )
        })?;
        let manager = Service(unsafe {
            OpenSCManagerW(
                ptr::null(),
                ptr::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        });
        if manager.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        // Refuse coexistence, including a stopped installation. Never stop,
        // reset, upgrade or delete services that this invocation did not create.
        for name in [NAME, "mullvad-split-tunnel"] {
            let name = wide(OsStr::new(name))?;
            let existing = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
            if !existing.is_null() {
                drop(Service(existing));
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another split driver installation exists; it was left untouched",
                ));
            }
            let code = unsafe { GetLastError() };
            if code != ERROR_SERVICE_DOES_NOT_EXIST {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        let directory = private_directory()?;
        let mut result = Self {
            service: None,
            catalog: None,
            verified: None,
            directory,
            may_be_running: false,
            retain_directory: false,
        };
        crate::windows_app_routing_journal::create(&result.directory)?;
        for artifact in [&bundle.sys, &bundle.inf, &bundle.cat] {
            write_new(&result.directory, artifact.name, artifact.bytes)?;
        }
        write_new(
            &result.directory,
            "LICENSE-MPL.txt",
            bundle.license.as_bytes(),
        )?;
        result.verified = Some(verify_extracted(&result.directory)?);
        result.catalog = Some(register_catalog(&result.directory)?);
        let name = wide(OsStr::new(NAME))?;
        let display = wide(OsStr::new("FCAE experimental application routing"))?;
        let binary = wide(OsStr::new(&format!(
            "\\??\\{}",
            result.directory.join(bundle.sys.name).display()
        )))?;
        let service = unsafe {
            CreateServiceW(
                manager.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                binary.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        if service.is_null() {
            return Err(io::Error::last_os_error());
        }
        result.service = Some(Service(service));
        // Even a failed start can leave a pending service. Observe state before
        // deciding it is safe to delete the catalog or image.
        result.may_be_running = true;
        if unsafe { StartServiceW(service, 0, ptr::null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        wait(service, SERVICE_RUNNING)?;
        Ok(result)
    }
    pub(super) fn retain_for_recovery(&mut self) {
        self.retain_directory = true;
    }
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn open_driver(&self) -> io::Result<Driver> {
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| io::Error::other("driver service is closed"))?;
        if status(service.0)? != SERVICE_RUNNING {
            return Err(io::Error::other("driver service is not running"));
        }
        Driver::open_started()
    }
    /// Drop the provider/device before stopping its service.
    pub fn stop(&mut self) -> io::Result<()> {
        if let Some(service) = &self.service {
            if self.may_be_running && status(service.0)? != SERVICE_STOPPED {
                let mut status = SERVICE_STATUS::default();
                if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                        return Err(error);
                    }
                }
                wait(service.0, SERVICE_STOPPED)?;
            }
            self.may_be_running = false;
            if unsafe { DeleteService(service.0) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.service.take();
        self.verified.take();
        if let Some(catalog) = self.catalog.as_mut() {
            catalog.remove()?;
        }
        self.catalog.take();
        if !self.retain_directory && self.directory.exists() {
            std::fs::remove_dir_all(&self.directory)?;
        }
        Ok(())
    }
}
impl Drop for OwnedDriverService {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            log::error!("[app-routing] driver service cleanup incomplete: {error}; retaining protected package at {}",self.directory.display());
            // Keep catalog registration if a kernel service may still need it.
            // Process exit releases verification file handles, not kernel state.
            if self.may_be_running {
                if let Some(catalog) = self.catalog.take() {
                    std::mem::forget(catalog);
                }
            }
        }
    }
}

fn configured_image(service: SC_HANDLE) -> io::Result<Vec<u16>> {
    let mut needed = 0;
    unsafe {
        QueryServiceConfigW(service, ptr::null_mut(), 0, &mut needed);
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || needed as usize > 65536
        || (needed as usize) < std::mem::size_of::<QUERY_SERVICE_CONFIGW>()
    {
        return Err(io::Error::other("invalid service configuration size"));
    }
    // The structure contains pointers; a byte-vector is not sufficiently aligned.
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service, config, needed, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let config = unsafe { &*config };
    if config.dwServiceType != SERVICE_KERNEL_DRIVER || config.dwStartType != SERVICE_DEMAND_START {
        return Err(io::Error::other(
            "foreign service configuration; recovery refused",
        ));
    }
    let p = config.lpBinaryPathName as usize;
    let start = storage.as_ptr() as usize;
    let end = start + storage.len() * 8;
    if p < start || p >= end || p & 1 != 0 {
        return Err(io::Error::other("invalid service binary path"));
    }
    let text = unsafe { std::slice::from_raw_parts(config.lpBinaryPathName, (end - p) / 2) };
    let end = text
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| io::Error::other("unterminated service binary path"))?;
    Ok(text[..end].to_vec())
}
fn remove_stale_sublayers(directory: &Path) -> io::Result<()> {
    use windows_sys::Win32::{
        NetworkManagement::WindowsFilteringPlatform::*, System::Rpc::RPC_C_AUTHN_WINNT,
    };
    let Some(keys) = crate::windows_app_routing_journal::read_keys(directory)? else {
        return Ok(());
    };
    let mut engine = ptr::null_mut();
    let code = unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            ptr::null(),
            &mut engine,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let result = (|| {
        let code = unsafe { FwpmTransactionBegin0(engine, 0) };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        for (index, key) in keys.iter().enumerate() {
            let mut layer = ptr::null_mut();
            let code = unsafe { FwpmSubLayerGetByKey0(engine, key, &mut layer) };
            if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
                continue;
            }
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            if layer.is_null() {
                return Err(io::Error::other("missing recovery WFP sublayer"));
            }
            let valid = unsafe {
                let layer = &*layer;
                let expected: Vec<u16> = "FCAE split routing owner\0".encode_utf16().collect();
                layer.flags == 0
                    && layer.weight == 0x7100 + index as u16
                    && layer.providerKey.is_null()
                    && !layer.displayData.name.is_null()
                    && expected
                        .iter()
                        .enumerate()
                        .all(|(n, c)| *layer.displayData.name.add(n) == *c)
            };
            unsafe {
                FwpmFreeMemory0((&mut layer as *mut *mut FWPM_SUBLAYER0).cast());
            }
            if !valid {
                return Err(io::Error::other("foreign WFP metadata; recovery refused"));
            }
            let code = unsafe { FwpmSubLayerDeleteByKey0(engine, key) };
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        let code = unsafe { FwpmTransactionCommit0(engine) };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            FwpmTransactionAbort0(engine);
        }
    }
    unsafe {
        FwpmEngineClose0(engine);
    }
    result
}
/// Run on an owned worker after explicit GUI recovery. A live process/device
/// owner, mismatched service, ACL, marker or WFP metadata causes refusal.
pub fn recover_stale() -> io::Result<usize> {
    if !crate::privilege::is_privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recovery requires administrator permission",
        ));
    }
    // Reuse the installer's protected-parent validation without relying on
    // process environment variables. The temporary directory has no kernel state.
    let probe = private_directory()?;
    let parent = probe
        .parent()
        .ok_or_else(|| io::Error::other("missing driver parent"))?
        .to_path_buf();
    std::fs::remove_dir(&probe)?;
    let manager = Service(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
    if manager.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut recovered = 0;
    for (index, entry) in std::fs::read_dir(parent)?.take(16385).enumerate() {
        if index == 16384 {
            return Err(io::Error::other(
                "driver directory scan exceeded its safety limit",
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name.strip_prefix("FCAE-split-") else {
            continue;
        };
        if suffix.len() != 35 || !suffix.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
            continue;
        }
        let directory = entry.path();
        let lock = crate::windows_app_routing_journal::lock_stale(&directory)?;
        // Resolve service ownership before requesting a driver reset. The
        // global device name alone is never authority to reset kernel state.
        let service_name = wide(OsStr::new(NAME))?;
        let handle = unsafe {
            OpenServiceW(
                manager.0,
                service_name.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_STOP | DELETE,
            )
        };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            if code != ERROR_SERVICE_DOES_NOT_EXIST {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        } else {
            let service = Service(handle);
            let actual = configured_image(handle)?;
            let expected: Vec<u16> = format!(
                "\\??\\{}",
                directory.join("mullvad-split-tunnel.sys").display()
            )
            .encode_utf16()
            .collect();
            if unsafe {
                windows_sys::Win32::Globalization::CompareStringOrdinal(
                    actual.as_ptr(),
                    actual.len() as i32,
                    expected.as_ptr(),
                    expected.len() as i32,
                    1,
                )
            } != windows_sys::Win32::Globalization::CSTR_EQUAL
            {
                return Err(io::Error::other(
                    "service image does not match this recovery record; no service was changed",
                ));
            }
            if status(handle)? != SERVICE_STOPPED {
                let mut driver = Driver::open_owned_stale()?;
                driver.reset()?;
                drop(driver);
                let mut value = SERVICE_STATUS::default();
                if unsafe { ControlService(handle, SERVICE_CONTROL_STOP, &mut value) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                wait(handle, SERVICE_STOPPED)?;
            }
            if unsafe { DeleteService(handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            drop(service);
        }
        remove_stale_sublayers(&directory)?;
        let mut admin = 0;
        let algorithm = wide(OsStr::new("SHA256"))?;
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                ptr::null(),
                algorithm.as_ptr(),
                ptr::null(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let basename = wide(OsStr::new(&format!("{name}.cat")))?;
        let ok = unsafe { CryptCATAdminRemoveCatalog(admin, basename.as_ptr(), 0) };
        let error = io::Error::last_os_error();
        unsafe {
            CryptCATAdminReleaseContext(admin, 0);
        }
        if ok == 0
            && !matches!(error.raw_os_error(),Some(x) if x==ERROR_NOT_FOUND as i32 || x==ERROR_FILE_NOT_FOUND as i32 || x==CRYPT_E_NOT_FOUND)
        {
            return Err(error);
        }
        drop(lock);
        std::fs::remove_dir_all(directory)?;
        recovered += 1;
    }
    Ok(recovered)
}
