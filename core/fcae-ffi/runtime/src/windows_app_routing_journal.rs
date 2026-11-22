//! Protected write-ahead ownership records. Recovery never infers ownership
//! from a service name, an executable name, or a random-looking directory alone.
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::Threading::*,
    },
};
const ACL_TEXT: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u32,
    pid: u32,
    created: [u32; 2],
    source: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    version: u32,
    baseline: [u8; 16],
    dns: [u8; 16],
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn times(process: HANDLE) -> io::Result<[u32; 2]> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok([created.dwLowDateTime, created.dwHighDateTime])
}
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
pub(super) fn create(directory: &Path) -> io::Result<()> {
    let owner = Owner {
        version: 1,
        pid: std::process::id(),
        created: times(unsafe { GetCurrentProcess() })?,
        source: crate::windows_split_driver_package::SOURCE_REVISION.into(),
    };
    write_new(
        &directory.join("owner.json"),
        &serde_json::to_vec(&owner).map_err(io::Error::other)?,
    )
}
fn guid_bytes(g: GUID) -> [u8; 16] {
    let mut b = [0; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    b
}
fn guid(b: [u8; 16]) -> GUID {
    GUID {
        data1: u32::from_le_bytes(b[..4].try_into().unwrap()),
        data2: u16::from_le_bytes(b[4..6].try_into().unwrap()),
        data3: u16::from_le_bytes(b[6..8].try_into().unwrap()),
        data4: b[8..].try_into().unwrap(),
    }
}
pub(super) fn write_keys(directory: &Path, baseline: GUID, dns: GUID) -> io::Result<()> {
    let keys = Keys {
        version: 1,
        baseline: guid_bytes(baseline),
        dns: guid_bytes(dns),
    };
    write_new(
        &directory.join("sublayers.json"),
        &serde_json::to_vec(&keys).map_err(io::Error::other)?,
    )
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > 65536
    {
        return Err(io::Error::other("invalid recovery record"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::other("oversized recovery record"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
/// Holds the directory open without write/delete sharing throughout recovery.
/// The directory must have exactly our protected administrators/SYSTEM DACL.
pub(super) fn lock_stale(directory: &Path) -> io::Result<File> {
    use std::os::windows::fs::MetadataExt;
    let file = OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("reparse-point recovery directory refused"));
    }
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let descriptor = Descriptor(descriptor);
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || acl.is_null()
    {
        return Err(io::Error::other("unprotected recovery directory ACL"));
    }
    let text: Vec<u16> = ACL_TEXT.encode_utf16().chain(Some(0)).collect();
    let mut expected = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut expected,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let expected = Descriptor(expected);
    let mut expected_acl = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(expected.0, &mut present, &mut expected_acl, &mut defaulted)
    } == 0
        || expected_acl.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { IsValidAcl(acl) } == 0 {
        return Err(io::Error::other("invalid recovery ACL"));
    }
    let actual = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize) };
    let expected = unsafe {
        std::slice::from_raw_parts(expected_acl.cast::<u8>(), (*expected_acl).AclSize as usize)
    };
    if actual != expected {
        return Err(io::Error::other("foreign recovery directory ACL"));
    }
    let owner: Owner = read_json(&directory.join("owner.json"))?;
    if owner.version != 1
        || owner.pid == 0
        || owner.source != crate::windows_split_driver_package::SOURCE_REVISION
    {
        return Err(io::Error::other("foreign recovery ownership record"));
    }
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            owner.pid,
        )
    };
    if process.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INVALID_PARAMETER as i32) {
            return Err(error);
        }
    } else {
        let created = times(process);
        let exited = unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0;
        unsafe {
            CloseHandle(process);
        }
        if created? == owner.created && !exited {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "routing installation still has a live owner",
            ));
        }
    }
    Ok(file)
}
pub(super) fn read_keys(directory: &Path) -> io::Result<Option<[GUID; 2]>> {
    let keys: Keys = match read_json(&directory.join("sublayers.json")) {
        Ok(keys) => keys,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if keys.version != 1
        || keys.baseline == [0; 16]
        || keys.dns == [0; 16]
        || keys.baseline == keys.dns
    {
        return Err(io::Error::other("invalid recovery sublayer keys"));
    }
    Ok(Some([guid(keys.baseline), guid(keys.dns)]))
}
