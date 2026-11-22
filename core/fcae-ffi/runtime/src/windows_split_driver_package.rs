//! Embedded, unmodified Windows driver distribution. Merely obtaining these
//! bytes does not install a service or authorize loading kernel code.
//! The installer must verify Windows catalog membership/trust before loading.

pub const AVAILABLE: bool = cfg!(all(windows, split_driver_staged));
pub const SOURCE_REVISION: &str = "0a0eb97f67d1dbcb3d08bda66d3b24f465d95475";
pub const SOURCE_URL: &str =
    "https://github.com/mullvad/win-split-tunnel/tree/0a0eb97f67d1dbcb3d08bda66d3b24f465d95475";
/// A report about this exact upstream revision remains a deployment gate.
pub const UPSTREAM_CRASH_REPORT: &str = "https://github.com/mullvad/mullvadvpn-app/issues/11487";

pub struct Artifact {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}
pub struct Package {
    pub sys: Artifact,
    pub inf: Artifact,
    pub cat: Artifact,
    pub license: &'static str,
    pub binary_revision: &'static str,
    pub source_revision: &'static str,
}
#[cfg(all(windows, split_driver_staged))]
pub fn bundled() -> Option<Package> {
    Some(Package {
        sys: Artifact {
            name: "mullvad-split-tunnel.sys",
            bytes: include_bytes!(env!("FCAE_SPLIT_DRIVER_SYS")),
            sha256: env!("FCAE_SPLIT_DRIVER_SYS_SHA256"),
        },
        inf: Artifact {
            name: "mullvad-split-tunnel.inf",
            bytes: include_bytes!(env!("FCAE_SPLIT_DRIVER_INF")),
            sha256: env!("FCAE_SPLIT_DRIVER_INF_SHA256"),
        },
        cat: Artifact {
            name: "mullvad-split-tunnel.cat",
            bytes: include_bytes!(env!("FCAE_SPLIT_DRIVER_CAT")),
            sha256: env!("FCAE_SPLIT_DRIVER_CAT_SHA256"),
        },
        license: include_str!(env!("FCAE_SPLIT_DRIVER_LICENSE")),
        binary_revision: env!("FCAE_SPLIT_DRIVER_BINARY_REV"),
        source_revision: env!("FCAE_SPLIT_DRIVER_SOURCE_REV"),
    })
}
#[cfg(not(all(windows, split_driver_staged)))]
pub fn bundled() -> Option<Package> {
    None
}

#[cfg(windows)]
mod trust {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek};
    use std::os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use std::path::{Path, PathBuf};
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Cryptography::Catalog::*, WinTrust::*},
        Storage::FileSystem::*,
    };

    /// Pins open file handles while a future installer uses their canonical
    /// paths. This performs no extraction, catalog registration or service load.
    pub struct VerifiedPackage {
        directory: PathBuf,
        _files: Vec<File>,
    }
    impl VerifiedPackage {
        pub fn directory(&self) -> &Path {
            &self.directory
        }
    }
    struct Catalog(isize);
    impl Drop for Catalog {
        fn drop(&mut self) {
            unsafe {
                CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }
    fn wide(path: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
        let mut text: Vec<_> = path.encode_wide().collect();
        if text.contains(&0) {
            return Err(io::Error::other("NUL in driver package path"));
        }
        text.push(0);
        Ok(text)
    }
    fn catalog_member(catalog: &Path, member: &Path, file: &File) -> io::Result<()> {
        let mut admin = 0;
        let algorithm: Vec<u16> = "SHA256\0".encode_utf16().collect();
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                &DRIVER_ACTION_VERIFY,
                algorithm.as_ptr(),
                ptr::null(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let admin = Catalog(admin);
        let handle = file.as_raw_handle();
        let mut position = file;
        position.rewind()?;
        let mut length = 0;
        let ok = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, handle, &mut length, ptr::null_mut(), 0)
        };
        if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }
        if length != 32 {
            return Err(io::Error::other("unexpected catalog hash algorithm"));
        }
        let mut hash = vec![0u8; length as usize];
        position.rewind()?;
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, handle, &mut length, hash.as_mut_ptr(), 0)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if length != 32 {
            return Err(io::Error::other("unexpected catalog hash size"));
        }
        let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
        let tag = wide(std::ffi::OsStr::new(&tag))?;
        let catalog_path = wide(catalog.as_os_str())?;
        let member_path = wide(member.as_os_str())?;
        let mut info = WINTRUST_CATALOG_INFO::default();
        info.cbStruct = std::mem::size_of_val(&info) as u32;
        info.pcwszCatalogFilePath = catalog_path.as_ptr();
        info.pcwszMemberTag = tag.as_ptr();
        info.pcwszMemberFilePath = member_path.as_ptr();
        info.hMemberFile = handle;
        info.pbCalculatedFileHash = hash.as_mut_ptr();
        info.cbCalculatedFileHash = length;
        info.hCatAdmin = admin.0;
        let mut data = WINTRUST_DATA::default();
        data.cbStruct = std::mem::size_of_val(&data) as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwUnionChoice = WTD_CHOICE_CATALOG;
        data.Anonymous.pCatalog = &mut info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
        let mut action = DRIVER_ACTION_VERIFY;
        position.rewind()?;
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        // Close the WinTrust state on success and failure; its lifetime is not
        // the lifetime of the driver or a catalog-store registration.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
        }
        if status != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,format!("Windows kernel driver catalog verification failed (0x{:08x}); refusing installation",status as u32)));
        }
        Ok(())
    }
    /// Validate a *previously extracted* copy of the embedded bundle. A caller
    /// must additionally enforce a protected installer-owned directory/ACL and
    /// coexistence policy. Never use success alone as authorization to load it.
    pub fn verify_extracted(directory: &Path) -> io::Result<VerifiedPackage> {
        let package = bundled().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no split driver was embedded")
        })?;
        if !directory.is_absolute() {
            return Err(io::Error::other("driver directory must be absolute"));
        }
        let directory = directory.canonicalize()?;
        let mut files = Vec::new();
        for artifact in [&package.sys, &package.inf, &package.cat] {
            let path = directory.join(artifact.name);
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || metadata.len() > 4 * 1024 * 1024
            {
                return Err(io::Error::other(
                    "unsafe or oversized extracted driver artifact",
                ));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.as_slice() != artifact.bytes
                || format!("{:x}", Sha256::digest(&bytes)) != artifact.sha256
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extracted driver artifact differs from the pinned package",
                ));
            }
            files.push(file);
        }
        catalog_member(
            &directory.join(package.cat.name),
            &directory.join(package.sys.name),
            &files[0],
        )?;
        catalog_member(
            &directory.join(package.cat.name),
            &directory.join(package.inf.name),
            &files[1],
        )?;
        Ok(VerifiedPackage {
            directory,
            _files: files,
        })
    }
}
#[cfg(windows)]
pub use trust::{verify_extracted, VerifiedPackage};
