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
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
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

    pub fn embedded(files: &[(&str, &[u8])], entry: &str) -> Result<Self> {
        if !files.iter().any(|(name, _)| *name == entry) {
            return Err(CoreError::Internal("embedded DLL entry is missing".into()));
        }
        let files = EmbeddedFiles::stage(files)?;
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
    pub fn stage(files: &[(&str, &[u8])]) -> Result<Self> {
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
        let dir = std::env::temp_dir().join("FCAE_VPN").join("native").join(format!("{:x}", hash.finalize()));
        std::fs::create_dir_all(&dir).map_err(|e| {
            CoreError::Internal(format!("cannot create {}: {e}", dir.display()))
        })?;
        let mut locks = Vec::with_capacity(files.len());
        for (name, bytes) in files { locks.push(stage(&dir.join(name), bytes)?); }
        Ok(Self { dir, locks })
    }

    pub fn directory(&self) -> &Path { &self.dir }
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

pub fn ensure_wintun(bytes: Option<&'static [u8]>) -> Result<()> {
    static WINTUN: OnceLock<std::result::Result<Library, String>> = OnceLock::new();
    WINTUN.get_or_init(|| {
        let library = if let Some(bytes) = bytes {
            Library::embedded(&[("wintun.dll", bytes)], "wintun.dll")
        } else {
            Library::load(OsStr::new("wintun.dll"), LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32, Vec::new())
        };
        library.map_err(|e| e.to_string())
    }).as_ref().map(|_| ()).map_err(|e| CoreError::Internal(e.clone()))
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
