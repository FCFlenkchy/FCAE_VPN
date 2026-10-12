//! `deps/` beside the app: where embedded native libraries are unpacked, so a
//! portable install keeps everything in its own folder instead of temp.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The `deps` directory beside the app, created on first use. `None` when the
/// app's folder is read-only, system-managed or not private to this user;
/// callers then fall back to the per-user temp directory.
pub fn dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = app_root()?.join("deps");
        match prepare(&dir) {
            Ok(()) => Some(dir),
            Err(e) => {
                log::info!("[deps] {} unusable ({e}); unpacking into the temp directory", dir.display());
                None
            }
        }
    })
    .as_deref()
}

/// The folder holding the executable, the AppImage, or the `.app` bundle —
/// the same place the desktop UI keeps its portable data.
fn app_root() -> Option<PathBuf> {
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return None;
    }
    #[cfg(target_os = "linux")]
    if let Some(image) = std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return image.parent().map(Path::to_path_buf);
    }
    let exe = std::env::current_exe().ok()?;
    #[cfg(unix)]
    let exe = exe.canonicalize().ok()?;
    let dir = exe.parent()?;
    #[cfg(target_os = "macos")]
    if dir.ends_with("Contents/MacOS") {
        // Never inside the bundle (that breaks its signature), and not beside
        // an installed or translocated one.
        let bundle = dir.parent()?.parent()?;
        if bundle.extension().is_some_and(|ext| ext == "app") {
            let parent = bundle.parent()?;
            let managed = parent.components().any(|c| {
                let c = c.as_os_str();
                c == "Applications" || c == "AppTranslocation"
            });
            return (!managed).then(|| parent.to_path_buf());
        }
    }
    Some(dir.to_path_buf())
}

#[cfg(unix)]
fn prepare(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    // The host runs TUN elevated and dlopens from here: only a directory this
    // user alone can write is acceptable.
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "not a directory private to this user"));
    }
    probe(dir)
}

#[cfg(not(unix))]
fn prepare(dir: &Path) -> io::Result<()> {
    match std::fs::create_dir(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    if !std::fs::symlink_metadata(dir)?.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
    }
    probe(dir)
}

fn probe(dir: &Path) -> io::Result<()> {
    let path = dir.join(format!(".probe-{}", std::process::id()));
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&path)?;
    std::fs::remove_file(path)
}
