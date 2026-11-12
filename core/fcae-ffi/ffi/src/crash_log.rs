//! Best-effort desktop crash breadcrumbs. Never captures panic payloads.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MAX_LOG: usize = 256 * 1024 - 128;
const MAX_PANIC: usize = 16 * 1024;
const KEEP_LOG: usize = 128 * 1024;

struct Log { file: File, path: PathBuf, bytes: usize }
static LOG: OnceLock<Mutex<Log>> = OnceLock::new();
static INIT: std::sync::Once = std::sync::Once::new();

fn fallback_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    { std::env::var_os("LOCALAPPDATA").map(|v| PathBuf::from(v).join("FCAE_VPN").join("logs")) }
    #[cfg(target_os = "macos")]
    { std::env::var_os("HOME").map(|v| PathBuf::from(v).join("Library/Logs/FCAE_VPN")) }
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/state")))?;
        Some(base.join("fcae-vpn"))
    }
}

fn prepare(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "crash log directory is not private"));
        }
    }
    #[cfg(windows)]
    {
        fs::create_dir_all(dir)?;
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid crash log directory"));
        }
    }
    Ok(())
}

fn open_log(dir: &Path) -> std::io::Result<(File, usize)> {
    prepare(dir)?;
    let path = dir.join("logs.txt");
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Allow truncation and seek-to-end while refusing reparse points.
        opts.access_mode(0x8000_0000 | 0x4000_0000).custom_flags(0x0020_0000);
    }
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular log file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "log file is not private"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "log file is a reparse point"));
        }
    }
    // One writer per file; a second instance may use the fallback directory.
    file.try_lock().map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
    let mut size = file.metadata()?.len();
    if size > (MAX_LOG - MAX_PANIC) as u64 {
        file.seek(SeekFrom::End(-(KEEP_LOG as i64)))?;
        let mut tail = Vec::with_capacity(KEEP_LOG);
        Read::by_ref(&mut file).take(KEEP_LOG as u64).read_to_end(&mut tail)?;
        let first_line = tail.iter().position(|b| *b == b'\n').map_or(tail.len(), |i| i + 1);
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&tail[first_line..])?;
        size = (tail.len() - first_line) as u64;
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, size as usize))
}

pub(crate) fn record(message: &str) {
    if let Some(log) = LOG.get() {
        // The panic may have interrupted a thread holding the log lock.
        if let Ok(mut log) = log.try_lock() {
            let remaining = MAX_LOG.saturating_sub(log.bytes);
            let bytes = message.as_bytes();
            let n = bytes.len().min(remaining);
            let mut written = 0;
            while written < n {
                match log.file.write(&bytes[written..n]) {
                    Ok(0) => break,
                    Ok(count) => { written += count; log.bytes += count; }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = log.file.flush();
        }
    }
}

pub(crate) fn record_log(message: &str) {
    let Some(lock) = LOG.get() else { return };
    let Ok(mut log) = lock.lock() else { return };
    let limit = MAX_LOG - MAX_PANIC;
    let mut end = message.len().min(limit.saturating_sub(32));
    while !message.is_char_boundary(end) { end -= 1; }
    let truncated = end < message.len();
    let suffix = if truncated { " [log truncated]\n" } else { "\n" };
    let needed = end + suffix.len();
    if log.bytes.saturating_add(needed) > limit {
        let keep = KEEP_LOG.min(log.bytes).min(limit.saturating_sub(needed));
        let size = log.bytes;
        let mut tail = Vec::with_capacity(keep);
        if keep > 0 {
            if log.file.seek(SeekFrom::Start((size - keep) as u64)).is_err()
                || Read::by_ref(&mut log.file).take(keep as u64).read_to_end(&mut tail).is_err() { return; }
            if size > keep {
                let first = tail.iter().position(|b| *b == b'\n').map_or(tail.len(), |i| i + 1);
                tail.drain(..first);
            }
        }
        if log.file.set_len(0).is_err() || log.file.seek(SeekFrom::Start(0)).is_err() { return; }
        if log.file.write_all(&tail).is_err() { return; }
        log.bytes = tail.len();
    }
    if log.file.write_all(message[..end].as_bytes()).is_ok() {
        log.bytes += end;
        if log.file.write_all(suffix.as_bytes()).is_ok() { log.bytes += suffix.len(); }
    }
}

pub fn init() {
    INIT.call_once(|| {
        let open = |dir: &Path| open_log(dir).ok().map(|(file, size)| (file, size, dir.join("logs.txt")));
        let result = fcae_runtime::deps::dir().and_then(open)
            .or_else(|| fallback_dir().and_then(|dir| open(&dir)));
        let Some((file, bytes, path)) = result else { return; };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            SIGNAL_FD.store(file.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            EXCEPTION_FILE.store(file.as_raw_handle(), std::sync::atomic::Ordering::Relaxed);
        }
        if LOG.set(Mutex::new(Log { file, path, bytes })).is_err() { return; }
        record(&format!("FCAE {} pid {} started\n", env!("CARGO_PKG_VERSION"), std::process::id()));
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info.location().map(|p| format!("{}:{}:{}", p.file(), p.line(), p.column())).unwrap_or_else(|| "unknown".into());
            record(&format!("Rust panic at {location} (payload omitted)\n"));
            let mut report = format!("{}\n", std::backtrace::Backtrace::force_capture());
            if report.len() > MAX_PANIC {
                let mut end = MAX_PANIC;
                while !report.is_char_boundary(end) { end -= 1; }
                report.truncate(end);
                report.push('\n');
            }
            record(&report);
            previous(info);
        }));
        install_native_handler();
    });
}

pub fn announce() {
    match LOG.get().and_then(|log| log.lock().ok().map(|log| log.path.clone())) {
        Some(path) => log::info!("[crash] diagnostic log: {}", path.display()),
        None => log::warn!("[crash] no writable diagnostic log directory"),
    }
}

#[cfg(unix)]
static SIGNAL_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
#[cfg(unix)]
static SIGNAL_RECORDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn fatal_signal(sig: libc::c_int) {
    use std::sync::atomic::Ordering;
    if !SIGNAL_RECORDED.swap(true, Ordering::Relaxed) {
        let text: &[u8] = match sig {
            libc::SIGSEGV => b"fatal signal SIGSEGV\n",
            libc::SIGBUS => b"fatal signal SIGBUS\n",
            libc::SIGILL => b"fatal signal SIGILL\n",
            libc::SIGFPE => b"fatal signal SIGFPE\n",
            libc::SIGABRT => b"fatal signal SIGABRT\n",
            _ => b"fatal signal\n",
        };
        let fd = SIGNAL_FD.load(Ordering::Relaxed);
        if fd >= 0 { unsafe { libc::write(fd, text.as_ptr().cast(), text.len()); } }
    }
    // SA_RESETHAND restored the default action before entering this handler.
    unsafe { libc::raise(sig); }
}

#[cfg(unix)]
fn install_native_handler() {
    // Go and other embedded runtimes own some signals. Do not replace or
    // forward their handlers: they use signals for recoverable faults.
    unsafe {
        for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGABRT] {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) != 0 { continue; }
            if old.sa_sigaction != libc::SIG_DFL { continue; }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = fatal_signal as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESETHAND;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
static EXCEPTION_FILE: std::sync::atomic::AtomicPtr<std::ffi::c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
#[cfg(windows)]
static EXCEPTION_RECORDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(windows)]
#[repr(C)]
struct ExceptionRecord { code: u32, flags: u32, record: *mut std::ffi::c_void, address: *mut std::ffi::c_void }
#[cfg(windows)]
#[repr(C)]
struct ExceptionPointers { record: *const ExceptionRecord, context: *const std::ffi::c_void }
#[cfg(windows)]
type Filter = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;
#[cfg(windows)]
static PREVIOUS_FILTER: OnceLock<Option<Filter>> = OnceLock::new();
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn SetUnhandledExceptionFilter(filter: Option<Filter>) -> Option<Filter>;
    fn WriteFile(file: *mut std::ffi::c_void, buffer: *const std::ffi::c_void, len: u32, written: *mut u32, overlapped: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
unsafe extern "system" fn exception_filter(info: *mut ExceptionPointers) -> i32 {
    use std::sync::atomic::Ordering;
    if !EXCEPTION_RECORDED.swap(true, Ordering::Relaxed) {
        let record = if !info.is_null() { (*info).record.as_ref() } else { None };
        let code = record.map_or(0, |record| record.code);
        let address = record.map_or(0, |record| record.address as usize as u64);
        let mut text = *b"unhandled Windows exception 0x00000000 address=0x0000000000000000\n";
        let hex = b"0123456789ABCDEF";
        for i in 0..8 { text[30 + i] = hex[((code >> ((7 - i) * 4)) & 15) as usize]; }
        for i in 0..16 { text[49 + i] = hex[((address >> ((15 - i) * 4)) & 15) as usize]; }
        let mut written = 0;
        let file = EXCEPTION_FILE.load(Ordering::Relaxed);
        if !file.is_null() { WriteFile(file, text.as_ptr().cast(), text.len() as u32, &mut written, std::ptr::null_mut()); }
    }
    match PREVIOUS_FILTER.get().copied().flatten() {
        Some(previous) => previous(info),
        None => 0, // EXCEPTION_CONTINUE_SEARCH
    }
}

#[cfg(windows)]
fn install_native_handler() {
    let previous = unsafe { SetUnhandledExceptionFilter(Some(exception_filter)) };
    let _ = PREVIOUS_FILTER.set(previous);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_is_bounded_and_keeps_recent_history() {
        let dir = std::env::temp_dir().join(format!("fcae-crash-log-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&dir);
        let (mut first, size) = open_log(&dir).unwrap();
        assert_eq!(size, 0);
        first.write_all(&vec![b'x'; MAX_LOG]).unwrap();
        first.write_all(b"\nlast crash\n").unwrap();
        drop(first);
        let (mut second, size) = open_log(&dir).unwrap();
        assert!(size <= KEEP_LOG);
        second.write_all(b"new run\n").unwrap();
        drop(second);
        let log = fs::read(dir.join("logs.txt")).unwrap();
        assert!(log.ends_with(b"last crash\nnew run\n"));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn log_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("fcae-crash-link-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&dir);
        prepare(&dir).unwrap();
        let target = dir.join("target");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, dir.join("logs.txt")).unwrap();
        assert!(open_log(&dir).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        fs::remove_dir_all(dir).unwrap();
    }
}
