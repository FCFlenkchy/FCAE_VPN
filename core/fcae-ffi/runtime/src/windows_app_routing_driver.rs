//! User-mode interoperability client for the Mullvad Windows split-tunnel
//! driver 1.3 protocol (upstream 0a0eb97f67d1dbcb3d08bda66d3b24f465d95475).
//! No upstream implementation is vendored. The kernel driver is separately
//! licensed GPL-3.0-or-later OR MPL-2.0. Optional pinned package embedding is
//! provided by windows_split_driver_package; installation remains separate.
//! This client is NOT an installer or a complete platform enforcement provider.
//! The owner must supply registered WFP sublayers, refresh interface addresses,
//! consume driver events, and coordinate existing DNS/kill-switch filters.
use std::collections::BTreeSet;
use std::io;

const MAX_BUFFER: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 65536;

#[derive(Clone, Debug)]
pub struct ProcessRecord {
    pub pid: u64,
    pub parent_pid: u64,
    /// NT device path, not a drive-letter path. Empty for inaccessible images.
    pub image: Vec<u16>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Addresses {
    pub tunnel_v4: [u8; 4],
    pub physical_v4: [u8; 4],
    pub tunnel_v6: [u8; 16],
    pub physical_v6: [u8; 16],
}
impl Addresses {
    pub fn encode(self) -> [u8; 40] {
        let mut bytes = [0; 40];
        bytes[0..4].copy_from_slice(&self.tunnel_v4);
        bytes[4..8].copy_from_slice(&self.physical_v4);
        bytes[8..24].copy_from_slice(&self.tunnel_v6);
        bytes[24..40].copy_from_slice(&self.physical_v6);
        bytes
    }
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn image_bytes(path: &[u16], allow_empty: bool) -> io::Result<usize> {
    let length = path
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("image path overflow"))?;
    let prefix: Vec<u16> = "\\Device\\".encode_utf16().collect();
    if length > u16::MAX as usize
        || path.contains(&0)
        || (!path.is_empty() && !path.starts_with(&prefix))
        || (!allow_empty && path.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid NT image path",
        ));
    }
    Ok(length)
}
fn encode_records(records: &[(u64, u64, Vec<u16>)], processes: bool) -> io::Result<Vec<u8>> {
    if records.len() > MAX_ENTRIES {
        return Err(io::Error::other("too many process/image entries"));
    }
    // Protocol is explicitly 64-bit (Windows amd64 and arm64). Never use Rust
    // struct memory: it could expose uninitialized C-ABI alignment padding.
    let stride = if processes { 32 } else { 16 };
    let strings = 16 + records.len() * stride;
    let mut length = strings;
    for (_, _, path) in records {
        length = length
            .checked_add(image_bytes(path, processes)?)
            .ok_or_else(|| io::Error::other("configuration overflow"))?;
    }
    if length > MAX_BUFFER {
        return Err(io::Error::other("configuration too large"));
    }
    let mut bytes = vec![0u8; length];
    put64(&mut bytes, 0, records.len() as u64);
    put64(&mut bytes, 8, length as u64);
    let mut string_offset = 0;
    for (index, (pid, parent, path)) in records.iter().enumerate() {
        let mut entry = 16 + index * stride;
        if processes {
            put64(&mut bytes, entry, *pid);
            put64(&mut bytes, entry + 8, *parent);
            entry += 16;
        }
        put64(&mut bytes, entry, string_offset as u64);
        bytes[entry + 8..entry + 10].copy_from_slice(&((path.len() * 2) as u16).to_le_bytes());
        for ch in path {
            bytes[strings + string_offset..strings + string_offset + 2]
                .copy_from_slice(&ch.to_le_bytes());
            string_offset += 2;
        }
    }
    Ok(bytes)
}
pub fn encode_configuration(paths: &[Vec<u16>]) -> io::Result<Vec<u8>> {
    let paths: BTreeSet<_> = paths.iter().cloned().collect();
    let records: Vec<_> = paths.into_iter().map(|p| (0, 0, p)).collect();
    encode_records(&records, false)
}
pub fn encode_processes(processes: &[ProcessRecord]) -> io::Result<Vec<u8>> {
    let mut seen = BTreeSet::new();
    for p in processes {
        if p.pid == 0 || p.pid == p.parent_pid || !seen.insert(p.pid) {
            return Err(io::Error::other("invalid/duplicate process ID"));
        }
    }
    let records: Vec<_> = processes
        .iter()
        .map(|p| (p.pid, p.parent_pid, p.image.clone()))
        .collect();
    encode_records(&records, true)
}

#[cfg(all(windows, target_pointer_width = "64"))]
mod client {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use windows_sys::core::GUID;
    use windows_sys::Win32::{
        Foundation::*,
        Storage::FileSystem::*,
        System::{Diagnostics::ToolHelp::*, Threading::*, IO::*},
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }
    fn wide(path: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
        let mut result: Vec<_> = path.encode_wide().collect();
        if result.contains(&0) {
            return Err(io::Error::other("NUL in Windows path"));
        }
        result.push(0);
        Ok(result)
    }
    pub fn device_path(path: &Path) -> io::Result<Vec<u16>> {
        if !path.is_absolute() || !std::fs::metadata(path)?.is_file() {
            return Err(io::Error::other("an absolute executable file is required"));
        }
        let path = wide(path.as_os_str())?;
        let file = Handle(unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        });
        if file.0 == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                VOLUME_NAME_NT,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize >= buffer.len() {
            return Err(io::Error::other("NT image path too long"));
        }
        buffer.truncate(length as usize);
        image_bytes(&buffer, false)?;
        Ok(buffer)
    }
    pub fn process_snapshot() -> io::Result<Vec<ProcessRecord>> {
        let snapshot = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) });
        if snapshot.0 == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        let mut rows = Vec::new();
        let mut times = std::collections::BTreeMap::new();
        while ok != 0 {
            if entry.th32ProcessID != 0 {
                if rows.len() >= MAX_ENTRIES {
                    return Err(io::Error::other("process inventory exceeds safety limit"));
                }
                let process = Handle(unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID)
                });
                let mut image = Vec::new();
                if !process.0.is_null() {
                    let mut path = vec![0u16; 32768];
                    let mut length = path.len() as u32;
                    if unsafe {
                        QueryFullProcessImageNameW(
                            process.0,
                            PROCESS_NAME_NATIVE,
                            path.as_mut_ptr(),
                            &mut length,
                        )
                    } != 0
                    {
                        path.truncate(length as usize);
                        if image_bytes(&path, false).is_ok() {
                            image = path;
                        }
                    }
                    let mut created = FILETIME::default();
                    let mut exited = FILETIME::default();
                    let mut kernel = FILETIME::default();
                    let mut user = FILETIME::default();
                    if unsafe {
                        GetProcessTimes(
                            process.0,
                            &mut created,
                            &mut exited,
                            &mut kernel,
                            &mut user,
                        )
                    } != 0
                    {
                        times.insert(
                            entry.th32ProcessID as u64,
                            ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64,
                        );
                    }
                }
                rows.push(ProcessRecord {
                    pid: entry.th32ProcessID as u64,
                    parent_pid: entry.th32ParentProcessID as u64,
                    image,
                });
            }
            ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_NO_MORE_FILES {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        // Unknown/recycled parent identity never inherits an exclusion. The
        // driver's live process notifications take over after initialization.
        for row in &mut rows {
            if row.pid == row.parent_pid
                || !matches!((times.get(&row.pid),times.get(&row.parent_pid)),(Some(child),Some(parent)) if parent<=child)
            {
                row.parent_pid = 0;
            }
        }
        Ok(rows)
    }

    /// Exclusive device owner. Construction never steals/resets an initialized
    /// device. Installation/service ownership must be established by the caller.
    pub struct Driver {
        handle: Handle,
        initialized: bool,
        event: Option<PendingEvent>,
    }
    // All raw pointers refer to owned/pinned buffers; operations require &mut
    // for the event stream. Moving the owner does not move either allocation.
    unsafe impl Send for Driver {}
    struct PendingEvent {
        device: HANDLE,
        _event: Handle,
        overlapped: Box<OVERLAPPED>,
        bytes: Box<[u8]>,
        finished: bool,
    }
    impl PendingEvent {
        fn start(device: HANDLE) -> io::Result<Self> {
            let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
            if event.0.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut overlapped = Box::<OVERLAPPED>::default();
            overlapped.hEvent = event.0;
            let mut pending = Self {
                device,
                _event: event,
                overlapped,
                bytes: vec![0; 128 * 1024].into_boxed_slice(),
                finished: true,
            };
            let ok = unsafe {
                DeviceIoControl(
                    device,
                    (0x8000 << 16) | (2 << 2),
                    ptr::null(),
                    0,
                    pending.bytes.as_mut_ptr().cast(),
                    pending.bytes.len() as u32,
                    ptr::null_mut(),
                    &mut *pending.overlapped,
                )
            };
            if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
                return Err(io::Error::last_os_error());
            }
            pending.finished = false;
            Ok(pending)
        }
        fn completed(&mut self) -> io::Result<Option<usize>> {
            let mut length = 0;
            if unsafe { GetOverlappedResult(self.device, &*self.overlapped, &mut length, 0) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32) {
                    return Ok(None);
                }
                self.finished = true;
                return Err(error);
            }
            self.finished = true;
            if length as usize > self.bytes.len() {
                return Err(io::Error::other("invalid event size"));
            }
            Ok(Some(length as usize))
        }
    }
    impl Drop for PendingEvent {
        fn drop(&mut self) {
            if !self.finished {
                unsafe {
                    CancelIoEx(self.device, &*self.overlapped);
                    let mut length = 0;
                    GetOverlappedResult(self.device, &*self.overlapped, &mut length, 1);
                }
            }
        }
    }
    impl Driver {
        pub fn open_started() -> io::Result<Self> {
            Self::open_checked(false)
        }
        /// Only after protected ownership-journal and service-image checks.
        pub(crate) fn open_owned_stale() -> io::Result<Self> {
            Self::open_checked(true)
        }
        fn open_checked(recover: bool) -> io::Result<Self> {
            let name: Vec<u16> = "\\\\.\\MULLVADSPLITTUNNEL\0".encode_utf16().collect();
            let handle = Handle(unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            });
            if handle.0 == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let mut driver = Self {
                handle,
                initialized: false,
                event: None,
            };
            let state = driver.state()?;
            if recover && (2..=4).contains(&state) {
                driver.initialized = true;
            } else if state != 1 {
                return Err(io::Error::other("driver is already initialized or has an incompatible state; refusing to reset another owner"));
            }
            Ok(driver)
        }
        fn ioctl(
            &self,
            function: u32,
            neither: bool,
            input: &[u8],
            output: &mut [u8],
        ) -> io::Result<usize> {
            if input.len() > MAX_BUFFER || output.len() > MAX_BUFFER {
                return Err(io::Error::other("IOCTL buffer exceeds safety limit"));
            }
            let event = Handle(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) });
            if event.0.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut overlapped = OVERLAPPED {
                hEvent: event.0,
                ..Default::default()
            };
            let code = (0x8000u32 << 16) | (function << 2) | if neither { 3 } else { 0 };
            let ok = unsafe {
                DeviceIoControl(
                    self.handle.0,
                    code,
                    if input.is_empty() {
                        ptr::null()
                    } else {
                        input.as_ptr().cast()
                    },
                    input.len() as u32,
                    if output.is_empty() {
                        ptr::null_mut()
                    } else {
                        output.as_mut_ptr().cast()
                    },
                    output.len() as u32,
                    ptr::null_mut(),
                    &mut overlapped,
                )
            };
            if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
                return Err(io::Error::last_os_error());
            }
            let wait = unsafe { WaitForSingleObject(event.0, 10000) };
            if wait != WAIT_OBJECT_0 {
                // Cancellation is a request, not completion. The kernel still
                // owns all pointers until GetOverlappedResult has returned.
                unsafe {
                    CancelIoEx(self.handle.0, &overlapped);
                }
                let mut ignored = 0;
                unsafe {
                    GetOverlappedResult(self.handle.0, &overlapped, &mut ignored, 1);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "split driver operation timed out",
                ));
            }
            let mut returned = 0;
            if unsafe { GetOverlappedResult(self.handle.0, &overlapped, &mut returned, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if returned as usize > output.len() {
                return Err(io::Error::other("invalid driver output length"));
            }
            Ok(returned as usize)
        }
        /// One pending dequeue per owner. Buffers remain heap-pinned until
        /// completion, including on cancellation and all error/drop paths.
        pub fn poll_event(
            &mut self,
        ) -> io::Result<Option<crate::windows_app_routing_events::DriverEvent>> {
            if !self.initialized {
                return Err(io::Error::other("driver not initialized"));
            }
            if self.event.is_none() {
                self.event = Some(PendingEvent::start(self.handle.0)?);
            }
            let pending = self
                .event
                .as_mut()
                .ok_or_else(|| io::Error::other("event request missing"))?;
            let Some(length) = pending.completed()? else {
                return Ok(None);
            };
            let result = crate::windows_app_routing_events::decode(&pending.bytes[..length]);
            self.event.take();
            result.map(Some)
        }
        pub fn state(&self) -> io::Result<u64> {
            let mut bytes = [0u8; 8];
            let length = self.ioctl(9, false, &[], &mut bytes)?;
            if length != 8 {
                return Err(io::Error::other("incompatible driver state ABI"));
            }
            Ok(u64::from_le_bytes(bytes))
        }
        pub fn initialize(&mut self, baseline: GUID, dns: GUID) -> io::Result<()> {
            let equal = |a: GUID, b: GUID| {
                (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
            };
            if equal(baseline, GUID::default())
                || equal(dns, GUID::default())
                || equal(baseline, dns)
            {
                return Err(io::Error::other(
                    "split WFP sublayers must be nonzero and distinct",
                ));
            }
            if self.initialized || self.state()? != 1 {
                return Err(io::Error::other("driver must be freshly started"));
            }
            let mut bytes = Vec::with_capacity(32);
            for guid in [baseline, dns] {
                bytes.extend_from_slice(&guid.data1.to_le_bytes());
                bytes.extend_from_slice(&guid.data2.to_le_bytes());
                bytes.extend_from_slice(&guid.data3.to_le_bytes());
                bytes.extend_from_slice(&guid.data4);
            }
            self.initialized = true;
            self.ioctl(1, false, &bytes, &mut [])?;
            let processes = encode_processes(&process_snapshot()?)?;
            self.ioctl(3, false, &processes, &mut [])?;
            if self.state()? != 3 {
                return Err(io::Error::other(
                    "driver did not acknowledge process initialization",
                ));
            }
            Ok(())
        }
        pub fn set_addresses(&self, addresses: Addresses) -> io::Result<()> {
            if !self.initialized {
                return Err(io::Error::other("driver not initialized"));
            }
            self.ioctl(4, false, &addresses.encode(), &mut [])?;
            Ok(())
        }
        pub fn set_exclusions(&self, paths: &[std::path::PathBuf]) -> io::Result<()> {
            if !self.initialized {
                return Err(io::Error::other("driver not initialized"));
            }
            if paths.is_empty() {
                self.ioctl(8, true, &[], &mut [])?;
                return Ok(());
            }
            let own = device_path(&std::env::current_exe()?)?;
            let snapshot = process_snapshot()?;
            let mut protected = vec![own];
            let mut pid = std::process::id() as u64;
            let mut ancestors = BTreeSet::new();
            while pid != 0 && ancestors.insert(pid) {
                let Some(process) = snapshot.iter().find(|process| process.pid == pid) else {
                    break;
                };
                if !process.image.is_empty() {
                    protected.push(process.image.clone());
                }
                pid = process.parent_pid;
            }
            let mut images = Vec::with_capacity(paths.len());
            for path in paths {
                let image = device_path(path)?;
                if protected.iter().any(|path| unsafe {
                    windows_sys::Win32::Globalization::CompareStringOrdinal(
                        image.as_ptr(),
                        image.len() as i32,
                        path.as_ptr(),
                        path.len() as i32,
                        1,
                    ) == windows_sys::Win32::Globalization::CSTR_EQUAL
                }) {
                    return Err(io::Error::other(
                        "FCAE cannot exclude its transport process or a live ancestor whose descendants include it",
                    ));
                }
                images.push(image);
            }
            self.ioctl(6, false, &encode_configuration(&images)?, &mut [])?;
            Ok(())
        }
        pub fn reset(&mut self) -> io::Result<()> {
            self.event.take();
            if self.initialized {
                self.ioctl(11, true, &[], &mut [])?;
                self.initialized = false;
            }
            Ok(())
        }
    }
    impl Drop for Driver {
        fn drop(&mut self) {
            if let Err(error) = self.reset() {
                log::error!("[app-routing] driver reset failed: {error}");
            }
        }
    }
}
#[cfg(all(windows, target_pointer_width = "64"))]
pub use client::*;
