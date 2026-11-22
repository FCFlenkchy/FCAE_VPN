//! Native userspace socket ownership for desktop app routing.
//! Ambiguous/shared sockets stay unresolved; callers keep those flows on VPN.
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct Owner {
    pub pid: u32,
    pub path: String,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub fn lookup(protocol: u32, source: SocketAddr, destination: SocketAddr) -> Option<Owner> {
    let source = SocketAddr::new(source.ip().to_canonical(), source.port());
    let destination = SocketAddr::new(destination.ip().to_canonical(), destination.port());
    if source.is_ipv4() != destination.is_ipv4() {
        return None;
    }
    use netstat2::{
        get_sockets_info, AddressFamilyFlags as Family, ProtocolFlags as Protocol,
        ProtocolSocketInfo as Socket,
    };
    use std::{collections::BTreeSet, sync::Mutex, time::Duration};
    // Bound simultaneous native table/procfs scans. Never persist ownership
    // across flows: source ports and PIDs may be recycled between connections.
    static SCAN: Mutex<()> = Mutex::new(());
    let family = if source.is_ipv4() {
        Family::IPV4
    } else {
        Family::IPV6
    };
    let transport = match protocol {
        6 => Protocol::TCP,
        17 => Protocol::UDP,
        _ => return None,
    };
    for attempt in 0..3 {
        let result = {
            let _scan = SCAN.lock().unwrap_or_else(|error| error.into_inner());
            let sockets = get_sockets_info(family, transport).ok()?;
            let mut pids = BTreeSet::new();
            let mut unresolved = false;
            for socket in sockets {
                let matched = match socket.protocol_socket_info {
                    Socket::Tcp(tcp) => {
                        tcp.local_port == source.port()
                            && same_ip(tcp.local_addr, source.ip())
                            && tcp.remote_port == destination.port()
                            && same_ip(tcp.remote_addr, destination.ip())
                    }
                    Socket::Udp(udp) => {
                        udp.local_port == source.port()
                            && (same_ip(udp.local_addr, source.ip())
                                || udp.local_addr.is_unspecified())
                    }
                };
                if !matched {
                    continue;
                }
                if socket.associated_pids.is_empty() {
                    unresolved = true;
                }
                for pid in socket.associated_pids {
                    if pid == 0 {
                        unresolved = true;
                    } else {
                        pids.insert(pid);
                    }
                }
            }
            if !unresolved && pids.len() == 1 {
                let pid = *pids.first()?;
                executable(pid)
                    .filter(|path| {
                        !path.is_empty()
                            && path.len() <= 32768
                            && !path.chars().any(char::is_control)
                    })
                    .map(|path| Owner { pid, path })
            } else {
                None
            }
        };
        if result.is_some() {
            return result;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    None
}
fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    a.to_canonical() == b.to_canonical()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn lookup(_: u32, _: SocketAddr, _: SocketAddr) -> Option<Owner> {
    None
}

#[cfg(target_os = "linux")]
fn executable(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if path.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        return None;
    }
    path.to_str().map(str::to_owned)
}
#[cfg(windows)]
fn executable(pid: u32) -> Option<String> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length);
        CloseHandle(process);
        if ok == 0 {
            return None;
        }
        let text = String::from_utf16(&buffer[..length as usize]).ok()?;
        Some(text.strip_prefix("\\\\?\\").unwrap_or(&text).to_owned())
    }
}
#[cfg(target_os = "macos")]
fn executable(pid: u32) -> Option<String> {
    #[link(name = "proc")]
    extern "C" {
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
    }
    if pid > i32::MAX as u32 {
        return None;
    }
    let mut buffer = vec![0u8; 4096];
    if unsafe { proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) } <= 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&buffer[..end]).ok().map(str::to_owned)
}
