//! Optional TUN fd bridge (Android VpnService). No-op on platforms without fd support.
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(unix)]
static TUN_FD: AtomicI32 = AtomicI32::new(-1);

pub fn set_fd(fd: i32) {
    #[cfg(unix)]
    TUN_FD.store(fd, Ordering::SeqCst);
    #[cfg(not(unix))]
    let _ = fd;
}

pub fn peek_fd() -> Option<i32> {
    #[cfg(unix)]
    {
        let fd = TUN_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            return Some(fd);
        }
    }
    None
}

fn env_fd() -> Option<i32> {
    std::env::var("AETHER_TUN_FD")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&fd| fd >= 0)
}

pub fn resolve_fd() -> Option<i32> {
    peek_fd().or_else(env_fd)
}

#[cfg(unix)]
pub async fn run(
    fd: i32,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(AetherError::Other(format!(
            "tun dup failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::info!("[tun] bridging fd={fd} (dup={dup})");

    let (err_tx, mut err_rx) = mpsc::channel::<String>(4);

    let out_tx = outbound_tx;
    let err_tx_r = err_tx.clone();
    let read_fd = dup;
    let read_task = tokio::task::spawn_blocking(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
        let mut buf = vec![0u8; 16384];
        loop {
            match file.read(&mut buf) {
                Ok(0) => {
                    let _ = err_tx_r.blocking_send("tun eof".into());
                    break;
                }
                Ok(n) => {
                    crate::stats::add_tx(n as u64);
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => {
                    let _ = err_tx_r.blocking_send(format!("tun read: {e}"));
                    break;
                }
            }
        }
        let _ = file.into_raw_fd();
    });

    let write_fd = unsafe { libc::dup(dup) };
    if write_fd < 0 {
        return Err(AetherError::Other("tun write dup failed".into()));
    }
    let write_task = tokio::spawn(async move {
        let mut file = unsafe { std::fs::File::from_raw_fd(write_fd) };
        while let Some(pkt) = inbound_rx.recv().await {
            crate::stats::add_rx(pkt.len() as u64);
            if let Err(e) = file.write_all(&pkt) {
                log::warn!("[tun] write: {e}");
                break;
            }
        }
    });

    tokio::select! {
        r = read_task => {
            if let Err(e) = r {
                log::warn!("[tun] read task join: {e}");
            }
        }
        _ = write_task => {
            log::info!("[tun] write task ended");
        }
        Some(msg) = err_rx.recv() => {
            log::warn!("[tun] {msg}");
        }
    }

    unsafe {
        let _ = libc::close(dup);
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run(
    _fd: i32,
    _outbound_tx: mpsc::Sender<Vec<u8>>,
    _inbound_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    Err(AetherError::Other("TUN not supported on this platform".into()))
}
