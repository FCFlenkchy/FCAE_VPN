//! Optional TUN fd bridge (Android VpnService). No-op on platforms without fd support.
//! 
//! ⚠️ IMPORTANT: This file is for Android VpnService integration only.
//! Do NOT modify this file for Linux/Windows TUN support.
//! 
//! For Linux/Windows TUN support, see `tun_t2s.rs` which uses
//! tun2socks as the TUN engine.

use tokio::sync::mpsc;
use bytes::Bytes;

use crate::error::{AetherError, Result};

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::mem::ManuallyDrop;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(unix)]
use std::sync::OnceLock;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
#[cfg(unix)]
use tokio::sync::Notify;

#[cfg(unix)]
static TUN_FD: AtomicI32 = AtomicI32::new(-1);

// Saved dup'd fds so we can force-close them on shutdown.
// Without this, the dup'd copies keep the kernel TUN device alive
// even after Java closes the original ParcelFileDescriptor.
#[cfg(unix)]
static TUN_DUP_READ: AtomicI32 = AtomicI32::new(-1);
#[cfg(unix)]
static TUN_DUP_WRITE: AtomicI32 = AtomicI32::new(-1);

// Fired by close_all_fds() to wake any task parked waiting on fd
// readiness. We do NOT rely on epoll/kernel behavior to notice the fd
// was closed out from under it — closing a fd automatically deregisters
// it from epoll, so a task purely awaiting readiness on that fd could
// otherwise hang forever with no periodic wakeup to save it. Racing
// against this Notify makes shutdown deterministic instead of hoping
// the OS interrupts a blocked/parked task.
#[cfg(unix)]
static TUN_SHUTDOWN: OnceLock<Notify> = OnceLock::new();

#[cfg(unix)]
fn shutdown_notify() -> &'static Notify {
    TUN_SHUTDOWN.get_or_init(Notify::new)
}

pub fn set_fd(fd: i32) {
    #[cfg(unix)]
    TUN_FD.store(fd, Ordering::SeqCst);
    #[cfg(not(unix))]
    let _ = fd;
}

/// Force-close all dup'd TUN fds and wake any tasks waiting on them.
/// Called from aether_stop() to ensure the kernel tears down the TUN
/// device immediately, even if the read/write tasks are still parked.
///
/// Uses swap(-1) so that whichever path runs first (close_all_fds vs
/// run()'s cleanup) atomically claims ownership of each fd, preventing
/// double-close.
pub fn close_all_fds() {
    #[cfg(unix)]
    {
        let read_fd = TUN_DUP_READ.swap(-1, Ordering::SeqCst);
        let write_fd = TUN_DUP_WRITE.swap(-1, Ordering::SeqCst);
        if read_fd >= 0 {
            unsafe { libc::close(read_fd); }
            log::info!("[tun] force-closed dup read fd={read_fd}");
        }
        if write_fd >= 0 {
            unsafe { libc::close(write_fd); }
            log::info!("[tun] force-closed dup write fd={write_fd}");
        }
        // Also clear the original fd reference
        TUN_FD.store(-1, Ordering::SeqCst);

        // Wake any task parked in AsyncFd::readable()/writable() or
        // waiting on the shutdown signal directly — see TUN_SHUTDOWN doc.
        shutdown_notify().notify_waiters();
    }
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
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Thin AsRawFd wrapper so we can hand a raw fd to AsyncFd. Intentionally
/// has no Drop impl — fd lifecycle is fully managed via the TUN_DUP_*
/// atomics + close_all_fds(), never by this wrapper going out of scope.
#[cfg(unix)]
struct RawFdHandle(RawFd);

#[cfg(unix)]
impl AsRawFd for RawFdHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(unix)]
pub async fn run(
    fd: i32,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    mut inbound_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(AetherError::Other(format!(
            "tun dup failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    log::info!("[tun] bridging fd={fd} (dup={dup})");

    // AsyncFd requires a non-blocking fd — epoll readiness + a blocking
    // syscall underneath would defeat the point and risks the exact
    // "blocked in read(), close() doesn't wake it" problem this design
    // avoids. Android's VpnService fd is usually already non-blocking,
    // but we set it explicitly rather than assume.
    if let Err(e) = set_nonblocking(dup) {
        log::warn!("[tun] failed to set O_NONBLOCK on read fd: {e}");
    }

    let (err_tx, mut err_rx) = mpsc::channel::<String>(4);

    let out_tx = outbound_tx;
    let err_tx_r = err_tx.clone();
    let read_fd = dup;

    // Save read fd for force-close on shutdown
    TUN_DUP_READ.store(read_fd, Ordering::SeqCst);

    let read_task = tokio::spawn(async move {
        let async_fd = match AsyncFd::new(RawFdHandle(read_fd)) {
            Ok(a) => a,
            Err(e) => {
                let _ = err_tx_r.send(format!("tun asyncfd register: {e}")).await;
                return;
            }
        };

        loop {
            let mut guard = tokio::select! {
                r = async_fd.readable() => match r {
                    Ok(g) => g,
                    Err(e) => {
                        let _ = err_tx_r.send(format!("tun readable: {e}")).await;
                        break;
                    }
                },
                _ = shutdown_notify().notified() => {
                    log::info!("[tun] read task got shutdown signal");
                    break;
                }
            };

            // Pooled buffer avoids an allocation + extra memcpy per packet.
            let mut pkt = crate::buffer_pool::take(16384);
            let cap = pkt.capacity();
            // SAFETY: len set to capacity purely so read() has valid
            // mutable space to write into; truncated to actual bytes
            // read immediately below before pkt is ever inspected.
            unsafe { pkt.set_len(cap); }

            let read_result = guard.try_io(|inner| {
                let raw = inner.as_raw_fd();
                let n = unsafe {
                    libc::read(raw, pkt.as_mut_ptr() as *mut libc::c_void, cap)
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });

            match read_result {
                Ok(Ok(0)) => {
                    let _ = err_tx_r.send("tun eof".into()).await;
                    break;
                }
                Ok(Ok(n)) => {
                    unsafe { pkt.set_len(n); }
                    crate::stats::add_tx(n as u64);
                    if out_tx.send(pkt).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    crate::buffer_pool::recycle(pkt);
                    let _ = err_tx_r.send(format!("tun read: {e}")).await;
                    break;
                }
                Err(_would_block) => {
                    // Readiness was stale (spurious wakeup or another
                    // waiter drained it) — guard clears itself, loop
                    // back and wait for a fresh readiness notification.
                    crate::buffer_pool::recycle(pkt);
                    continue;
                }
            }
        }
    });

    let write_fd = unsafe { libc::dup(dup) };
    if write_fd < 0 {
        return Err(AetherError::Other("tun write dup failed".into()));
    }

    // Save write fd for force-close on shutdown
    TUN_DUP_WRITE.store(write_fd, Ordering::SeqCst);

    let write_task = tokio::spawn(async move {
        // Use ManuallyDrop so File::drop() NEVER closes the fd.
        // When the runtime is dropped, this async task is cancelled and
        // drop() would run — but close_all_fds() already owns the fd via
        // the atomic. Without ManuallyDrop, cancelling this task causes
        // a double-close crash on Android disconnect.
        let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(write_fd) });
        loop {
            tokio::select! {
                pkt = inbound_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    // NOTE: no add_rx here — netstack.rs already counts
                    // inbound packets via the split_dataplane fan-out.
                    // Counting here too would double the download stats.
                    if let Err(e) = file.write_all(&pkt) {
                        log::warn!("[tun] write: {e}");
                        break;
                    }
                    // Bytes is refcounted — drops automatically when last reference is gone.
                }
                _ = shutdown_notify().notified() => {
                    log::info!("[tun] write task got shutdown signal");
                    break;
                }
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

    // Make sure the loser of the select above also gets told to stop,
    // in case it wasn't already covered by close_all_fds() having run.
    shutdown_notify().notify_waiters();

    // Clear saved fds — use swap so we atomically claim ownership.
    // If close_all_fds() already swapped them to -1, we skip the close
    // (it already did it). If not, we own them and must close.
    let saved_read = TUN_DUP_READ.swap(-1, Ordering::SeqCst);
    let saved_write = TUN_DUP_WRITE.swap(-1, Ordering::SeqCst);
    if saved_read >= 0 {
        unsafe { libc::close(saved_read); }
    }
    if saved_write >= 0 {
        unsafe { libc::close(saved_write); }
    }

    Ok(())
}

#[cfg(not(unix))]
pub async fn run(
    _fd: i32,
    _outbound_tx: mpsc::Sender<Vec<u8>>,
    _inbound_rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    Err(AetherError::Other("TUN not supported on this platform".into()))
}
