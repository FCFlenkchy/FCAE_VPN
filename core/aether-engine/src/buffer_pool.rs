//! A small process-wide pool of reusable byte buffers.
//!
//! The TUN read loop and the WireGuard encapsulate/decapsulate hot paths
//! previously allocated a fresh `Vec<u8>` for *every single packet*
//! (`buf[..n].to_vec()` in tun.rs, `pkt.to_vec()` in wireguard.rs). During
//! active transfer that's continuous allocator churn on the packet-rate
//! hot path — real CPU cost, and on Android, allocator pressure is a
//! genuine battery-relevant cost.
//!
//! This pool lets those call sites reuse an existing heap allocation
//! instead of asking the allocator for fresh memory on every packet.
//! Buffers taken from the TUN-read side flow through `split_dataplane()`
//! where they're converted to `Bytes` (zero-copy refcount) and fanned out
//! to both the netstack and TUN write task. The WireGuard side recycles
//! buffers back here after sending — closing the loop.
//!
//! Deliberately does NOT change any `mpsc` channel item types (still
//! `Vec<u8>` on the tunnel side, `Bytes` in the TUN bridge), so it
//! doesn't require touching the channel-creation code in the engine
//! crate root / ffi layer.

use once_cell::sync::Lazy;
use parking_lot::Mutex;

/// Upper bound on how many buffers we'll hold onto. Bounds memory use if
/// traffic bursts and then drops off, instead of letting the pool grow
/// unboundedly during a heavy transfer.
const MAX_POOLED: usize = 256;

static POOL: Lazy<Mutex<Vec<Vec<u8>>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(64)));

/// Take a buffer with at least `min_cap` capacity, cleared to zero length.
/// Reuses a pooled allocation if one big enough is available, otherwise
/// allocates a new one (so this is always correct, just not always free).
pub fn take(min_cap: usize) -> Vec<u8> {
    let mut pool = POOL.lock();
    if let Some(pos) = pool.iter().position(|b| b.capacity() >= min_cap) {
        let mut buf = pool.swap_remove(pos);
        buf.clear();
        buf
    } else {
        Vec::with_capacity(min_cap.max(64))
    }
}

/// Return a buffer's underlying storage to the pool for reuse. Once the
/// pool is at `MAX_POOLED`, extra buffers are simply dropped instead of
/// growing the pool further.
pub fn recycle(mut buf: Vec<u8>) {
    if buf.capacity() == 0 {
        return;
    }
    buf.clear();
    let mut pool = POOL.lock();
    if pool.len() < MAX_POOLED {
        pool.push(buf);
    }
    // else: let it drop — pool is already at capacity.
}
