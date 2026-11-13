//! Shared Psiphon exit plumbing for the TUN bridges.
//!
//! Psiphon sessions dial the exit through a loopback `socks5p` adapter so the
//! tunnel engine never sees a UDP ASSOCIATE (0x03) it cannot serve; DNS rides
//! the engine's UDP gateway instead. The bridges all need the same dance, so
//! it lives here once instead of in four copies with drifting error text.

use std::net::SocketAddr;

use crate::backend::Endpoints;
use crate::config::SessionConfig;
use crate::error::{CoreError, Result};
use crate::{socks5p, tun_dns};

/// The SOCKS endpoint the backend exposed for this session.
///
/// Every TUN bridge refuses to start without one; keeping the error in one
/// place keeps the message identical everywhere.
pub fn require_socks(endpoints: &Endpoints) -> Result<SocketAddr> {
    endpoints.socks.ok_or_else(|| {
        CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
    })
}

/// Start the loopback `socks5p` adapter for a Psiphon exit, if this session
/// uses one.
///
/// Returns the adapter (`None` for non-Psiphon sessions) and the SOCKS
/// address the bridge should actually dial. The caller keeps the adapter
/// alive for the session's lifetime — dropping it stops the loopback
/// listener. `tag` names the calling bridge in logs (`"hev"`, `"zeptun"`).
pub fn psiphon_socks5p(
    cfg: &SessionConfig,
    endpoints: &Endpoints,
    tag: &'static str,
) -> Result<(Option<socks5p::Adapter>, SocketAddr)> {
    let socks = require_socks(endpoints)?;
    if !endpoints.psiphon_dns {
        return Ok((None, socks));
    }
    let resolvers = tun_dns::psiphon_resolvers(cfg)?;
    if resolvers.is_empty() {
        log::info!("[{tag}] socks5p: Psiphon exit resolver through the UDP gateway");
    } else {
        log::info!("[{tag}] socks5p: TUN DNS {resolvers:?} through the Psiphon UDP gateway");
    }
    let adapter = socks5p::Adapter::start(tag, socks, resolvers)
        .map_err(|e| CoreError::Internal(format!("{tag} socks5p adapter: {e}")))?;
    let endpoint = adapter.endpoint();
    Ok((Some(adapter), endpoint))
}
