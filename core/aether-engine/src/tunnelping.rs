use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::masque_h2;
use crate::netstack;
use crate::noize::NoizeConfig;
use crate::quic;
use crate::socks;
use crate::wireguard;

const PING_MTU: usize = 1280;
const HTTP_PROBE_HOST: &str = "www.gstatic.com";
const HTTP_PROBE_PATH: &str = "/generate_204";

struct AbortGuard<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn http_probe_port() -> u16 {
    std::env::var("AETHER_IRONCLAD_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80)
}

async fn http_probe_to(stack: &netstack::StackHandle, dst: SocketAddr, host: &str) -> Result<()> {
    let conn = stack.open_tcp(dst).await?;
    let (sender, mut from_stack) = conn.into_split();

    let request = format!(
        "GET {HTTP_PROBE_PATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: aether-ironclad\r\n\r\n"
    );
    sender.send(request.into_bytes()).await?;

    let mut buf = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(8), from_stack.recv()).await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk);
                if buf.len() >= 12 {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => return Err(AetherError::Other("http probe response timeout".into())),
        }
    }

    sender.close().await;

    let status_line = String::from_utf8_lossy(&buf);
    // 204 (gstatic) or any 2xx/3xx proves the tunnel carries TCP.
    if status_line.contains(" 20") || status_line.contains(" 30") || status_line.contains("204") {
        Ok(())
    } else if buf.is_empty() {
        Err(AetherError::Other("http probe empty response".into()))
    } else {
        let first_line = status_line.lines().next().unwrap_or("").trim();
        Err(AetherError::Other(format!(
            "unexpected http probe response: {first_line}"
        )))
    }
}

async fn http_probe(stack: &netstack::StackHandle) -> Result<()> {
    let ip = socks::dns_resolve(stack, HTTP_PROBE_HOST).await?;
    http_probe_to(stack, SocketAddr::new(ip, http_probe_port()), HTTP_PROBE_HOST).await
}

/// TCP connectivity without DNS — works even when resolver path is flaky.
async fn tcp_ip_probe(stack: &netstack::StackHandle) -> Result<()> {
    // Cloudflare anycast HTTP (returns 301/400-ish but proves data plane).
    const TARGETS: &[(IpAddr, u16, &str)] = &[
        (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80, "1.1.1.1"),
        (IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 80, "1.0.0.1"),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53, "dns.google"),
    ];
    let mut last = AetherError::Other("tcp ip probe failed".into());
    for &(ip, port, host) in TARGETS {
        let dst = SocketAddr::new(ip, port);
        if port == 80 {
            match http_probe_to(stack, dst, host).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::debug!("[health] tcp http to {dst}: {e}");
                    last = e;
                }
            }
        } else {
            // Port 53: just establish TCP (DoT-ish connectivity check).
            match tokio::time::timeout(Duration::from_secs(6), stack.open_tcp(dst)).await {
                Ok(Ok(conn)) => {
                    conn.close().await;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    log::debug!("[health] tcp connect {dst}: {e}");
                    last = e;
                }
                Err(_) => {
                    last = AetherError::Other(format!("tcp connect timeout {dst}"));
                }
            }
        }
    }
    Err(last)
}

/// End-to-end probe on an already-running netstack.
/// Prefer IP-literal TCP (no DNS) so cold WireGuard tunnels still pass.
pub async fn live_stack_probe(stack: &netstack::StackHandle) -> Result<()> {
    match tcp_ip_probe(stack).await {
        Ok(()) => return Ok(()),
        Err(e) => log::debug!("[health] ip-literal probe failed ({e}); trying DNS+HTTP"),
    }
    match http_probe(stack).await {
        Ok(()) => Ok(()),
        Err(e) => {
            log::debug!("[health] named http probe failed ({e}); trying DNS-only");
            // Last resort: UDP DNS A query for a short name.
            let _ip = socks::dns_resolve(stack, "cloudflare.com").await?;
            Ok(())
        }
    }
}

pub struct MasquePingParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub noize: NoizeConfig,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv4_str: String,
    pub local_ipv6_str: String,
}

pub async fn masque_http_ping(p: &MasquePingParams, timeout: Duration) -> Result<Duration> {
    let attempt = async {
        let (chans, internals) = quic::channels();
        let quic::Channels {
            outbound_tx,
            inbound_rx,
            ctrl_tx,
        } = chans;

        let stack = netstack::spawn(
            &p.local_ipv4_str,
            &p.local_ipv6_str,
            PING_MTU,
            inbound_rx.map(bytes::Bytes::from),
            outbound_tx,
        )?;

        let (ready_tx, ready_rx) = oneshot::channel();

        let tunnel_task = if masque_h2::enabled() {
            let h2cfg = masque_h2::H2TunnelConfig {
                peer: masque_h2::h2_peer(p.peer),
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                path: p.path.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                local_ipv4: p.local_ipv4,
                quiet: true,
            };
            AbortGuard(tokio::spawn(masque_h2::run(h2cfg, internals, None, Some(ready_tx))))
        } else {
            let cfg = quic::TunnelConfig {
                peer: p.peer,
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                path: p.path.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                ech_config_list: None,
                noize: p.noize.clone(),
                local_ipv4: p.local_ipv4,
                quiet: true,
            };
            AbortGuard(tokio::spawn(quic::run(cfg, internals, None, Some(ready_tx))))
        };

        if ready_rx.await.is_err() {
            return Err(AetherError::Other(
                "tunnel exited before data-plane validation".into(),
            ));
        }

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(ctrl_tx);
        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}

pub struct WgPingParams {
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub aethernoize: AetherNoizeConfig,
}

pub async fn wg_http_ping_established(
    session: wireguard::EstablishedSession,
    p: &WgPingParams,
    timeout: Duration,
) -> Result<Duration> {
    let attempt = async {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1024);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1024);

        let tunnel = wireguard::WgTunnel::from_established(
            session,
            std::sync::Arc::new(p.aethernoize.clone()),
            inbound_tx,
        );

        let local_ipv4_str = p.local_ipv4.to_string();
        let local_ipv6_str = p.local_ipv6.to_string();
        let stack = netstack::spawn(
            &local_ipv4_str,
            &local_ipv6_str,
            PING_MTU,
            inbound_rx.map(bytes::Bytes::from),
            outbound_tx,
        )?;

        let tunnel_task = AbortGuard(tokio::spawn(tunnel.run(outbound_rx)));

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}
