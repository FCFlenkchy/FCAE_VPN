#![allow(dead_code)]
mod account;
mod cli;
mod config;
mod consts;
mod dns;
pub mod error;
mod fragment;
mod lastconn;
mod masque;
mod masque_h2;
mod netstack;
mod noize;
mod prober;
mod quic;
mod socks;
mod http_proxy;
mod stats;
mod tls;
mod aethernoize;
mod tunnelping;
pub mod tun;
mod wireguard;
mod wg_prober;

/// Public traffic counters for the FFI / GUI.
pub use stats::{
    add_rx, add_tx, rates, reset as reset_stats, rtt_ms, set_rtt_ms, total_rx, total_tx,
};


use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use error::{AetherError, Result};

fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

const TUNNEL_MTU: usize = 1420;
const INNER_MTU: usize = 1400;
const DEFAULT_CONFIG: &str = "aether.toml";

/// TLS Server Name (SNI) for MASQUE. Override with AETHER_SNI / --sni.
fn connect_sni() -> String {
    std::env::var("AETHER_SNI")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| consts::CONNECT_SNI.to_string())
}

fn tun_mode_active() -> bool {
    matches!(
        std::env::var("AETHER_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "tun" | "1" | "true" | "vpn"
    ) && tun::resolve_fd().is_some()
}

/// Post-scan validation: ironclad = real HTTP through tunnel; handshake = probe only.
fn ironclad_validate() -> bool {
    match std::env::var("AETHER_VALIDATE")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "ironclad" | "http" | "real" | "1" | "true" | "yes" | "on" => true,
        _ => false,
    }
}

fn health_interval() -> std::time::Duration {
    let secs = std::env::var("AETHER_HEALTH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(20);
    std::time::Duration::from_secs(secs)
}

fn health_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_HEALTH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5);
    std::time::Duration::from_secs(secs)
}

fn health_max_fails() -> u32 {
    std::env::var("AETHER_HEALTH_MAX_FAILS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(2)
}

fn live_validate_timeout() -> std::time::Duration {
    // Pre-SOCKS validation needs more headroom than background health probes
    // (handshake settle + DNS + HTTP through a cold tunnel).
    let secs = std::env::var("AETHER_LIVE_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

/// Probe the live netstack before exposing SOCKS (DNS + optional HTTP).
async fn validate_live_stack(stack: &netstack::StackHandle, label: &str) -> Result<()> {
    if std::env::var("AETHER_NO_LIVE_CHECK").is_ok() {
        return Ok(());
    }
    let timeout = live_validate_timeout();
    log::info!("[*] validating live {label} data-plane before exposing SOCKS (timeout {timeout:?})");
    // A few retries — cold WG/MASQUE often needs 1–2 attempts after handshake.
    let mut last_err = AetherError::Other("live validation failed".into());
    for attempt in 1..=3u32 {
        match tokio::time::timeout(timeout, tunnelping::live_stack_probe(stack)).await {
            Ok(Ok(())) => {
                log::info!("[+] live {label} data-plane OK (attempt {attempt})");
                return Ok(());
            }
            Ok(Err(e)) => {
                last_err = AetherError::Other(format!("live {label} validation failed: {e}"));
                log::debug!("[-] live {label} attempt {attempt}/3: {e}");
            }
            Err(_) => {
                last_err = AetherError::Other(format!(
                    "live {label} validation timeout ({timeout:?})"
                ));
                log::debug!("[-] live {label} attempt {attempt}/3: timeout");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
    }
    Err(last_err)
}

/// Background health monitor: consecutive failed probes abort the tunnel task.
fn spawn_health_monitor(
    stack: netstack::StackHandle,
    shutdown: tokio::sync::oneshot::Sender<()>,
) -> tokio::task::JoinHandle<()> {
    let interval = health_interval();
    let max_fails = health_max_fails();
    let probe_timeout = health_timeout().max(std::time::Duration::from_secs(8));
    // Give the tunnel 2 full intervals to stabilize before counting failures.
    // Using 1x caused the first probe (at t=interval) to land exactly on the
    // grace boundary, so a single transient failure immediately killed the tunnel.
    let grace = interval * 2;
    tokio::spawn(async move {
        let mut fails = 0u32;
        let started = std::time::Instant::now();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // skip first immediate tick
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let ok = match tokio::time::timeout(probe_timeout, tunnelping::live_stack_probe(&stack))
                .await
            {
                Ok(Ok(())) => true,
                Ok(Err(e)) => {
                    log::debug!("[health] probe failed: {e}");
                    false
                }
                Err(_) => {
                    log::debug!("[health] probe timeout");
                    false
                }
            };
            if ok {
                fails = 0;
            } else if started.elapsed() < grace {
                log::debug!(
                    "[health] probe failed during grace ({:?} left); not counting",
                    grace.saturating_sub(started.elapsed())
                );
            } else {
                fails += 1;
                log::warn!("[health] consecutive failures {fails}/{max_fails}");
                if fails >= max_fails {
                    log::warn!("[health] tunnel considered dead; forcing reconnect");
                    let _ = shutdown.send(());
                    return;
                }
            }
        }
    })
}

async fn spawn_local_proxies(
    stack: netstack::StackHandle,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
) -> (Option<tokio::task::JoinHandle<Result<()>>>, Option<tokio::task::JoinHandle<()>>) {
    let socks_task = listen.map(|addr| {
        let socks_stack = stack.clone();
        tokio::spawn(async move {
            log::info!("[+] socks5 server listening on {addr}");
            socks::serve(addr, socks_stack).await
        })
    });
    let http_task = http_listen.map(|http_addr| {
        let http_stack = stack.clone();
        tokio::spawn(async move {
            log::info!("[+] http proxy listening on {http_addr}");
            if let Err(e) = http_proxy::serve(http_addr, http_stack).await {
                log::warn!("[-] http proxy ended: {e}");
            }
        })
    });
    (socks_task, http_task)
}
/// Blocking CLI entry used by the optional binary target.
pub fn run_cli() -> Result<()> {
    cli::parse_and_apply()?;
    let default_filter = if std::env::var("AETHER_VERBOSE").is_ok() {
        "info,aether=debug"
    } else {
        "info"
    };
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp_millis()
        .try_init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| AetherError::Other(format!("tokio runtime: {e}")))?;
    rt.block_on(run_from_env())
}

/// Run the engine using AETHER_* environment variables (set by CLI or FFI).
/// Does not parse argv or initialize the global logger (caller owns that).
pub async fn run_from_env() -> Result<()> {
    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    install_netstack_panic_guard();

    let socks_disabled = std::env::var("AETHER_SOCKS_DISABLED").is_ok();
    let http_disabled = std::env::var("AETHER_HTTP_DISABLED").is_ok();

    let listen: Option<SocketAddr> = if socks_disabled {
        None
    } else {
        std::env::var("AETHER_SOCKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|a: &SocketAddr| a.port() != 0)
    };

    let http_listen: Option<SocketAddr> = if http_disabled {
        None
    } else {
        std::env::var("AETHER_HTTP")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|a: &SocketAddr| a.port() != 0)
            .or_else(|| {
                let port: u16 = std::env::var("AETHER_HTTP_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(1820);
                match listen {
                    Some(addr) if port != 0 && port != addr.port() => {
                        Some(SocketAddr::new(addr.ip(), port))
                    }
                    _ => None,
                }
            })
    };

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    // Prefer env (GUI/FFI always sets AETHER_PROTOCOL). Only prompt in interactive CLI.
    let protocol = match std::env::var("AETHER_PROTOCOL") {
        Ok(v) => Protocol::parse(&v),
        Err(_) => {
            if std::env::var("AETHER_PEER").is_ok() || std::env::var("AETHER_WG_PEER").is_ok() {
                Protocol::Masque
            } else {
                select_protocol().await
            }
        }
    };

    match protocol {
        Protocol::Masque => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let ech = resolve_ech().await;
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, ech, listen, http_listen, lastconn_path).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            let lastconn_path = lastconn_path(&config_path);
            run_wireguard(identity, listen, http_listen, lastconn_path).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id, primary.ipv4, secondary.device_id, secondary.ipv4
            );
            let peer = select_peer(&primary, Protocol::WireGuard).await?;
            log::info!("[+] using cloudflare edge {peer} (outer)");
            run_warp_in_warp(primary, secondary, peer, listen, http_listen).await
        }
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config() -> noize::NoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

fn warp_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_WG_CONFIG") {
        return p;
    }
    base.to_string()
}

fn masque_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    derive_sibling_path(base, "masque")
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base.rfind(|c| c == '/' || c == '\\').map(|i| i + 1).unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        return Ok(identity);
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        if identity.has_masque_credentials() {
            return Ok(identity);
        }
        log::info!("[+] masque identity missing credentials; enrolling masque key");
        let (cert_pem, key_pem) = account::ensure_masque_enrolled(&identity).await?;
        let identity = account::Identity { cert_pem, key_pem, ..identity };
        config::save(config_path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    let (cert_pem, key_pem) = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity { cert_pem, key_pem, ..identity };
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };
    
    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;

        match protocol {
            Protocol::Masque => {
                log::info!("[+] using forced MASQUE peer {peer}; probing RTT...");
                let params = tunnelping::MasquePingParams {
                    peer,
                    sni: connect_sni(),
                    authority: quic::default_authority().to_string(),
                    path: quic::default_path().to_string(),
                    cert_pem: identity.cert_pem.clone(),
                    key_pem: identity.key_pem.clone(),
                    noize: noize_config(),
                    local_ipv4: parse_local_v4(&identity.ipv4),
                    local_ipv4_str: identity.ipv4.clone(),
                    local_ipv6_str: String::new(),
                };
                match tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    tunnelping::masque_http_ping(&params, std::time::Duration::from_secs(5)),
                )
                .await
                {
                    Ok(Ok(rtt)) => {
                        log::info!("[+] forced peer {peer} RTT: {:?}", rtt);
                        stats::set_rtt_ms(rtt.as_millis() as u64);
                    }
                    _ => {
                        log::warn!("[-] forced peer {peer} RTT probe failed; continuing anyway");
                    }
                }
            }
            Protocol::WireGuard | Protocol::WarpInWarp => {
                log::info!("[+] using forced WireGuard peer {peer}; probing RTT...");
                let private_key = identity.private_key_bytes()?;
                let peer_public = identity.peer_public_key_bytes()?;
                let profile = aethernoize_config();
                match wireguard::verify_endpoint(
                    peer,
                    private_key,
                    peer_public,
                    identity.client_id,
                    parse_local_v4(&identity.ipv4),
                    &profile,
                    std::time::Duration::from_secs(10),
                )
                .await
                {
                    Ok(rtt) => {
                        log::info!("[+] forced WireGuard peer {peer} RTT: {:?}", rtt);
                        stats::set_rtt_ms(rtt.as_millis() as u64);
                    }
                    Err(e) => {
                        log::warn!("[-] forced WireGuard peer {peer} probe failed: {e}; continuing anyway");
                    }
                }
            }
        }
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());
    
    let mode_str = select_scan_mode_str().await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            let mode = prober::ScanMode::parse(&mode_str);
            let probe = prober::MasqueProbe {
                sni: connect_sni(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip,
                local_ipv4: parse_local_v4(&identity.ipv4),
            };

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!("[+] selected MASQUE gateway {}:{} (rtt {:?})", best.ip, best.port, best.rtt);
            stats::set_rtt_ms(best.rtt.as_millis() as u64);
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            log::info!("[*] hunting for a working WireGuard endpoint (handshake + data-plane verification)");
            let mode = wg_prober::WgScanMode::parse(&mode_str);
            
            let private_key = identity.private_key_bytes()?;
            let peer_public = identity.peer_public_key_bytes()?;
            
            let probe = wg_prober::WgProbe {
                private_key: std::sync::Arc::new(private_key),
                peer_public_key: std::sync::Arc::new(peer_public),
                client_id: identity.client_id.clone(),
                local_ipv4: identity.ipv4.parse().map_err(|_| AetherError::Other("invalid ipv4".into()))?,
                aethernoize: aethernoize_config(),
                ports: wireguard::WG_PORTS.to_vec(),
                ip,
            };

            let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
            log::info!("[+] selected WireGuard endpoint {}:{} (rtt {:?})", best.ip, best.port, best.rtt);
            stats::set_rtt_ms(best.rtt.as_millis() as u64);
            Ok(SocketAddr::new(best.ip, best.port))
        }
    }
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!("[+] fetched ECHConfigList automatically ({} bytes)", raw.len());
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
) -> Result<SocketAddr> {
    log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)");
    let mode = prober::ScanMode::parse(mode_str);
    let probe = prober::MasqueProbe {
        sni: connect_sni(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: None,
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    let best = prober::hunt_best_gateway(&probe, mode).await?;
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    stats::set_rtt_ms(best.rtt.as_millis() as u64);
    Ok(SocketAddr::new(best.ip, best.port))
}


fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

async fn quick_verify_masque_peer(identity: &account::Identity, peer: SocketAddr) -> bool {
    let vp = quic::VerifyParams {
        peer,
        sni: connect_sni(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        timeout: std::time::Duration::from_secs(5),
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: connect_sni(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        return masque_h2::verify_h2(&cfg, std::time::Duration::from_secs(5))
            .await
            .is_ok();
    }

    quic::verify_masque(&vp).await.is_ok()
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

async fn run_masque(
    identity: account::Identity,
    ech: Option<Vec<u8>>,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
    lastconn_path: String,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();

    let mut quick_peer: Option<SocketAddr> = None;
    if forced.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    log::info!("[*] verifying cached gateway {peer} before reuse");
                    if quick_verify_masque_peer(&identity, peer).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                    } else {
                        log::warn!("[-] cached gateway {peer} no longer works; scanning fresh");
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick_peer.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str().await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if quick_verify_masque_peer(&identity, p).await {
                        Some(p)
                    } else {
                        log::warn!("[-] last known-good gateway {p} no longer responds; rescanning");
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(p) => p,
                None => match &forced {
                    Some(p) => match p.parse::<SocketAddr>() {
                        Ok(peer) => {
                            log::info!("[+] using forced peer {peer}; probing RTT...");
                            let params = tunnelping::MasquePingParams {
                                peer,
                                sni: connect_sni(),
                                authority: quic::default_authority().to_string(),
                                path: quic::default_path().to_string(),
                                cert_pem: identity.cert_pem.clone(),
                                key_pem: identity.key_pem.clone(),
                                noize: noize_config(),
                                local_ipv4: parse_local_v4(&identity.ipv4),
                                local_ipv4_str: identity.ipv4.clone(),
                                local_ipv6_str: String::new(),
                            };
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(8),
                                tunnelping::masque_http_ping(&params, std::time::Duration::from_secs(5)),
                            )
                            .await
                            {
                                Ok(Ok(rtt)) => {
                                    log::info!("[+] forced peer {peer} RTT: {:?}", rtt);
                                    stats::set_rtt_ms(rtt.as_millis() as u64);
                                }
                                _ => {
                                    log::warn!("[-] forced peer {peer} RTT probe failed; continuing anyway");
                                }
                            }
                            peer
                        }
                        Err(_) => return Err(AetherError::Other(format!("bad peer address {p}"))),
                    },
                    None => match hunt_masque_peer(&identity, &mode_str, ip).await {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!("[-] no usable MASQUE gateway found: {e}; rescanning shortly");
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
            lastconn::save(&lastconn_path, &peer.to_string(), &profile);
        }

        last_good_peer = Some(peer);

        match run_masque_tunnel(&identity, peer, ech.clone(), listen, http_listen).await {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

type TunBridge = (
    i32,
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
);

/// Wire tunnel channels to netstack. Only fan-out when a real TUN fd is present
/// (Android VpnService). Proxy-only mode keeps the original direct path.
fn split_dataplane(
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> (
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Option<TunBridge>,
) {
    let Some(fd) = (if tun_mode_active() {
        tun::resolve_fd()
    } else {
        None
    }) else {
        // Direct: netstack ↔ tunnel (same as pre-TUN-bridge behavior).
        return (outbound_tx, inbound_rx, None);
    };

    let (ns_out_tx, mut ns_out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    let (ns_in_tx, ns_in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    let (tun_in_tx, tun_in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);

    let ot_ns = outbound_tx.clone();
    tokio::spawn(async move {
        while let Some(p) = ns_out_rx.recv().await {
            if ot_ns.send(p).await.is_err() {
                break;
            }
        }
    });

    // Tunnel → netstack + TUN (clone each IP packet).
    let mut inbound_rx = inbound_rx;
    tokio::spawn(async move {
        while let Some(p) = inbound_rx.recv().await {
            let _ = ns_in_tx.send(p.clone()).await;
            let _ = tun_in_tx.send(p).await;
        }
    });

    // TUN reads are sent on `outbound_tx` (shared with netstack via ot_ns clone above).
    (ns_out_tx, ns_in_rx, Some((fd, outbound_tx, tun_in_rx)))
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
) -> Result<()> {
    let (chans, internals) = quic::channels();

    let cfg = quic::TunnelConfig {
        peer,
        sni: connect_sni(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech,
        noize: noize_config(),
        local_ipv4: parse_local_v4(&identity.ipv4),
        quiet: false,
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;
    let _ctrl = ctrl_tx;

    let (ns_out_tx, ns_in_rx, tun_bridge) = split_dataplane(outbound_tx, inbound_rx);

    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        ns_in_rx,
        ns_out_tx,
    )?;

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let bridge_stack = stack.clone();
    tokio::spawn(async move {
        while let Some(a) = addr_rx.recv().await {
            let res = match a.ip {
                IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
            };
            if let Err(e) = res {
                log::warn!("[-] failed to sync edge address into netstack: {e}");
            }
        }
    });

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if masque_h2::enabled() {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: connect_sni(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        log::info!("[+] MASQUE transport: HTTP/2 (TCP) to {}", h2cfg.peer);
        tokio::spawn(masque_h2::run(h2cfg, internals, Some(addr_tx), Some(ready_tx)))
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {}", peer);
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };

    match ready_rx.await {
        Ok(()) => {}
        Err(_) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => "tunnel exited before validation".to_string(),
                Ok(Err(e)) => format!("tunnel failed before validation: {e}"),
                Err(e) => format!("tunnel task join error: {e}"),
            };
            return Err(AetherError::Other(msg));
        }
    }

    let mut tun_task = None;
    if let Some((fd, ot, tun_rx)) = tun_bridge {
        log::info!("[+] TUN mode: bridging Android/system fd={fd}");
        tun_task = Some(tokio::spawn(async move {
            if let Err(e) = tun::run(fd, ot, tun_rx).await {
                log::warn!("[-] tun bridge ended: {e}");
            }
        }));
    }

    // Re-validate on the live stack before SOCKS (avoids false positives after reconnect).
    if let Err(e) = validate_live_stack(&stack, "MASQUE").await {
        tunnel_task.abort();
        if let Some(t) = tun_task {
            t.abort();
        }
        return Err(e);
    }

    let (health_tx, health_rx) = tokio::sync::oneshot::channel::<()>();
    // Keep a StackHandle clone alive so the netstack task is NOT dropped
    // when socks/http/health tasks are aborted on health-check failure.
    let _stack_keepalive = stack.clone();
    let health_task = spawn_health_monitor(stack.clone(), health_tx);
    let (socks_task, http_task) = spawn_local_proxies(stack, listen, http_listen).await;

    enum End {
        Tunnel(std::result::Result<Result<()>, tokio::task::JoinError>),
        Health,
    }
    let end = tokio::select! {
        r = tunnel_task => End::Tunnel(r),
        _ = health_rx => End::Health,
    };
    if let Some(t) = socks_task {
        t.abort();
    }
    health_task.abort();
    if let Some(t) = http_task {
        t.abort();
    }
    if let Some(t) = tun_task {
        t.abort();
    }

    match end {
        End::Health => Err(AetherError::Other("tunnel health check failed".into())),
        End::Tunnel(Ok(Ok(()))) => Ok(()),
        End::Tunnel(Ok(Err(e))) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
        End::Tunnel(Err(e)) => Err(AetherError::Other(format!("tunnel task join error: {e}"))),
    }
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "chrome", "aggressive", "light", "off"] {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(fallback)) {
                names.push(fallback.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|n| {
            let cfg = aethernoize::from_profile(&n);
            (n, cfg)
        })
        .collect()
}

async fn hunt_wg_peer_with_profile(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    profile: aethernoize::AetherNoizeConfig,
) -> Result<SocketAddr> {
    let mode = wg_prober::WgScanMode::parse(mode_str);
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id,
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: profile,
        ports: wireguard::WG_PORTS.to_vec(),
        ip,
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    stats::set_rtt_ms(best.rtt.as_millis() as u64);
    Ok(SocketAddr::new(best.ip, best.port))
}

fn wg_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let multi = candidates.len() > 1;
    for (name, profile) in candidates {
        log::info!(
            "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='{name}')"
        );
        match hunt_wg_peer_with_profile(identity, mode_str, ip, profile.clone()).await {
            Ok(peer) => {
                log::info!("[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'");
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(e) => {
                if multi {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}; trying next profile");
                } else {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}");
                }
            }
        }
    }
    Err(AetherError::NoCleanEndpoint)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
    lastconn_path: String,
) -> Result<()> {
    let candidates = wg_profile_candidates();

    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    if forced.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let profile = aethernoize::from_profile(&cached.profile);
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        &profile,
                        std::time::Duration::from_secs(6),
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!("[+] cached endpoint {peer} still works (rtt {:?}); skipping scan", rtt);
                            quick = Some((peer, profile, cached.profile.clone()));
                        }
                        Err(e) => {
                            log::warn!("[-] cached endpoint {peer} no longer works ({e}); scanning fresh");
                        }
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        let mode_str = select_scan_mode_str().await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    loop {
        let (peer, profile, profile_name) = if let Some(q) = quick.take() {
            q
        } else {
            let retried = match &last_good {
                Some((p, profile, _)) => {
                    log::info!("[*] retrying last known-good WireGuard endpoint {p} before rescanning");
                    match wireguard::verify_endpoint(
                        *p,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        profile,
                        std::time::Duration::from_secs(6),
                    )
                    .await
                    {
                        Ok(_) => Some(last_good.clone().unwrap()),
                        Err(e) => {
                            log::warn!("[-] last known-good endpoint {p} no longer responds ({e}); rescanning");
                            None
                        }
                    }
                }
                None => None,
            };

            match retried {
                Some(v) => v,
                None => {
                    if let Some(ref p) = forced {
                        let peer: SocketAddr = p
                            .parse()
                            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!("[*] testing forced peer {peer} with aethernoize profile '{name}'");
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public,
                                identity.client_id,
                                ipv4,
                                profile,
                                std::time::Duration::from_secs(10),
                            )
                            .await
                            {
                                Ok(rtt) => {
                                    log::info!("[+] profile '{}' passed handshake + data-plane (rtt {:?})", name, rtt);
                                    stats::set_rtt_ms(rtt.as_millis() as u64);
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("[-] profile '{name}' failed on forced peer: {e}");
                                }
                            }
                        }
                        match chosen {
                            Some(v) => v,
                            None => return Err(AetherError::NoCleanEndpoint),
                        }
                    } else {
                        match hunt_wg_peer(&identity, &candidates, &mode_str, ip).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("[-] no usable WireGuard endpoint found: {e}; rescanning shortly");
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            lastconn::save(&lastconn_path, &peer.to_string(), &profile_name);
        }

        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen, http_listen).await {
            Ok(()) => log::warn!("[-] WireGuard tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
) -> Result<()> {
    log::info!("[*] establishing WireGuard tunnel with {peer} (already verified during scan)...");

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity.ipv4.parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;
    let ipv6: std::net::Ipv6Addr = identity.ipv6.parse()
        .map_err(|_| AetherError::Other("invalid ipv6".into()))?;

    let cfg = wireguard::WgConfig {
        local_private_key: private_key,
        peer_public_key: peer_public,
        peer_endpoint: peer,
        local_ipv4: ipv4,
        local_ipv6: ipv6,
        client_id: identity.client_id,
        preshared_key: None,
        persistent_keepalive: Some(wg_keepalive_secs()),
        aethernoize: std::sync::Arc::new(aethernoize),
    };

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1024);
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1024);

    let tunnel = wireguard::WgTunnel::new(cfg, inbound_tx).await?;

    let (ns_out_tx, ns_in_rx, tun_bridge) = split_dataplane(outbound_tx, inbound_rx);
    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        ns_in_rx,
        ns_out_tx,
    )?;

    // Run tunnel first so live validation can pass traffic.
    let tunnel_task = tokio::spawn(async move { tunnel.run(outbound_rx).await });

    let mut tun_task = None;
    if let Some((fd, ot, tun_rx)) = tun_bridge {
        log::info!("[+] TUN mode: bridging Android/system fd={fd}");
        tun_task = Some(tokio::spawn(async move {
            if let Err(e) = tun::run(fd, ot, tun_rx).await {
                log::warn!("[-] tun bridge ended: {e}");
            }
        }));
    }

    // Brief settle for WG handshake + keepalive path.  The health-check grace
    // period (2x interval) handles the rest — no need for a long sleep here.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // WireGuard was verified on a throwaway session; re-check the LIVE stack
    // before SOCKS (fixes false positives on quick-reconnect / Ironclad).
    if let Err(e) = validate_live_stack(&stack, "WireGuard").await {
        tunnel_task.abort();
        if let Some(t) = tun_task {
            t.abort();
        }
        return Err(e);
    }

    let (health_tx, health_rx) = tokio::sync::oneshot::channel::<()>();
    // Keep a StackHandle clone alive so the netstack task is NOT dropped
    // when socks/http/health tasks are aborted on health-check failure.
    let _stack_keepalive = stack.clone();
    let health_task = spawn_health_monitor(stack.clone(), health_tx);
    let (socks_task, http_task) = spawn_local_proxies(stack, listen, http_listen).await;

    enum End {
        Tunnel(std::result::Result<Result<()>, tokio::task::JoinError>),
        Health,
    }
    let end = tokio::select! {
        r = tunnel_task => End::Tunnel(r),
        _ = health_rx => End::Health,
    };
    if let Some(t) = socks_task {
        t.abort();
    }
    health_task.abort();
    if let Some(t) = http_task {
        t.abort();
    }
    if let Some(t) = tun_task {
        t.abort();
    }

    match end {
        End::Health => Err(AetherError::Other("tunnel health check failed".into())),
        End::Tunnel(Ok(Ok(()))) => Ok(()),
        End::Tunnel(Ok(Err(e))) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
        End::Tunnel(Err(e)) => Err(AetherError::Other(format!("wireguard task join: {e}"))),
    }
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<netstack::StackHandle> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;
    let ipv6: std::net::Ipv6Addr = identity
        .ipv6
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv6".into()))?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    let cfg = wireguard::WgConfig {
        local_private_key: private_key,
        peer_public_key: peer_public,
        peer_endpoint: peer,
        local_ipv4: ipv4,
        local_ipv6: ipv6,
        client_id: identity.client_id,
        preshared_key: None,
        persistent_keepalive: Some(keepalive),
        aethernoize: std::sync::Arc::new(profile),
    };

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1024);
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1024);

    let tunnel = wireguard::WgTunnel::new(cfg, inbound_tx).await?;
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    tokio::spawn(async move {
        if let Err(e) = tunnel.run(outbound_rx).await {
            log::error!("[{label}] wireguard tunnel exited: {e}");
        }
    });

    Ok(stack)
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<SocketAddr> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match up_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    *up_peer.lock().await = Some(from);
                    if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    Ok(local)
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    listen: Option<SocketAddr>,
    http_listen: Option<SocketAddr>,
) -> Result<()> {
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let outer_stack = establish_wg(&primary, peer, TUNNEL_MTU, true, 5, "outer").await?;

    // Outer needs time for handshake + first data before inner can forward.
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    // Validate the outer tunnel before building the inner tunnel on top of it.
    if let Err(e) = validate_live_stack(&outer_stack, "outer WARP").await {
        log::warn!("[-] outer WARP validation failed: {e}; inner tunnel may not work");
    }

    let forwarder = spawn_udp_forwarder(&outer_stack, peer).await?;
    log::info!("[+] inner endpoint tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let inner_stack = establish_wg(&secondary, forwarder, INNER_MTU, false, 20, "inner").await?;

    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    if let Err(e) = validate_live_stack(&inner_stack, "WARP-in-WARP").await {
        return Err(e);
    }

    let (health_tx, health_rx) = tokio::sync::oneshot::channel::<()>();
    let health_task = spawn_health_monitor(inner_stack.clone(), health_tx);
    let (socks_task, http_task) = spawn_local_proxies(inner_stack, listen, http_listen).await;

    enum End {
        Socks(std::result::Result<Result<()>, tokio::task::JoinError>),
        Health,
    }
    let end = if let Some(task) = socks_task {
        tokio::select! {
            r = task => End::Socks(r),
            _ = health_rx => End::Health,
        }
    } else {
        End::Health
    };
    health_task.abort();
    if let Some(t) = http_task {
        t.abort();
    }
    match end {
        End::Health => Err(AetherError::Other("tunnel health check failed".into())),
        End::Socks(Ok(Ok(()))) => Ok(()),
        End::Socks(Ok(Err(e))) => Err(e),
        End::Socks(Err(e)) => Err(AetherError::Other(format!("socks task join: {e}"))),
    }
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode (discovery speed):\n  [1] turbo     (fast, first hit)\n  [2] balanced  (thorough)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\nChoose [1-4] (default 1): ";

const VALIDATE_PROMPT: &str = "\nValidate candidates with:\n  [1] handshake / dataplane ping (default, fast)\n  [2] ironclad — real tunnel + HTTP on top candidates only\nChoose [1-2] (default 1): ";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("2") => prober::ScanMode::Balanced,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        _ => prober::ScanMode::Turbo,
    }
}

async fn select_scan_mode_str() -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;
    let mode = match answer.as_deref() {
        Some("2") => "balanced".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        _ => "turbo".to_string(),
    };

    // Optional ironclad validation (independent of scan mode).
    if std::env::var("AETHER_VALIDATE").is_err() && std::env::var("AETHER_NONINTERACTIVE").is_err()
    {
        let v = prompt_line(VALIDATE_PROMPT).await;
        if matches!(v.as_deref(), Some("2")) {
            std::env::set_var("AETHER_VALIDATE", "ironclad");
            log::info!("[+] validation mode: ironclad (post-scan HTTP check on top candidates)");
        }
    }

    mode
}

async fn select_protocol() -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }
    if std::env::var("AETHER_NONINTERACTIVE").is_ok() {
        return Protocol::Masque;
    }

    let answer = prompt_line(
        "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => Protocol::WarpInWarp,
        _ => Protocol::Masque,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok()
        || std::env::var("AETHER_PEER").is_ok()
        || std::env::var("AETHER_NONINTERACTIVE").is_ok()
    {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}
