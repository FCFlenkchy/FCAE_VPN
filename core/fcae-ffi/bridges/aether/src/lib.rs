#![recursion_limit = "512"]

mod rates;

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fcae_abi::{FcaeState, FcaeTorMode};
use fcae_runtime::backend::{
    Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints,
};
use fcae_runtime::config::{env_compat, SessionConfig};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::telemetry::TelemetrySink;
use parking_lot::Mutex;
use serde_json::Value;

pub fn register() {
    fcae_runtime::registry::register(fcae_abi::FcaeBackend::Aether, || Arc::new(AetherBackend));
}

pub struct AetherBackend;

#[async_trait]
impl Backend for AetherBackend {
    fn id(&self) -> BackendId { BackendId::Aether }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            gateway_scanning: true,
            routing_rules: true,
            requires_privileges: false,
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let cfg = cx.config.clone();
        if cfg.tor.is_enabled() && !cfg!(feature = "tor") {
            return Err(CoreError::InvalidConfig(format!(
                "tor mode `{}` was requested but this build has no tor support",
                tor_mode_label(cfg.tor.mode)
            )));
        }

        env_compat::apply(&cfg);
        cx.report(FcaeState::Scanning, "Establishing tunnel…");

        let job = ffi_start()?;
        let engine_socks = if cfg.tor.mode == FcaeTorMode::Only {
            local_dial_addr(cfg.tor.bind.as_deref().ok_or_else(|| {
                CoreError::InvalidConfig("tor is enabled but no bind address was provided".into())
            })?)?
        } else {
            format!("127.0.0.1:{}", cfg.socks_port)
                .parse()
                .map_err(|e| CoreError::InvalidConfig(format!("bad socks address: {e}")))?
        };
        let socks_addr = if cfg.tor.mode == FcaeTorMode::Chain {
            local_dial_addr(cfg.tor.bind.as_deref().ok_or_else(|| {
                CoreError::InvalidConfig("tor is enabled but no bind address was provided".into())
            })?)?
        } else {
            engine_socks
        };

        cx.report(FcaeState::Connecting, "Establishing tunnel…");
        let timeout = if cfg.tor.is_enabled() { cfg.tor_start_timeout() } else { cfg.start_timeout() };
        let ready = if cfg.tor.is_enabled() {
            wait_for_socks(socks_addr, timeout, job).await?
        } else {
            wait_for_listener(socks_addr, timeout, job).await?
        };
        if !ready {
            ffi_cancel(job);
            ffi_free(job);
            return Err(CoreError::StartFailed(format!(
                "Aether did not open its SOCKS listener on {socks_addr} within {timeout:?}"
            )));
        }

        let baseline = aether_engine::stats::snapshot();
        let baseline_rx = baseline.down;
        let baseline_tx = baseline.up;
        Ok(Box::new(AetherHandle {
            rates: Mutex::new(rates::RateMeter::new(baseline)),
            baseline_rx,
            baseline_tx,
            cfg,
            socks_addr,
            sink: cx.telemetry,
            job,
            stopped: AtomicBool::new(false),
        }))
    }
}

fn ffi_reply(raw: *mut std::ffi::c_char) -> std::result::Result<Value, String> {
    if raw.is_null() { return Err("Aether FFI returned a null reply".into()); }
    let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    unsafe { aether_engine::ffi::aether_string_free(raw) };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Aether FFI returned invalid JSON: {e}"))?;
    if value.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(value.get("error").and_then(Value::as_str).unwrap_or("unknown Aether error").into());
    }
    Ok(value)
}

fn ffi_start() -> Result<u64> {
    let args = CString::new("[]").expect("static JSON has no NUL");
    let reply = ffi_reply(unsafe { aether_engine::ffi::aether_core_start(args.as_ptr()) })
        .map_err(CoreError::StartFailed)?;
    reply.get("job").and_then(Value::as_u64)
        .ok_or_else(|| CoreError::StartFailed("Aether FFI did not return a job id".into()))
}

fn ffi_poll(job: u64) -> std::result::Result<Option<std::result::Result<(), String>>, String> {
    let reply = ffi_reply(aether_engine::ffi::aether_job_poll(job))?;
    if reply.get("state").and_then(Value::as_str) != Some("done") { return Ok(None); }
    let result = reply.get("result").ok_or_else(|| "Aether job completed without a result".to_string())?;
    if result.get("ok").and_then(Value::as_bool) == Some(false) {
        Ok(Some(Err(result.get("error").and_then(Value::as_str).unwrap_or("Aether failed").into())))
    } else {
        Ok(Some(Ok(())))
    }
}

fn ffi_cancel(job: u64) { let _ = ffi_reply(aether_engine::ffi::aether_job_cancel(job)); }
fn ffi_free(job: u64) { let _ = ffi_reply(aether_engine::ffi::aether_job_free(job)); }

async fn wait_for_listener(addr: SocketAddr, timeout: Duration, job: u64) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(result) = ffi_poll(job).map_err(CoreError::StartFailed)? {
            return result.map(|_| false).map_err(CoreError::StartFailed);
        }
        if probe_listener(addr).await { return Ok(true); }
        if tokio::time::Instant::now() >= deadline { return Ok(false); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_socks(addr: SocketAddr, timeout: Duration, job: u64) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(result) = ffi_poll(job).map_err(CoreError::StartFailed)? {
            return result.map(|_| false).map_err(CoreError::StartFailed);
        }
        if socks5_greeting(addr).await { return Ok(true); }
        if tokio::time::Instant::now() >= deadline { return Ok(false); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn probe_listener(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok())
        .await.unwrap_or(false)
}

async fn socks5_greeting(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || {
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else { return false; };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let mut reply = [0u8; 2];
        stream.write_all(&[0x05, 0x01, 0x00]).is_ok()
            && stream.read_exact(&mut reply).is_ok()
            && reply == [0x05, 0x00]
    }).await.unwrap_or(false)
}

fn local_dial_addr(bound: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = bound.parse()
        .map_err(|e| CoreError::InvalidConfig(format!("bad tor socks address: {e}")))?;
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    Ok(SocketAddr::new(ip, addr.port()))
}

struct AetherHandle {
    rates: Mutex<rates::RateMeter>,
    baseline_rx: u64,
    baseline_tx: u64,
    cfg: SessionConfig,
    socks_addr: SocketAddr,
    sink: TelemetrySink,
    job: u64,
    stopped: AtomicBool,
}

#[async_trait]
impl BackendHandle for AetherHandle {
    fn endpoints(&self) -> Endpoints {
        let http_port = if matches!(self.cfg.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain) {
            self.cfg.tor.http_port
        } else { self.cfg.http_port };
        Endpoints {
            socks: Some(self.socks_addr),
            http: (http_port != 0).then(|| format!("127.0.0.1:{http_port}").parse().ok()).flatten(),
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        }
    }

    async fn wait(&self) -> Result<()> {
        let mut was_up = true;
        loop {
            if let Some(result) = ffi_poll(self.job).map_err(CoreError::Internal)? {
                return result.map_err(CoreError::Internal);
            }
            let up = probe_listener(self.socks_addr).await;
            if up != was_up {
                was_up = up;
                self.sink.set_state(
                    if up { FcaeState::Connected } else { FcaeState::Reconnecting },
                    if up { "Tunnel reconnected".into() } else { "Tunnel dropped; reconnecting…".into() },
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn stop(&self, timeout: Duration) -> Result<()> {
        if self.stopped.swap(true, Ordering::AcqRel) { return Ok(()); }
        ffi_cancel(self.job);
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if ffi_poll(self.job).ok().flatten().is_some() { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        ffi_free(self.job);
        Ok(())
    }

    fn counters(&self) -> Counters {
        let snapshot = aether_engine::stats::snapshot();
        let (rx, tx) = self.rates.lock().sample(&snapshot);
        Counters {
            total_rx: snapshot.down.saturating_sub(self.baseline_rx),
            total_tx: snapshot.up.saturating_sub(self.baseline_tx),
            rx_bytes_sec: rx,
            tx_bytes_sec: tx,
            rtt_ms: 0,
        }
    }
}

fn tor_mode_label(mode: FcaeTorMode) -> &'static str {
    match mode {
        FcaeTorMode::Off => "off",
        FcaeTorMode::Chain => "chain",
        FcaeTorMode::Reverse => "reverse",
        FcaeTorMode::Only => "only",
    }
}
