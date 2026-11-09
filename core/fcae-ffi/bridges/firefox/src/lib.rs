use std::ffi::{CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod accounts;

use async_trait::async_trait;
use fcae_abi::{FcaeBackend, FcaeMode};
use fcae_firefox::{EngineConfig, FirefoxEngine, TransportPreference};
use fcae_runtime::backend::{Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints};
use fcae_runtime::{CoreError, Result};

static PROTECT: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static CAPTCHA: parking_lot::Mutex<Option<(usize, usize)>> = parking_lot::Mutex::new(None);

pub type ProtectFn = unsafe extern "C" fn(std::ffi::c_int) -> std::ffi::c_int;
pub type CaptchaFn = unsafe extern "C" fn(
    *const std::ffi::c_char,
    u32,
    *mut std::ffi::c_char,
    u32,
    *mut std::ffi::c_void,
) -> std::ffi::c_int;

pub fn register() {
    fcae_runtime::registry::register(FcaeBackend::Firefox, || Arc::new(FirefoxBackend));
}

pub fn set_protect_callback(callback: Option<ProtectFn>) {
    let pointer = callback.map(|callback| callback as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut());
    PROTECT.store(pointer, Ordering::SeqCst);
}

fn protect_callback() -> Option<fcae_firefox::dialer::ProtectCallback> {
    #[cfg(target_os = "android")]
    {
        Some(Arc::new(move |fd| {
            let pointer = PROTECT.load(Ordering::SeqCst);
            if pointer.is_null() {
                return true;
            }
            let callback: ProtectFn = unsafe { std::mem::transmute(pointer) };
            unsafe { callback(fd) == 1 }
        }))
    }
    #[cfg(not(target_os = "android"))]
    {
        let pointer = PROTECT.load(Ordering::SeqCst);
        if pointer.is_null() {
            return None;
        }
        let callback: ProtectFn = unsafe { std::mem::transmute(pointer) };
        Some(Arc::new(move |fd| unsafe { callback(fd) == 1 }))
    }
}

pub fn set_captcha_callback(callback: Option<CaptchaFn>, user_data: *mut std::ffi::c_void) {
    *CAPTCHA.lock() = callback.map(|callback| (callback as usize, user_data as usize));
}

pub fn captcha_solver() -> Arc<dyn fcae_firefox::CaptchaSolver> {
    Arc::new(HostCaptcha)
}

struct HostCaptcha;

#[async_trait]
impl fcae_firefox::CaptchaSolver for HostCaptcha {
    async fn solve(&self, image_data_url: &str) -> fcae_firefox::Result<String> {
        let Some((callback, user_data)) = *CAPTCHA.lock() else {
            return accounts::solve_captcha(image_data_url).await;
        };
        let callback: CaptchaFn = unsafe { std::mem::transmute(callback) };
        let image = CString::new(image_data_url).map_err(|_| fcae_firefox::FirefoxError::ChallengeRequired)?;
        let mut output = vec![0u8; 513];
        let written = unsafe {
            callback(image.as_ptr(), image_data_url.len() as u32, output.as_mut_ptr().cast(), output.len() as u32, user_data as *mut std::ffi::c_void)
        };
        if written <= 0 || written as usize >= output.len() {
            return Err(fcae_firefox::FirefoxError::ChallengeRequired);
        }
        output.truncate(written as usize + 1);
        let answer = CStr::from_bytes_with_nul(&output)
            .map_err(|_| fcae_firefox::FirefoxError::ChallengeRequired)?
            .to_str()
            .map_err(|_| fcae_firefox::FirefoxError::ChallengeRequired)?
            .trim()
            .to_string();
        if answer.is_empty() || answer.len() > 256 {
            return Err(fcae_firefox::FirefoxError::ChallengeRequired);
        }
        Ok(answer)
    }
}

pub struct FirefoxBackend;

#[async_trait]
impl Backend for FirefoxBackend {
    fn id(&self) -> BackendId {
        BackendId::Firefox
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            gateway_scanning: false,
            routing_rules: false,
            requires_privileges: false,
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let config = cx.config.clone();
        if config.routing.rules_file.is_some() || !config.routing.direct.is_empty() || !config.routing.block.is_empty() {
            return Err(CoreError::InvalidConfig(
                "Firefox split-routing rules are not supported by this backend; use full-tunnel routing".into(),
            ));
        }
        let transport = match config.firefox.transport.as_str() {
            "auto" => TransportPreference::Auto,
            "h1" => TransportPreference::H1,
            "h2" => TransportPreference::H2,
            "h3" => {
                return Err(CoreError::InvalidConfig(
                    "Firefox HTTP/3 is not available in this build; select auto, h2 or h1".into(),
                ))
            }
            other => return Err(CoreError::InvalidConfig(format!("unsupported Firefox transport {other:?}"))),
        };
        let data_dir = PathBuf::from(config.data_dir.clone().unwrap_or_else(|| "fcae-data".into()));
        let bind_host = if config.lan_sharing { "0.0.0.0" } else { "127.0.0.1" };
        let socks_addr = if config.internal_socks {
            Some(parse_bind("127.0.0.1", 0)?)
        } else {
            (config.socks_port != 0).then(|| parse_bind(bind_host, config.socks_port)).transpose()?
        };
        let http_addr = if config.internal_http {
            Some(parse_bind("127.0.0.1", 0)?)
        } else {
            (config.http_port != 0).then(|| parse_bind(bind_host, config.http_port)).transpose()?
        };
        let dns_servers = if config.mode == FcaeMode::Tun {
            let servers = fcae_runtime::tun_dns::servers(&config)?;
            let servers = if servers.is_empty() {
                vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
            } else {
                servers
            };
            servers.into_iter().take(3).collect()
        } else {
            Vec::new()
        };
        if config.require_udp_proxy && socks_addr.is_none() {
            return Err(CoreError::InvalidConfig("the next hop needs UDP; enable Firefox SOCKS5".into()));
        }
        let engine_config = EngineConfig {
            data_dir,
            account_id: config.firefox.account_id.clone(),
            location: config.firefox.location.clone(),
            server: config.firefox.server.clone(),
            transport,
            require_udp: config.mode == FcaeMode::Tun || config.require_udp_proxy,
            dns_servers,
            socks_addr,
            http_addr,
            upstream_proxy: config.upstream_proxy.as_ref().map(|proxy| proxy.url()),
            ip_version: config.ip_version,
            connect_timeout: Duration::from_secs(30),
            routing_rules: None,
        };
        cx.report(fcae_abi::FcaeState::Connecting, "Connecting to Firefox IP Protection");
        let engine = FirefoxEngine::start(engine_config, protect_callback(), Some(captcha_solver()))
            .await
            .map_err(|error| {
                log::error!("[firefox] connection startup failed: {error}");
                if error.is_transient() { CoreError::StartFailed(error.to_string()) }
                else { CoreError::InvalidConfig(error.to_string()) }
            })?;
        let peers = engine.peers();
        let peer_ip = (!peers.selected.is_empty()).then(|| {
            peers.selected.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(",")
        });
        let endpoints = Endpoints {
            socks: engine.socks_addr(),
            http: engine.http_addr(),
            peer_ip,
            udp: transport != TransportPreference::H1,
            psiphon_dns: false,
        };
        if config.mode == FcaeMode::Tun && (endpoints.socks.is_none() || transport == TransportPreference::H1) {
            engine.stop().await;
            return Err(CoreError::StartFailed(if transport == TransportPreference::H1 {
                "Firefox TUN requires UDP-safe H2; select auto or h2".into()
            } else {
                "Firefox did not expose the required SOCKS endpoint".into()
            }));
        }
        Ok(Box::new(RunningFirefox {
            engine,
            endpoints,
            rates: parking_lot::Mutex::new(RateSample { at: Instant::now(), rx: 0, tx: 0, rates: (0, 0) }),
        }))
    }
}

fn parse_bind(host: &str, port: u16) -> Result<SocketAddr> {
    format!("{host}:{port}").parse().map_err(|error| CoreError::InvalidConfig(format!("invalid Firefox listener {host}:{port}: {error}")))
}

struct RateSample {
    at: Instant,
    rx: u64,
    tx: u64,
    rates: (u64, u64),
}

struct RunningFirefox {
    engine: Arc<FirefoxEngine>,
    endpoints: Endpoints,
    rates: parking_lot::Mutex<RateSample>,
}

#[async_trait]
impl BackendHandle for RunningFirefox {
    fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    fn carrier_up(&self) -> bool {
        self.engine.carrier_up()
    }

    fn counters(&self) -> Counters {
        let (rx, tx) = self.engine.traffic();
        let mut sample = self.rates.lock();
        let elapsed = sample.at.elapsed();
        if elapsed >= Duration::from_millis(100) {
            let seconds = elapsed.as_secs_f64();
            sample.rates = ((rx.saturating_sub(sample.rx) as f64 / seconds) as u64,
                            (tx.saturating_sub(sample.tx) as f64 / seconds) as u64);
            sample.rx = rx;
            sample.tx = tx;
            sample.at = Instant::now();
        }
        Counters { total_rx: rx, total_tx: tx, rx_bytes_sec: sample.rates.0, tx_bytes_sec: sample.rates.1, rtt_ms: 0 }
    }

    async fn wait(&self) -> Result<()> {
        self.engine.wait().await.map_err(|error| CoreError::Internal(error.to_string()))
    }

    async fn stop(&self, timeout: Duration) -> Result<()> {
        match tokio::time::timeout(timeout, self.engine.stop()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(CoreError::Timeout(timeout)),
        }
    }
}
