use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

use crate::accounts::Accounts;
use crate::challenge::{CaptchaSolver, ChallengeService};
use crate::control::ControlPlane;
use crate::dialer::{Dialer, ProtectCallback};
use crate::error::{FirefoxError, Result};
use crate::fxa::Fxa;
use crate::proxy::LocalProxies;
use crate::server_list::{select_candidates, RemoteSettings};
use crate::store::AccountStore;
use crate::transport::Upstream;
use crate::types::{Candidate, EngineConfig, PeerSet};

pub struct FirefoxEngine {
    upstream: Arc<Upstream>,
    proxies: Arc<LocalProxies>,
    dialer: Dialer,
    stopped: AtomicBool,
    carrier_up: AtomicBool,
    notify: Notify,
    fatal: Mutex<Option<FirefoxError>>,
    renewal: Mutex<Option<JoinHandle<()>>>,
}

impl FirefoxEngine {
    pub async fn start(
        config: EngineConfig,
        protect: Option<ProtectCallback>,
        captcha: Option<Arc<dyn CaptchaSolver>>,
    ) -> Result<Arc<Self>> {
        if config.account_id.as_deref().is_some_and(|id| id.is_empty()) {
            return Err(FirefoxError::InvalidConfig("Firefox account ID cannot be empty".into()));
        }
        log::info!("[firefox] loading account and Mozilla locations");
        let store = AccountStore::new(&config.data_dir)?;
        let account = store.resolve(config.account_id.as_deref())?;
        let dialer = Dialer::new(config.upstream_proxy.as_deref(), protect, config.ip_version)?;
        let control = ControlPlane::new(dialer.clone()).with_timeout(config.connect_timeout);
        let challenges = Arc::new(ChallengeService::new(captcha));
        let fxa = Fxa::new(control.clone()).with_challenges(challenges);
        let accounts = Accounts::new(store.clone(), control.clone(), fxa);
        let tokens = accounts.tokens(&account.id)?;
        let countries = RemoteSettings::new(control).load(&store).await?;
        let candidates = select_candidates(&crate::server_list::connect_candidates(&countries), config.location.as_deref(), config.server.as_deref())?;
        if candidates.is_empty() {
            return Err(FirefoxError::NoLocation(String::new()));
        }
        if tokio::time::timeout(config.connect_timeout, resolve_candidates(&dialer, &candidates)).await.is_err() {
            log::debug!("[firefox] candidate pre-resolution reached the connect deadline");
        }

        let mut selected = None;
        let mut last_error = None;
        for candidate in candidates.iter().take(3) {
            log::info!("[firefox] checking Mozilla proxy {}", candidate.address);
            let attempt = async {
                let upstream = Upstream::new(candidate.clone(), config.transport, dialer.clone(), tokens.clone(), config.connect_timeout).await?;
                let probe = upstream.open_tcp("www.mozilla.org:443").await?;
                drop(probe);
                if config.require_udp {
                    let probe = upstream.open_udp("1.1.1.1:53").await?;
                    drop(probe);
                }
                Ok::<_, FirefoxError>(upstream)
            }.await;
            match attempt {
                Ok(upstream) => {
                    selected = Some(upstream);
                    break;
                }
                Err(error) if error.is_transient() => {
                    log::warn!("[firefox] proxy check failed: {error}");
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        let upstream = selected.ok_or_else(|| last_error.unwrap_or_else(|| FirefoxError::NoLocation(" all candidates failed".into())))?;
        let upstream = Arc::new(upstream);
        upstream.set_candidates(candidates);
        let socks_addr = Some(config.socks_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()));
        let proxies = LocalProxies::start(upstream.clone(), socks_addr, config.http_addr).await?;
        log::info!("[firefox] proxy check passed; local SOCKS {:?}, HTTP {:?}", proxies.socks_addr, proxies.http_addr);
        if let Err(error) = accounts.ensure_device(&account.id).await {
            log::warn!("[firefox] device registration was not refreshed: {error}");
        }
        let engine = Arc::new(Self {
            upstream,
            proxies,
            dialer,
            stopped: AtomicBool::new(false),
            carrier_up: AtomicBool::new(true),
            notify: Notify::new(),
            fatal: Mutex::new(None),
            renewal: Mutex::new(None),
        });
        let task = spawn_renewal(Arc::downgrade(&engine));
        *engine.renewal.lock().await = Some(task);
        Ok(engine)
    }

    pub fn socks_addr(&self) -> Option<std::net::SocketAddr> {
        self.proxies.socks_addr
    }

    pub fn http_addr(&self) -> Option<std::net::SocketAddr> {
        self.proxies.http_addr
    }

    pub fn peers(&self) -> PeerSet {
        PeerSet { selected: self.dialer.peer_ips(), control_plane: Vec::new() }
    }

    pub fn candidate(&self) -> Candidate {
        self.upstream.candidate()
    }

    pub fn traffic(&self) -> (u64, u64) {
        self.upstream.traffic().totals()
    }

    pub fn carrier_up(&self) -> bool {
        self.carrier_up.load(Ordering::Acquire) && !self.stopped.load(Ordering::Acquire)
    }

    pub async fn expires_at(&self) -> SystemTime {
        self.upstream.expires_at().await
    }

    pub async fn wait(&self) -> Result<()> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(error) = self.fatal.lock().await.take() {
                self.carrier_up.store(false, Ordering::Release);
                return Err(error);
            }
            notified.await;
        }
    }

    pub async fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.notify.notify_waiters();
        if let Some(task) = self.renewal.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.proxies.stop().await;
        self.upstream.close().await;
        self.carrier_up.store(false, Ordering::Release);
    }
}

async fn resolve_candidates(dialer: &Dialer, candidates: &[Candidate]) {
    let mut lookups = Vec::with_capacity(candidates.len().min(256));
    for candidate in candidates.iter().take(256) {
        let dialer = dialer.clone();
        let host = candidate.host.clone();
        let port = candidate.port;
        lookups.push(async move {
            if let Err(error) = dialer.resolve(&host, port).await {
                log::debug!("[firefox] pre-resolving {host} failed: {error}");
            }
        });
    }
    futures::stream::iter(lookups).buffer_unordered(16).collect::<Vec<()>>().await;
}

fn spawn_renewal(engine: Weak<FirefoxEngine>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(engine) = engine.upgrade() else { break };
            if engine.stopped.load(Ordering::Acquire) {
                break;
            }
            let renew_at = engine.upstream.expires_at().await.checked_sub(Duration::from_secs(120));
            if renew_at.is_some_and(|at| SystemTime::now() < at) {
                continue;
            }
            match engine.upstream.renew(false).await {
                Ok(_) => engine.carrier_up.store(true, Ordering::Release),
                Err(error) if error.is_transient() => {
                    engine.carrier_up.store(false, Ordering::Release);
                    log::warn!("[firefox] proxy-pass renewal failed: {error}");
                    engine.upstream.note_error(&error).await;
                }
                Err(error) => {
                    engine.carrier_up.store(false, Ordering::Release);
                    *engine.fatal.lock().await = Some(error);
                    engine.notify.notify_waiters();
                    break;
                }
            }
        }
    })
}
