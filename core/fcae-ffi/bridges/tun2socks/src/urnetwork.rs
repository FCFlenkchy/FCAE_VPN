use async_trait::async_trait;
use fcae_abi::{FcaeBackend, FcaeMode, FcaeState};
use fcae_runtime::backend::{
    Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints,
};
use fcae_runtime::{CoreError, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::Duration;
use zeroize::Zeroizing;

unsafe extern "C" {
    fn ur_call(request: *const libc::c_char) -> *mut libc::c_char;
    fn ur_set_log_callback(callback: Option<unsafe extern "C" fn(u32, *const libc::c_char)>);
    fn ur_set_log_level(level: u32);
    fn ur_free(value: *mut libc::c_char);
    fn ur_set_protect(callback: usize);
}
// Record host configuration without calling into Go during UI startup. The
// library may still be mapped (and Go itself may already have initialized):
// this only defers URnetwork bridge calls, not library loading or reclamation.
type LogCallback = Option<unsafe extern "C" fn(u32, *const libc::c_char)>;
type ProtectCallback = Option<unsafe extern "C" fn(libc::c_int) -> libc::c_int>;
struct BridgeConfig {
    active: bool,
    log_callback: LogCallback,
    log_level: u32,
    protect: ProtectCallback,
}
static BRIDGE_CONFIG: parking_lot::Mutex<BridgeConfig> = parking_lot::Mutex::new(BridgeConfig {
    active: false, log_callback: None, log_level: 3, protect: None,
});

pub fn set_log_callback(callback: LogCallback) {
    let mut config = BRIDGE_CONFIG.lock();
    config.log_callback = callback;
    if config.active { unsafe { ur_set_log_callback(callback); } }
}

pub fn set_log_level(level: u32) {
    let mut config = BRIDGE_CONFIG.lock();
    config.log_level = level.min(4);
    if config.active { unsafe { ur_set_log_level(config.log_level); } }
}

pub fn set_protect(callback: ProtectCallback) {
    let mut config = BRIDGE_CONFIG.lock();
    config.protect = callback;
    if config.active {
        unsafe { ur_set_protect(callback.map(|f| f as usize).unwrap_or(0)); }
    }
}

fn activate_bridge() {
    let mut config = BRIDGE_CONFIG.lock();
    if !config.active {
        // Serialize activation with callback updates so a concurrently
        // detached VpnService can never leave an old protect callback installed.
        unsafe {
            ur_set_log_callback(config.log_callback);
            ur_set_log_level(config.log_level);
            ur_set_protect(config.protect.map(|f| f as usize).unwrap_or(0));
        }
        config.active = true;
    }
}
fn call(request: &str) -> std::result::Result<Value, String> {
    let request = CString::new(request).map_err(|_| "invalid URnetwork request".to_owned())?;
    activate_bridge();
    let raw = unsafe { ur_call(request.as_ptr()) };
    if raw.is_null() {
        return Err("URnetwork returned no reply".into());
    }
    let result = unsafe { serde_json::from_slice::<Value>(CStr::from_ptr(raw).to_bytes()) };
    unsafe {
        ur_free(raw);
    }
    let result = result.map_err(|_| "invalid URnetwork reply".to_owned())?;
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        return Err(error.to_owned());
    }
    Ok(result)
}
pub fn register() {
    fcae_runtime::registry::register(FcaeBackend::URnetwork, || Arc::new(UrBackend));
}
// The supervisor reclaims every registered backend on every disconnect. An
// unused URnetwork backend has no sessions to stop, so do not cross into Go
// merely to ask it to stop an empty session map. Never reset this bit: after
// the first attempted start, later reclaims must continue to catch cancelled
// or late starts even when an earlier cleanup appeared to finish.
static SESSION_START_ATTEMPTED: AtomicBool = AtomicBool::new(false);
struct UrBackend;
#[async_trait]
impl Backend for UrBackend {
    fn id(&self) -> BackendId {
        BackendId::URnetwork
    }
    fn reclaim_blocking(&self) {
        if SESSION_START_ATTEMPTED.load(Ordering::Acquire) {
            let _ = call(r#"{"op":"stop-all"}"#);
        }
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
        let cfg = &cx.config;
        if cfg.routing.rules_file.is_some()
            || !cfg.routing.direct.is_empty()
            || !cfg.routing.block.is_empty()
        {
            return Err(CoreError::InvalidConfig("URnetwork does not interpret legacy core routing files; use the shared destination-routing selector".into()));
        }
        let host = if cfg.lan_sharing {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let socks = if cfg.internal_socks {
            "127.0.0.1:0".to_owned()
        } else if cfg.socks_port != 0 {
            format!("{host}:{}", cfg.socks_port)
        } else {
            String::new()
        };
        let http = if cfg.internal_http {
            "127.0.0.1:0".to_owned()
        } else if cfg.http_port != 0 {
            format!("{host}:{}", cfg.http_port)
        } else {
            String::new()
        };
        if (cfg.mode == FcaeMode::Tun || cfg.require_udp_proxy) && socks.is_empty() {
            return Err(CoreError::InvalidConfig(
                "URnetwork TUN/chaining requires a SOCKS5 listener".into(),
            ));
        }
        log::info!(target: "fcae.urnetwork", "[urnetwork] establishing device connection");
        cx.report(FcaeState::Connecting, "Connecting to URnetwork");
        let request = json!({"op":"start", "data_dir":cfg.data_dir.as_deref().unwrap_or("fcae-data"), "socks":socks,"http":http,"proxy":cfg.upstream_proxy.as_ref().map(|p|p.url()).unwrap_or_default(),"tun":true}).to_string();
        // The blocking result owns cleanup even if startup's async future is
        // cancelled before the native request returns.
        SESSION_START_ATTEMPTED.store(true, Ordering::Release);
        let handle = tokio::task::spawn_blocking(move || {
            let v = call(&request).map_err(CoreError::StartFailed)?;
            let id = v.get("id").and_then(Value::as_u64).ok_or_else(|| {
                CoreError::StartFailed("URnetwork did not allocate an instance".into())
            })?;
            let parse = |key| {
                v.get(key)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| s.parse().ok())
            };
            Ok::<_, CoreError>(UrHandle {
                id,
                endpoints: Endpoints {
                    socks: parse("socks"),
                    http: parse("http"),
                    peer_ip: None,
                    udp: true,
                    psiphon_dns: false,
                },
                stopped: AtomicBool::new(false),
            })
        })
        .await
        .map_err(|_| CoreError::StartFailed("URnetwork startup worker failed".into()))??;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if cx.cancel.is_cancelled() {
                return Err(CoreError::StartFailed("URnetwork startup cancelled".into()));
            }
            if handle.carrier_up() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::StartFailed(
                    "URnetwork could not establish an exit within 60 seconds".into(),
                ));
            }
            tokio::select! { _=cx.cancel.cancelled()=>return Err(CoreError::StartFailed("URnetwork startup cancelled".into())), _=tokio::time::sleep(Duration::from_millis(250))=>{} }
        }
        log::info!(target: "fcae.urnetwork", "[urnetwork] device connection ready");
        Ok(Box::new(handle))
    }
}
struct UrHandle {
    id: u64,
    endpoints: Endpoints,
    stopped: AtomicBool,
}
impl UrHandle {
    fn status(&self) -> Value {
        if self.stopped.load(Ordering::Acquire) {
            return Value::Null;
        }
        call(&json!({"op":"status","id":self.id}).to_string()).unwrap_or(Value::Null)
    }
    fn close(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let id = self.id;
            let _ = std::thread::Builder::new()
                .name("urnetwork-stop".into())
                .spawn(move || {
                    let _ = call(&json!({"op":"stop","id":id}).to_string());
                });
        }
    }
}
impl Drop for UrHandle {
    fn drop(&mut self) {
        self.close();
    }
}
#[async_trait]
impl BackendHandle for UrHandle {
    fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }
    async fn wait(&self) -> Result<()> {
        while !self.stopped.load(Ordering::Acquire) {
            if self.status().get("alive").and_then(Value::as_bool) == Some(false) {
                return Err(CoreError::StartFailed("URnetwork device stopped".into()));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }
    async fn stop(&self, timeout: Duration) -> Result<()> {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let id = self.id;
            let worker = tokio::task::spawn_blocking(move || {
                call(&json!({"op":"stop","id":id}).to_string())
            });
            tokio::time::timeout(timeout, worker)
                .await
                .map_err(|_| {
                    CoreError::StartFailed("URnetwork shutdown is still completing".into())
                })?
                .map_err(|_| CoreError::StartFailed("URnetwork shutdown worker failed".into()))?
                .map_err(CoreError::StartFailed)?;
        }
        Ok(())
    }
    fn carrier_up(&self) -> bool {
        self.status()
            .get("up")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
    fn counters(&self) -> Counters {
        let v = self.status();
        Counters {
            total_rx: v.get("rx").and_then(Value::as_u64).unwrap_or(0),
            total_tx: v.get("tx").and_then(Value::as_u64).unwrap_or(0),
            rx_bytes_sec: v.get("rx_rate").and_then(Value::as_u64).unwrap_or(0),
            tx_bytes_sec: v.get("tx_rate").and_then(Value::as_u64).unwrap_or(0),
            rtt_ms: v.get("rtt_ms").and_then(Value::as_u64).unwrap_or(0) as u32,
        }
    }
}

static NEXT: AtomicU64 = AtomicU64::new(1);
static BUSY: AtomicBool = AtomicBool::new(false);
static JOBS: OnceLock<parking_lot::Mutex<HashMap<u64, String>>> = OnceLock::new();
fn jobs() -> &'static parking_lot::Mutex<HashMap<u64, String>> {
    JOBS.get_or_init(Default::default)
}
pub fn submit(request: &str) -> u64 {
    if request.len() > 65536 {
        return 0;
    }
    let Ok(v) = serde_json::from_str::<Value>(request) else {
        return 0;
    };
    if !matches!(
        v.get("op").and_then(Value::as_str),
        Some("load" | "save" | "login" | "verify" | "verify-send" | "code-login" | "regions" | "usage" | "logout" | "select" | "remove")
    ) {
        return 0;
    }
    if BUSY.swap(true, Ordering::AcqRel) {
        return 0;
    }
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    {
        let mut j = jobs().lock();
        if j.len() >= 32 {
            BUSY.store(false, Ordering::Release);
            return 0;
        }
        j.insert(id, json!({"status":"pending"}).to_string());
    }
    let operation = v.get("op").and_then(Value::as_str).unwrap_or_default().to_owned();
    log::debug!(target: "fcae.urnetwork", "[urnetwork] account operation queued: {operation}");
    let request = Zeroizing::new(request.to_owned());
    if std::thread::Builder::new()
        .name("urnetwork-account".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(|| call(&request));
            match &result {
                Ok(Ok(_)) => log::debug!(target: "fcae.urnetwork", "[urnetwork] account operation completed: {operation}"),
                _ => log::warn!(target: "fcae.urnetwork", "[urnetwork] account operation failed: {operation}"),
            }
            let value = match result {
                Ok(Ok(v)) => json!({"status":"done","result":v}),
                Ok(Err(e)) => json!({"status":"error","error":e}),
                Err(_) => json!({"status":"error","error":"URnetwork account worker failed"}),
            };
            let mut j = jobs().lock();
            if let Some(slot) = j.get_mut(&id) {
                *slot = value.to_string();
            }
            BUSY.store(false, Ordering::Release);
        })
        .is_err()
    {
        jobs().lock().remove(&id);
        BUSY.store(false, Ordering::Release);
        return 0;
    }
    id
}
pub fn poll(id: u64) -> String {
    jobs().lock().get(&id).cloned().unwrap_or_default()
}
pub fn release(id: u64) {
    jobs().lock().remove(&id);
}
