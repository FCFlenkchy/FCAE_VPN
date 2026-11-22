//! GUI policy requests and per-TUN ownership; no CLI or detached installer.
use crate::{
    app_routing::{
        Action, CompiledPolicy, Mode, Platform, Policy, Provider, Selector, SCHEMA_VERSION,
    },
    windows_app_routing_driver::Addresses,
    windows_app_routing_provider::WindowsExclusionProvider,
    windows_split_driver_service::OwnedDriverService,
};
use serde_json::{json, Value};
use std::{
    io,
    sync::{LazyLock, Mutex},
};
#[derive(Default)]
struct State {
    requested: Option<CompiledPolicy>,
    requested_revision: u64,
    active_revision: Option<u64>,
    message: String,
    worker: Option<std::thread::JoinHandle<()>>,
    maintenance: bool,
    installing: bool,
}
static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));
fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}
pub fn request(value: &Value) -> Value {
    if value["action"].as_str() == Some("shutdown") {
        let worker = { state().worker.take() };
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
    let mut state = state();
    if state
        .worker
        .as_ref()
        .is_some_and(|worker| worker.is_finished())
    {
        if let Some(worker) = state.worker.take() {
            let _ = worker.join();
        }
    }
    match value["action"].as_str().unwrap_or("") {
        "status" => {}
        "shutdown" | "stop" => {
            state.requested = None;
            state.message="Bypass disabled for the next VPN connection. Disconnect the active VPN to withdraw its installed policy.".into();
        }
        "recover" => {
            if state.maintenance || state.installing || state.active_revision.is_some() {
                return json!({"ok":false,"active":state.active_revision.is_some(),"message":"Disconnect the VPN and wait for current routing work before recovery."});
            }
            state.maintenance = true;
            state.message = "Recovering confirmed stale FCAE-owned Windows routing state...".into();
            match std::thread::Builder::new().name("fcae-routing-recovery".into()).spawn(|| {
                let result=std::panic::catch_unwind(crate::windows_split_driver_service::recover_stale);
                let mut state=STATE.lock().unwrap_or_else(|e|e.into_inner());
                state.maintenance=false;
                state.message=match result {
                    Ok(Ok(count))=>format!("Recovered {count} stale FCAE routing installation(s). Live owners and foreign resources were not modified."),
                    Ok(Err(error))=>format!("Recovery stopped without adopting unverified state: {error}. Previously confirmed stale resources may already have been cleaned; retry after resolving this condition."),
                    Err(_)=>"Recovery worker failed; ownership records retained for another attempt.".into(),
                };
            }) {
                Ok(worker)=>state.worker=Some(worker),
                Err(error)=>{state.maintenance=false;state.message=format!("Could not start routing recovery: {error}");},
            }
        }
        "configure" => {
            let parsed = (|| -> Result<CompiledPolicy, String> {
                if !crate::windows_split_driver_package::AVAILABLE {
                    return Err("This build has no experimental signed split driver bundle.".into());
                }
                if value["acknowledge_kernel_crash_risk"].as_bool() != Some(true) {
                    return Err("Explicit acknowledgement of upstream kernel crash report #11487 is required.".into());
                }
                let mode=match value["mode"].as_u64(){Some(0)=>Mode::AllApps,Some(2)=>Mode::Exclude,_=>return Err("The Windows driver supports bypass-selected mode only; include mode is unavailable.".into())};
                let apps = value["apps"]
                    .as_array()
                    .ok_or("An application path list is required")?;
                if apps.len() > 8192 {
                    return Err("Too many selected applications".into());
                }
                let mut selectors = Vec::new();
                for app in apps {
                    let path = app.as_str().ok_or("Application path must be a string")?;
                    selectors.push(Selector::WindowsExecutable(path.into()));
                }
                let revision = state
                    .requested_revision
                    .checked_add(1)
                    .ok_or("Policy revision exhausted")?;
                Policy {
                    schema_version: SCHEMA_VERSION,
                    revision,
                    mode,
                    selectors,
                    unknown_action: Action::Tunnel,
                    fail_closed: false,
                }
                .compile(Platform::Windows)
                .map_err(|e| format!("Invalid application policy: {e:?}"))
            })();
            match parsed {
                Ok(policy) => {
                    state.requested_revision = policy.revision();
                    state.message="Requested policy syntax validated, not installed. Executable identities are resolved during VPN connection. Reconnect the VPN to apply. DNS stays in the protected tunnel. New connections only; exclusions include descendants. No independent kill switch.".into();
                    state.requested = Some(policy);
                }
                Err(error) => {
                    state.message=format!("Draft rejected; the previous requested/active policies were not replaced: {error}");
                    return json!({"ok":false,"active":state.active_revision.is_some(),"message":state.message});
                }
            }
        }
        _ => {
            return json!({"ok":false,"active":state.active_revision.is_some(),"message":"Unknown Windows routing operation"})
        }
    }
    json!({"ok":true,"active":state.active_revision.is_some(),"message":state.message,
        "requested_revision":state.requested_revision,"active_revision":state.active_revision,
        "experimental_bundle":crate::windows_split_driver_package::AVAILABLE})
}
pub fn needed() -> bool {
    state()
        .requested
        .as_ref()
        .is_some_and(|p| p.mode() == Mode::Exclude && !p.local_selectors().is_empty())
}
pub struct Session {
    provider: Option<WindowsExclusionProvider>,
    service: Option<OwnedDriverService>,
    revision: u64,
}
impl Session {
    pub fn start(addresses: Addresses) -> io::Result<Option<Self>> {
        let policy = {
            let mut state = state();
            if state.maintenance || state.installing {
                return Err(io::Error::other(
                    "routing recovery or another installation is in progress",
                ));
            }
            let policy = state.requested.clone();
            state.installing = true;
            policy
        };
        struct Installing;
        impl Drop for Installing {
            fn drop(&mut self) {
                state().installing = false;
            }
        }
        let _installing = Installing;
        let Some(policy) =
            policy.filter(|p| p.mode() == Mode::Exclude && !p.local_selectors().is_empty())
        else {
            return Ok(None);
        };
        let mut result = Self {
            provider: None,
            service: None,
            revision: policy.revision(),
        };
        let installation = (|| {
            result.service = Some(OwnedDriverService::install_experimental(true)?);
            let driver = result
                .service
                .as_ref()
                .ok_or_else(|| io::Error::other("driver service missing"))?
                .open_driver()?;
            result.provider = Some(WindowsExclusionProvider::from_verified_driver(
                driver,
                addresses,
                result
                    .service
                    .as_ref()
                    .ok_or_else(|| io::Error::other("driver service missing"))?
                    .directory(),
            )?);
            result
                .provider
                .as_mut()
                .ok_or_else(|| io::Error::other("driver provider missing"))?
                .install(&policy)
                .map_err(|e| io::Error::other(format!("Driver policy installation: {e:?}")))?;
            Ok(())
        })();
        if let Err(error) = installation {
            // Construction can fail after recording WFP intent but before the
            // provider reaches this struct. Preserve that recovery authority.
            if let Some(service) = result.service.as_mut() {
                service.retain_for_recovery();
            }
            state().message = format!("Windows app routing was not installed: {error}");
            return Err(error);
        }
        {
            let mut state = state();
            state.active_revision = Some(policy.revision());
            state.message=format!("Experimental OS bypass policy revision {} installed. DNS stays in the tunnel; existing connections may need restart. No independent kill switch.",policy.revision());
        }
        Ok(Some(result))
    }
    pub fn check_health(&mut self, current: Addresses) -> io::Result<()> {
        let result = self
            .provider
            .as_mut()
            .ok_or_else(|| io::Error::other("routing provider closed"))?
            .check_health(current);
        if let Err(error) = &result {
            let mut state = state();
            state.active_revision = None;
            state.message = format!("App routing degraded; VPN reconnect required: {error}");
        }
        result
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Withdrawal and device close must precede service unload, which must
        // precede deleting its protected image/catalog. Field order is not used
        // as a substitute for explicit resource lifetime ordering.
        let provider_error = self
            .provider
            .as_mut()
            .and_then(|provider| provider.close().err());
        self.provider.take();
        if provider_error.is_some() {
            if let Some(service) = self.service.as_mut() {
                service.retain_for_recovery();
            }
        }
        let service_error = self
            .service
            .as_mut()
            .and_then(|service| service.stop().err());
        self.service.take();
        let mut state = state();
        if state.active_revision == Some(self.revision) {
            state.active_revision = None;
        }
        if let Some(error) = provider_error.or(service_error) {
            state.message=format!("Windows routing cleanup could not be confirmed: {error}. Do not assume bypass was withdrawn; check retained service state before reconnecting.");
        } else if !state.message.starts_with("App routing degraded") {
            state.message =
                "Windows application bypass withdrawn; requested policy retained for reconnect."
                    .into();
        }
    }
}
