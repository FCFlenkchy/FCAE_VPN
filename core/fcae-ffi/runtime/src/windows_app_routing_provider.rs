//! Exclusive Windows exclusion provider for a pre-installed, verified driver.
//! Not activated automatically: the bundled revision remains experimental.
//! DNS remains on FCAE's protected tunnel; bypass is not a DNS bypass promise.
use crate::app_routing::{
    Action, CompiledPolicy, Mechanism, Mode, PolicyError, Provider, Selector,
};
use crate::windows_app_routing_driver::{Addresses, Driver};
use std::{io, path::PathBuf, ptr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::{UuidCreate, RPC_C_AUTHN_WINNT, RPC_S_UUID_LOCAL_ONLY},
    },
};

fn checked(code: u32, operation: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation}: Windows status 0x{code:08x}"
        )))
    }
}
fn policy_error(error: io::Error) -> PolicyError {
    PolicyError::ProviderOperation(error.to_string())
}
struct Sublayers {
    engine: usize,
    baseline: GUID,
    dns: GUID,
    installed: bool,
}
impl Sublayers {
    fn create(directory: &std::path::Path) -> io::Result<Self> {
        let mut session = FWPM_SESSION0::default();
        // The kernel opens a distinct WFP session and installs callouts under
        // these sublayers. A dynamic-session sublayer cannot be referenced by
        // objects in that other session. Use nonpersistent, exact-owned keys.
        let mut name: Vec<u16> = "FCAE split routing owner\0".encode_utf16().collect();
        session.displayData.name = name.as_mut_ptr();
        let mut engine = ptr::null_mut();
        checked(
            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut engine,
                )
            },
            "open split WFP session",
        )?;
        let mut result = Self {
            engine: engine as usize,
            baseline: GUID::default(),
            dns: GUID::default(),
            installed: false,
        };
        for key in [&mut result.baseline, &mut result.dns] {
            let code = unsafe { UuidCreate(key) };
            if code != 0 && code != RPC_S_UUID_LOCAL_ONLY {
                return Err(io::Error::other(format!("create WFP owner key: {code}")));
            }
        }
        // Flush exact ownership before any non-dynamic WFP object is added.
        crate::windows_app_routing_journal::write_keys(directory, result.baseline, result.dns)?;
        checked(
            unsafe { FwpmTransactionBegin0(engine, 0) },
            "begin split WFP transaction",
        )?;
        let transaction = (|| {
            for (key, weight) in [(result.baseline, 0x7100), (result.dns, 0x7101)] {
                let mut layer = FWPM_SUBLAYER0 {
                    subLayerKey: key,
                    ..Default::default()
                };
                layer.displayData.name = name.as_mut_ptr();
                layer.weight = weight;
                checked(
                    unsafe { FwpmSubLayerAdd0(engine, &layer, ptr::null_mut()) },
                    "add split WFP sublayer",
                )?;
            }
            checked(
                unsafe { FwpmTransactionCommit0(engine) },
                "commit split WFP transaction",
            )
        })();
        if transaction.is_err() {
            unsafe {
                FwpmTransactionAbort0(engine);
            }
        }
        transaction?;
        result.installed = true;
        Ok(result)
    }
    fn remove(&mut self) -> io::Result<()> {
        if !self.installed {
            return Ok(());
        }
        let engine = self.engine as HANDLE;
        checked(
            unsafe { FwpmTransactionBegin0(engine, 0) },
            "begin split WFP cleanup",
        )?;
        let transaction = (|| {
            for key in [&self.dns, &self.baseline] {
                checked(
                    unsafe { FwpmSubLayerDeleteByKey0(engine, key) },
                    "remove owned split WFP sublayer",
                )?;
            }
            checked(
                unsafe { FwpmTransactionCommit0(engine) },
                "commit split WFP cleanup",
            )
        })();
        if transaction.is_err() {
            unsafe {
                FwpmTransactionAbort0(engine);
            }
        } else {
            self.installed = false;
        }
        transaction
    }
}
impl Drop for Sublayers {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            log::error!("[app-routing] WFP owner cleanup failed: {error}");
        }
        if let Err(error) = checked(
            unsafe { FwpmEngineClose0(self.engine as HANDLE) },
            "close split WFP session",
        ) {
            log::error!("[app-routing] {error}");
        }
    }
}

pub struct WindowsExclusionProvider {
    // Driver is reset and closed before sublayers are removed, including when
    // any step of construction or policy installation fails.
    driver: Option<Driver>,
    layers: Sublayers,
    addresses: Addresses,
    revision: Option<u64>,
    engaged: bool,
    failed: bool,
}
impl WindowsExclusionProvider {
    /// Caller must first establish trusted service/package ownership. Device
    /// access alone is not proof that the loaded kernel binary is our bundle.
    pub fn from_verified_driver(
        driver: Driver,
        addresses: Addresses,
        directory: &std::path::Path,
    ) -> io::Result<Self> {
        validate_addresses(addresses)?;
        let layers = Sublayers::create(directory)?;
        let baseline = layers.baseline;
        let dns = layers.dns;
        let mut result = Self {
            driver: Some(driver),
            layers,
            addresses,
            revision: None,
            engaged: false,
            failed: false,
        };
        result.driver_mut()?.initialize(baseline, dns)?;
        result.driver()?.set_addresses(addresses)?;
        // Start consuming before installing exclusions; lifecycle/errors must
        // not accumulate indefinitely in an unattended kernel event queue.
        result.driver_mut()?.poll_event()?;
        Ok(result)
    }
    fn driver(&self) -> io::Result<&Driver> {
        self.driver
            .as_ref()
            .ok_or_else(|| io::Error::other("split driver is closed"))
    }
    fn driver_mut(&mut self) -> io::Result<&mut Driver> {
        self.driver
            .as_mut()
            .ok_or_else(|| io::Error::other("split driver is closed"))
    }
    /// Call from the existing TUN health monitor, not the GUI render thread.
    /// Interface/address changes invalidate the policy until a reconnect.
    pub fn check_health(&mut self, current: Addresses) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                "split provider is degraded; reconnect required",
            ));
        }
        let result = (|| {
            if current != self.addresses {
                return Err(io::Error::other(
                    "split routing uplink changed; reconnect required",
                ));
            }
            // Bound per-tick work. The pending dequeue survives between ticks.
            for _ in 0..256 {
                let Some(event) = self.driver_mut()?.poll_event()? else {
                    break;
                };
                if event.is_error() {
                    return Err(io::Error::other(format!(
                        "split driver enforcement error: {event:?}"
                    )));
                }
                log::debug!("[app-routing] {event:?}");
            }
            let expected = if self.engaged { 4 } else { 3 };
            if self.driver()?.state()? != expected {
                return Err(io::Error::other("split driver lost its acknowledged state"));
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            // Never leave intentional bypass active after losing enforcement
            // health. This is not an independent system-wide kill switch.
            if let Some(driver) = self.driver.as_mut() {
                if let Err(error) = driver.set_exclusions(&[]) {
                    log::error!("[app-routing] failed to withdraw exclusions: {error}");
                }
            }
            self.revision = None;
            self.engaged = false;
        }
        result
    }
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(driver) = self.driver.as_mut() {
            driver.reset()?;
        }
        self.driver.take();
        self.revision = None;
        self.engaged = false;
        self.layers.remove()
    }
}
fn validate_addresses(a: Addresses) -> io::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let t = Ipv4Addr::from(a.tunnel_v4);
    let p = Ipv4Addr::from(a.physical_v4);
    if t.is_unspecified()
        || p.is_unspecified()
        || t == p
        || t.is_loopback()
        || p.is_loopback()
        || t.is_multicast()
        || p.is_multicast()
    {
        return Err(io::Error::other(
            "split routing requires distinct tunnel and physical IPv4 addresses",
        ));
    }
    let t = Ipv6Addr::from(a.tunnel_v6);
    let p = Ipv6Addr::from(a.physical_v6);
    if t.is_unspecified() != p.is_unspecified()
        || (!t.is_unspecified()
            && (t == p
                || t.is_loopback()
                || p.is_loopback()
                || t.is_multicast()
                || p.is_multicast()))
    {
        return Err(io::Error::other(
            "split routing requires a complete IPv6 address pair or neither",
        ));
    }
    Ok(())
}
impl Provider for WindowsExclusionProvider {
    fn mechanism(&self) -> Mechanism {
        Mechanism::OsRouting
    }
    fn install(&mut self, policy: &CompiledPolicy) -> Result<u64, PolicyError> {
        if self.failed || self.driver.is_none() {
            return Err(PolicyError::ProviderUnavailable);
        }
        if !policy.foreign_selectors().is_empty() {
            return Err(PolicyError::ForeignSelector);
        }
        // This driver implements exclusion and inherited exclusions only. An
        // include mode cannot be emulated by enumerating today's process list.
        if policy.mode() == Mode::Include
            || policy.fail_closed()
            || policy.unknown_action() != Action::Tunnel
        {
            return Err(PolicyError::ProviderOperation("Windows exclusion driver cannot enforce include, block-unknown or an independent fail-closed policy".into()));
        }
        if self
            .revision
            .is_some_and(|revision| policy.revision() <= revision)
        {
            return Err(PolicyError::StaleAcknowledgement);
        }
        let mut paths = Vec::new();
        if policy.mode() == Mode::Exclude {
            for selector in policy.local_selectors() {
                match selector {
                    Selector::WindowsExecutable(path) => paths.push(PathBuf::from(path)),
                    _ => return Err(PolicyError::ForeignSelector),
                }
            }
        }
        // Acknowledgement is only returned after the driver completed its
        // transaction and state verification, never on serializer success.
        let result = (|| {
            self.driver()?.set_exclusions(&paths)?;
            let expected = if paths.is_empty() { 3 } else { 4 };
            if self.driver()?.state()? != expected {
                return Err(io::Error::other(
                    "split driver did not engage the requested policy",
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = true;
            if let Some(driver) = self.driver.as_mut() {
                let _ = driver.set_exclusions(&[]);
            }
            self.revision = None;
            self.engaged = false;
            return Err(policy_error(error));
        }
        // Empty exclusions are effectively full tunnel, not engaged bypass.
        self.engaged = !paths.is_empty();
        self.revision = Some(policy.revision());
        Ok(policy.revision())
    }
    fn rollback(&mut self) -> Result<(), PolicyError> {
        self.driver()
            .map_err(policy_error)?
            .set_exclusions(&[])
            .map_err(policy_error)?;
        self.revision = None;
        self.engaged = false;
        Ok(())
    }
}
impl Drop for WindowsExclusionProvider {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("[app-routing] split driver teardown failed: {error}");
        }
    }
}
