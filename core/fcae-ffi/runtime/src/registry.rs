//! Backend registry — the only module allowed to name concrete backends.
//!
//! Backends are compiled in behind cargo features so a build can ship Aether
//! only, Psiphon only, or both, without `#[cfg]` scattered through the
//! supervisor.

use fcae_abi::FcaeBackend;

use crate::backend::Backend;
use crate::error::{CoreError, Result};

/// Factory installed by the `fcae-ffi` crate at startup.
///
/// `fcae-runtime` cannot depend on the backend crates directly without a
/// dependency cycle (backends depend on core for the trait), so the top-level
/// crate registers them here instead.
pub type BackendFactory = fn() -> std::sync::Arc<dyn Backend>;

static REGISTRY: parking_lot::Mutex<Vec<(FcaeBackend, BackendFactory)>> =
    parking_lot::Mutex::new(Vec::new());

/// Register a backend implementation. Re-registering an id replaces it, which
/// makes it easy to inject a fake backend in integration tests.
pub fn register(id: FcaeBackend, factory: BackendFactory) {
    let mut reg = REGISTRY.lock();
    if let Some(slot) = reg.iter_mut().find(|(existing, _)| *existing == id) {
        slot.1 = factory;
    } else {
        reg.push((id, factory));
    }
}

/// Look up a backend, or explain that it was not compiled in.
pub fn resolve(id: FcaeBackend) -> Result<std::sync::Arc<dyn Backend>> {
    let factory = REGISTRY
        .lock()
        .iter()
        .find(|(existing, _)| *existing == id)
        .map(|(_, f)| *f);

    match factory {
        Some(f) => Ok(f()),
        None => Err(CoreError::BackendUnavailable(match id {
            FcaeBackend::Aether => "aether",
            FcaeBackend::Psiphon => "psiphon",
        })),
    }
}

/// Ids currently available, for a UI that wants to grey out unsupported ones.
pub fn available() -> Vec<FcaeBackend> {
    REGISTRY.lock().iter().map(|(id, _)| *id).collect()
}

/// Every backend the ABI knows about, registered or not.
///
/// `available()` only lists what was compiled in, so a UI iterating it can
/// never render "Psiphon — not included in this build". This lists all ids so
/// the caller can show the full menu and explain the gaps.
pub const ALL: [FcaeBackend; 2] = [FcaeBackend::Aether, FcaeBackend::Psiphon];

/// Registered *and* able to start. A backend can be registered yet be a stub
/// (Psiphon without `--features psiphon-live`), which previously only
/// surfaced as a failed start.
pub fn describe(id: FcaeBackend) -> (bool, String, crate::backend::Capabilities) {
    match resolve(id) {
        Ok(backend) => {
            let caps = backend.capabilities();
            match backend.availability() {
                Ok(()) => (true, String::new(), caps),
                Err(reason) => (false, reason, caps),
            }
        }
        Err(CoreError::BackendUnavailable(name)) => (
            false,
            format!("{name} is not compiled into this build"),
            crate::backend::Capabilities::NONE,
        ),
        Err(e) => (false, e.to_string(), crate::backend::Capabilities::NONE),
    }
}
