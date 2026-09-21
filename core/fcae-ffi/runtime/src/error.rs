//! Error type shared by the runtime, mapped 1:1 onto [`FcaeStatus`] at the
//! FFI boundary so the UI gets an actionable code instead of a bare `false`.

use fcae_abi::FcaeStatus;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("library not initialized (call fcae_init first)")]
    NotInitialized,

    #[error("a session is already running")]
    AlreadyRunning,

    #[error("null pointer passed for required argument `{0}`")]
    NullArgument(&'static str),

    #[error("ABI mismatch: {0}")]
    AbiMismatch(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("backend `{0}` is not available in this build")]
    BackendUnavailable(&'static str),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("failed to start tunnel: {0}")]
    StartFailed(String),

    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("{0}")]
    Internal(String),
}

impl CoreError {
    /// Stable numeric code handed back across the ABI.
    pub fn status(&self) -> FcaeStatus {
        match self {
            CoreError::NotInitialized => FcaeStatus::NotInitialized,
            CoreError::AlreadyRunning => FcaeStatus::AlreadyRunning,
            CoreError::NullArgument(_) => FcaeStatus::NullArgument,
            CoreError::AbiMismatch(_) => FcaeStatus::AbiMismatch,
            CoreError::InvalidConfig(_) => FcaeStatus::InvalidConfig,
            CoreError::BackendUnavailable(_) => FcaeStatus::BackendUnavailable,
            CoreError::PermissionDenied(_) => FcaeStatus::PermissionDenied,
            CoreError::StartFailed(_) => FcaeStatus::StartFailed,
            CoreError::Timeout(_) => FcaeStatus::Timeout,
            CoreError::Internal(_) => FcaeStatus::Internal,
        }
    }
}

impl CoreError {
    /// True when re-running the same operation can succeed without anything
    /// external changing. The supervisor auto-reconnects on transient
    /// failures; deterministic ones (bad config, missing privileges, a
    /// backend not compiled in) must surface immediately, or a box without
    /// resolvectl — or a TUN start without elevation — spins RECONNECTING
    /// forever instead of telling the user what to fix.
    pub fn is_transient(&self) -> bool {
        !matches!(
            self,
            CoreError::NotInitialized
                | CoreError::NullArgument(_)
                | CoreError::AbiMismatch(_)
                | CoreError::InvalidConfig(_)
                | CoreError::BackendUnavailable(_)
                | CoreError::PermissionDenied(_)
        )
    }
}

impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::Internal(format!("{e:#}"))
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
