use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum FirefoxError {
    #[error("invalid Firefox backend configuration: {0}")]
    InvalidConfig(String),
    #[error("Firefox Account not found; sign in first")]
    AccountNotFound,
    #[error("Firefox Account credentials were revoked; sign in again")]
    ReauthRequired,
    #[error("the Mozilla proxy rejected the current proxy pass")]
    PassRejected,
    #[error("Firefox Account verification is required")]
    VerificationRequired,
    #[error("Firefox Account requires the account's original email spelling")]
    EmailCaseCorrection(String),
    #[error("Mozilla's security check requires interactive sign-in")]
    ChallengeRequired,
    #[error("Firefox Accounts requires the emailed unblock code")]
    UnblockCodeRequired(String),
    #[error("Mozilla VPN quota is exhausted{0}")]
    QuotaExhausted(String),
    #[error("Mozilla VPN is not entitled for this account")]
    NotEntitled,
    #[error("Mozilla VPN is unavailable in this region")]
    RegionUnavailable,
    #[error("no Firefox VPN location is available{0}")]
    NoLocation(String),
    #[error("the selected Firefox VPN location is unavailable: {0}")]
    LocationUnavailable(String),
    #[error("unsupported destination: {0}")]
    UnsupportedDestination(String),
    #[error("connection was blocked by a routing rule")]
    Blocked,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("DNS lookup failed for {host}: {message}")]
    Dns { host: String, message: String },
    #[error("TLS connection to {host} failed: {message}")]
    Tls { host: String, message: String },
    #[error("TLS certificate verification for {host} failed: {message}. Check the device clock and network; do not bypass certificate verification")]
    TlsCertificate { host: String, message: String },
    #[error("HTTP request to {host} failed with status {status}: {message}")]
    Http {
        host: String,
        status: u16,
        errno: Option<i64>,
        retry_after: Option<Duration>,
        message: String,
    },
    #[error("HTTP/2 session failed: {0}")]
    H2(String),
    #[error("HTTP/3 is not supported by this build")]
    H3Unavailable,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("backend stopped")]
    Stopped,
    #[error("internal Firefox backend error: {0}")]
    Internal(String),
}

impl FirefoxError {
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Http { status, .. } => *status == 408 || *status == 429 || *status >= 500,
            Self::Timeout(_)
            | Self::Dns { .. }
            | Self::Tls { .. }
            | Self::H2(_)
            | Self::Network(_)
            | Self::Protocol(_) => true,
            _ => false,
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Http { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "invalid_config",
            Self::AccountNotFound => "account_not_found",
            Self::ReauthRequired => "reauth_required",
            Self::PassRejected => "pass_rejected",
            Self::VerificationRequired => "verification_required",
            Self::EmailCaseCorrection(_) => "email_case_correction",
            Self::ChallengeRequired => "challenge_required",
            Self::UnblockCodeRequired(_) => "unblock_code_required",
            Self::QuotaExhausted(_) => "quota_exhausted",
            Self::NotEntitled => "not_entitled",
            Self::RegionUnavailable => "region_unavailable",
            Self::NoLocation(_) => "no_location",
            Self::LocationUnavailable(_) => "location_unavailable",
            Self::UnsupportedDestination(_) => "unsupported_destination",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
            Self::Timeout(_) => "timeout",
            Self::Dns { .. } => "dns",
            Self::Tls { .. } => "tls",
            Self::TlsCertificate { .. } => "tls_certificate",
            Self::Http { .. } => "http",
            Self::H2(_) => "h2",
            Self::H3Unavailable => "h3_unavailable",
            Self::Protocol(_) => "protocol",
            Self::Storage(_) => "storage",
            Self::Network(_) => "network",
            Self::Stopped => "stopped",
            Self::Internal(_) => "internal",
        }
    }

    pub fn http(host: &str, status: u16, errno: Option<i64>, retry_after: Option<Duration>, message: impl Into<String>) -> Self {
        match status {
            401 => Self::ReauthRequired,
            403 => Self::NotEntitled,
            429 => Self::QuotaExhausted(String::new()),
            451 => Self::RegionUnavailable,
            _ => Self::Http {
                host: host.to_string(),
                status,
                errno,
                retry_after,
                message: message.into(),
            },
        }
    }
}

impl From<std::io::Error> for FirefoxError {
    fn from(value: std::io::Error) -> Self {
        Self::Network(value.to_string())
    }
}

impl From<serde_json::Error> for FirefoxError {
    fn from(value: serde_json::Error) -> Self {
        Self::Protocol(value.to_string())
    }
}

impl From<url::ParseError> for FirefoxError {
    fn from(value: url::ParseError) -> Self {
        Self::Protocol(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FirefoxError>;
