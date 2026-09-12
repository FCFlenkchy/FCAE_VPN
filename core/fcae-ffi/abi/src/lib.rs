//! # fcae-abi — the C ABI contract
//!
//! Every `#[repr(C)]` type that crosses the FFI boundary is declared here and
//! **only** here. This crate has no dependencies and does no I/O, so it can be
//! compiled by cbindgen, by bindings generators, and by tests without dragging
//! in tokio or a tunnel engine.
//!
//! ## Versioning rules
//!
//! * `FCAE_ABI_VERSION` is bumped on **any** layout change.
//! * Structs passed *in* by the host start with `struct_size: u32` so the
//!   library can accept an older/newer caller instead of reading garbage. This
//!   is what the old `AetherConfig` lacked: adding a field silently broke every
//!   prebuilt UI binary.
//! * Fields are only ever appended, never reordered or removed. Removed fields
//!   become `_reserved`.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_void};

/// Bumped on every layout-affecting change to the types in this crate.
pub const FCAE_ABI_VERSION: u32 = 6;

// ── Enumerations ────────────────────────────────────────────────────────

/// Tunnel lifecycle state, reported through [`FcaeTelemetry::state`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeState {
    Disconnected = 0,
    Provisioning = 1,
    Scanning = 2,
    Connecting = 3,
    Connected = 4,
    Error = 5,
    /// Tunnel dropped and the supervisor is retrying. Previously the UI was
    /// shown `Scanning` for this, which lost the distinction between a first
    /// connect and a recovery.
    Reconnecting = 6,
}

/// Which tunnel implementation to run. Adding `Psiphon` here (rather than
/// overloading the old `protocol` int) is what makes the second backend a
/// non-breaking change.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeBackend {
    /// Cloudflare WARP / MASQUE engine (`core/Aether`).
    Aether = 0,
    /// Psiphon tunnel core. Reserved; `fcae_start` returns
    /// [`FcaeStatus::BackendUnavailable`] until the backend is compiled in.
    Psiphon = 1,
}

/// What a backend supports, so the UI can describe it instead of hardcoding
/// per-backend special cases.
///
/// Previously the only backend introspection was
/// [`fcae_available_backends`], which returns bare ids: the UI had no way to
/// tell "Psiphon is compiled in and ready" from "Psiphon is a stub that will
/// fail on start", and no way to know Psiphon ignores scan modes and gateway
/// pinning. Both had to be hardcoded UI-side and silently went stale.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeBackendInfo {
    pub struct_size: u32,
    pub abi_version: u32,

    pub backend: FcaeBackend,
    /// Stable lowercase id, e.g. "aether", "psiphon".
    pub id: [c_char; 32],
    /// Human-readable name for a menu, e.g. "Psiphon".
    pub display_name: [c_char; 64],

    /// Registered AND able to actually start a tunnel.
    pub available: bool,
    /// Why it is unavailable; empty when `available` is true.
    pub unavailable_reason: [c_char; 192],

    /// Exposes a local SOCKS5 endpoint (required for TUN mode).
    pub supports_socks: bool,
    /// Exposes its own HTTP CONNECT endpoint.
    pub supports_http_proxy: bool,
    /// Honours `scan_mode` and `force_peer`; false for Psiphon.
    pub supports_gateway_scanning: bool,
    /// Applies split-tunnel rules internally.
    pub supports_routing_rules: bool,
    /// Needs elevation even in proxy mode.
    pub requires_privileges: bool,

    pub _reserved: [u64; 4],
}

/// Transport selected *within* a backend.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeProtocol {
    Masque = 0,
    WireGuard = 1,
    /// WARP-in-WARP.
    Gool = 2,
    /// Backend picks. Psiphon uses this exclusively.
    Auto = 3,
    /// Tor alone, with no WARP tunnel underneath.
    ///
    /// Tor is an egress *inside* the Aether engine rather than a backend, so
    /// this is sugar for `tor.mode = Only`: it belongs in the protocol list
    /// because from the user's point of view it is a peer of MASQUE and
    /// WireGuard ("how do I get out?"), not a modifier layered on one. The
    /// Chain and Reverse modes stay on [`FcaeTor::mode`], where they really
    /// are modifiers.
    Tor = 4,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeMode {
    /// Local SOCKS5 + HTTP CONNECT proxies only.
    Proxy = 0,
    /// Proxies plus a system-wide TUN device fed by the in-process
    /// tun2socks bridge.
    Tun = 1,
}

/// Verbosity of the **Aether engine's** own logging (`AETHER_LOG_LEVEL`).
///
/// This is distinct from [`FcaeLogLevel`], which filters what the FFI passes
/// to the host's log callback. The FFI needs no knob -- it always reports at
/// info -- but the engine is chatty and its level is worth exposing.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeEngineLog {
    /// Engine logging disabled entirely.
    Off = 0,
    Error = 1,
    Warn = 2,
    /// The default.
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl FcaeEngineLog {
    /// The value `AETHER_LOG_LEVEL` expects.
    pub fn as_str(self) -> &'static str {
        match self {
            FcaeEngineLog::Off => "off",
            FcaeEngineLog::Error => "error",
            FcaeEngineLog::Warn => "warn",
            FcaeEngineLog::Info => "info",
            FcaeEngineLog::Debug => "debug",
            FcaeEngineLog::Trace => "trace",
        }
    }
}

/// Tor egress, mirroring the engine's own `AETHER_TOR` modes.
///
/// Tor is an egress *inside* the Aether engine, not a separate backend: there
/// is no fcae-ffi bridge for it. These values are projected onto `AETHER_TOR`
/// and friends by `env_compat::apply`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeTorMode {
    /// No Tor. The default.
    Off = 0,
    /// Tor reached *through* the tunnel (tunnel -> tor -> internet).
    Chain = 1,
    /// The tunnel carried *over* Tor (tor -> tunnel -> internet).
    Reverse = 2,
    /// Tor alone, with no WARP tunnel at all.
    Only = 3,
}

/// Which built-in bridge family to request when Tor is censored.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeTorBridges {
    /// Connect directly to the Tor network.
    None = 0,
    /// Built-in obfs4 bridges.
    Obfs4 = 1,
    /// Built-in snowflake bridges.
    Snowflake = 2,
    /// Use the lines supplied in `FcaeTor::bridge_lines`.
    Custom = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeScanMode {
    Turbo = 0,
    Balanced = 1,
    Thorough = 2,
    Stealth = 3,
    Ironclad = 4,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeIpVersion {
    V4 = 4,
    V6 = 6,
    Dual = 10,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeDnsMode {
    /// Classic UDP/53.
    Udp = 0,
    /// DNS-over-HTTPS via [`FcaeConfig::doh_url`].
    Doh = 1,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeSysProfile {
    Auto = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeLogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

/// Return code for every fallible entry point.
///
/// The old ABI returned bare `bool`, so the UI could only say "it failed".
/// These codes let the UI render an actionable message (and let Android
/// distinguish "needs VPN permission" from "config is nonsense").
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcaeStatus {
    Ok = 0,
    /// `fcae_init` was never called, or `fcae_shutdown` already ran.
    NotInitialized = 1,
    /// A session is already running.
    AlreadyRunning = 2,
    /// A required pointer argument was NULL.
    NullArgument = 3,
    /// `struct_size` / `abi_version` mismatch between caller and library.
    AbiMismatch = 4,
    /// A config field failed validation; details via `fcae_last_error`.
    InvalidConfig = 5,
    /// Backend not compiled into this build (e.g. Psiphon).
    BackendUnavailable = 6,
    /// TUN mode requested without admin/root, or without a VpnService fd.
    PermissionDenied = 7,
    /// Backend started but never reached a usable state.
    StartFailed = 8,
    /// Operation timed out.
    Timeout = 9,
    /// Catch-all; details via `fcae_last_error`.
    Internal = 10,
}

// ── Configuration ───────────────────────────────────────────────────────

/// Obfuscation / fragmentation knobs, split out of the flat config so a
/// backend that does not support them can ignore one struct.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeObfuscation {
    /// "off" | "light" | "balanced" | "aggressive". NULL = "balanced".
    pub noize_profile: *const c_char,
    /// TLS ClientHello fragmentation on the HTTP/2 fallback path.
    pub fragment_enabled: bool,
    pub frag_min_size: u32,
    pub frag_max_size: u32,
    pub frag_min_delay_ms: u32,
    pub frag_max_delay_ms: u32,
    /// MASQUE over HTTP/2 instead of HTTP/3.
    pub h2_enabled: bool,
    /// Encrypted Client Hello.
    pub ech_enabled: bool,
}

/// DNS + TLS tuning.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeDnsConfig {
    /// e.g. "1.1.1.1:53". NULL = backend default.
    pub server: *const c_char,
    pub mode: FcaeDnsMode,
    /// e.g. "https://cloudflare-dns.com/dns-query".
    pub doh_url: *const c_char,
    /// Address family preference for resolution; `Dual` follows the session.
    pub ip_prefer: FcaeIpVersion,
    /// BoringSSL curve list, e.g. "P-256:X25519:P-384".
    pub tls_groups: *const c_char,
    /// TLS SNI override for MASQUE.
    pub sni: *const c_char,
}

/// Split-tunnel / routing rules.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeRouting {
    /// Path to a rules file.
    pub rules_file: *const c_char,
    /// Inline rules: `[direct]a,b [block]c` — same grammar as the file.
    pub rules_inline: *const c_char,
}

/// Cloudflare Zero Trust enrolment (Aether only).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeZeroTrust {
    pub team_name: *const c_char,
    pub access_token: *const c_char,
    pub access_email: *const c_char,
}

/// Tor egress configuration. Consumed by the Aether backend only.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeTor {
    pub mode: FcaeTorMode,
    pub bridges: FcaeTorBridges,
    /// "ip:port" for the local Tor SOCKS listener. NULL = derive from
    /// `socks_port` below, i.e. 127.0.0.1:<socks_port>.
    ///
    /// Prefer `socks_port`; this exists for binding to a non-loopback
    /// address.
    pub bind: *const c_char,
    /// Local SOCKS5 port for Tor's own listener. 0 = 1821.
    ///
    /// Distinct from the session `socks_port` (the engine's plain tunnel) and
    /// from `psiphon.socks_port`: in Chain mode Tor and the engine both
    /// listen at once, so they must not collide.
    pub socks_port: u16,
    /// State/cache directory for the Arti client. NULL = under `data_dir`.
    pub state_dir: *const c_char,
    /// Newline-separated bridge lines, used when `bridges == Custom`.
    pub bridge_lines: *const c_char,
    /// Path to a pluggable-transport binary (lyrebird/snowflake), or NULL.
    pub pt_path: *const c_char,
}

/// Psiphon-specific inputs. Present in the ABI *now* so that enabling the
/// backend later does not change the struct layout and does not invalidate
/// prebuilt UI binaries.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaePsiphon {
    /// Contents (not path) of the Psiphon `psiphon_config.json`.
    pub config_json: *const c_char,
    /// Embedded server entry list; NULL to rely on remote fetch.
    pub embedded_server_list: *const c_char,
    /// e.g. "GB"; NULL = automatic.
    pub egress_region: *const c_char,
    /// Writable directory for Psiphon's datastore.
    pub data_root_dir: *const c_char,
    /// Local SOCKS5 port for Psiphon's own proxy. 0 = let Psiphon choose.
    ///
    /// Separate from the session `socks_port`, which belongs to whichever
    /// backend is active: when Psiphon is chained behind Aether both are
    /// listening at once and they must not collide.
    pub socks_port: u16,
    /// Local HTTP CONNECT port for Psiphon. 0 = let Psiphon choose.
    pub http_port: u16,
}

/// Top-level session configuration.
///
/// **Caller must set `struct_size = sizeof(FcaeConfig)` and
/// `abi_version = FCAE_ABI_VERSION`.** Use [`fcae_config_default`] to get a
/// correctly-stamped, fully-defaulted value and then override fields.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeConfig {
    pub struct_size: u32,
    pub abi_version: u32,

    pub backend: FcaeBackend,
    pub protocol: FcaeProtocol,
    pub mode: FcaeMode,
    pub scan_mode: FcaeScanMode,
    pub ip_version: FcaeIpVersion,
    pub sys_profile: FcaeSysProfile,

    /// Bind proxies to 0.0.0.0 and report the LAN IP.
    pub lan_sharing: bool,
    /// Reuse the last known-good gateway when it still verifies.
    pub quick_reconnect: bool,
    /// 0 disables the listener (TUN mode still spawns an internal one).
    pub socks_port: u16,
    /// 0 disables the HTTP CONNECT listener.
    pub http_port: u16,
    /// "ip:port" to pin a gateway; NULL to scan.
    pub force_peer: *const c_char,
    /// Base config file path, e.g. "aether.toml".
    pub config_path: *const c_char,
    /// Writable directory for caches and extracted assets.
    pub data_dir: *const c_char,
    /// UDP socket buffer in KiB; 0 = default (512).
    pub udp_buf_kb: u32,
    /// Verbosity of the engine's own logging. Defaults to `Info`.
    pub engine_log: FcaeEngineLog,

    pub obfuscation: FcaeObfuscation,
    pub dns: FcaeDnsConfig,
    pub routing: FcaeRouting,
    pub zero_trust: FcaeZeroTrust,
    pub psiphon: FcaePsiphon,
    pub tor: FcaeTor,

    /// TUN device name. NULL = "FCAE_VPN".
    pub tun_name: *const c_char,
    /// TUN MTU; 0 = 1500.
    pub tun_mtu: u32,
    /// Android VpnService descriptor, or -1 on desktop. The bridge dups it
    /// and never closes the original — Android's ParcelFileDescriptor owns it.
    pub tun_fd: i32,

    /// Reserved for future growth without another ABI bump.
    pub _reserved: [u64; 4],
}

// ── Telemetry ───────────────────────────────────────────────────────────

/// Fixed-width snapshot of tunnel state, memcpy'd into caller-owned storage
/// so the UI never has to free anything.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeTelemetry {
    pub struct_size: u32,
    pub abi_version: u32,

    pub state: FcaeState,
    pub backend: FcaeBackend,
    pub active_mode: FcaeMode,
    pub lan_enabled: bool,

    pub rtt_ms: u32,
    pub rx_bytes_sec: u64,
    pub tx_bytes_sec: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    /// Seconds since the session reached `Connected`.
    pub uptime_secs: u64,
    /// Successful reconnects in this session.
    pub reconnect_count: u32,

    pub connected_peer: [c_char; 64],
    pub lan_ip: [c_char; 64],
    pub status_message: [c_char; 128],
    pub last_error: [c_char; 256],

    pub _reserved: [u64; 4],
}

/// Result of an update check.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeUpdateInfo {
    pub struct_size: u32,
    pub abi_version: u32,
    pub update_available: bool,
    pub check_in_progress: bool,
    pub check_done: bool,
    pub is_prerelease: bool,
    pub latest_version: [c_char; 32],
    pub release_date: [c_char; 32],
    pub release_notes: [c_char; 1024],
    pub download_url: [c_char; 512],
    pub status_message: [c_char; 256],
}

// ── Callbacks ───────────────────────────────────────────────────────────

/// Log sink. Invoked from arbitrary engine threads; `message` is only valid
/// for the duration of the call, so copy it.
pub type FcaeLogCallback =
    Option<unsafe extern "C" fn(level: FcaeLogLevel, message: *const c_char, user_data: *mut c_void)>;

/// Optional state-change notification, so a UI can react immediately instead
/// of polling telemetry at frame rate. Invoked from engine threads.
pub type FcaeStateCallback =
    Option<unsafe extern "C" fn(state: FcaeState, user_data: *mut c_void)>;

/// Everything `fcae_init` needs, as a struct so new hooks can be added
/// without changing the function signature.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FcaeInitOptions {
    pub struct_size: u32,
    pub abi_version: u32,
    pub log_cb: FcaeLogCallback,
    pub state_cb: FcaeStateCallback,
    pub user_data: *mut c_void,
    /// Messages below this level are dropped before reaching `log_cb`.
    pub max_log_level: FcaeLogLevel,
    /// Android: absolute path of the app's native library directory.
    /// Unused now that tun2socks is in-process; kept for asset lookups.
    pub native_lib_dir: *const c_char,
    pub _reserved: [u64; 4],
}

// ── Const helpers shared by Rust callers ────────────────────────────────

impl FcaeState {
    /// True while the session is doing work the user should see a spinner for.
    pub const fn is_transitional(self) -> bool {
        matches!(
            self,
            FcaeState::Provisioning
                | FcaeState::Scanning
                | FcaeState::Connecting
                | FcaeState::Reconnecting
        )
    }
}

impl FcaeStatus {
    pub const fn is_ok(self) -> bool {
        matches!(self, FcaeStatus::Ok)
    }
}
