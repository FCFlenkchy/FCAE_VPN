//! Typed session configuration.
//!
//! The old FFI turned its config struct straight into ~40 `std::env::set_var`
//! calls and the engine read them back with `env::var`. That is process-global
//! (so two backends can never run at once), racy across start/stop cycles
//! (stale vars from the previous session leak into the next), and unvalidated
//! (a typo silently became a default three layers down).
//!
//! Here the ABI struct is parsed **once** into [`SessionConfig`], validated
//! with real errors, and passed by value to the backend. [`env_compat`] still
//! projects it onto the legacy variables so the current `aether-engine` works
//! unmodified — that shim is the only place env vars are written, and it is
//! meant to be deleted once the engine accepts a config argument.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::time::Duration;

use fcae_abi::*;

use crate::saved_configs::{SavedConfig, SavedConfigs};
use crate::sing_xray::CoreProfile;
use crate::error::{CoreError, Result};
use crate::upstream::UpstreamProxy;

/// The name a UI shows for a backend.
pub fn backend_label(backend: FcaeBackend) -> &'static str {
    match backend {
        FcaeBackend::Aether => "Aether",
        FcaeBackend::Psiphon => "Psiphon",
        FcaeBackend::Firefox => "Firefox",
        FcaeBackend::Xray => "Xray",
        FcaeBackend::SingBox => "sing-box",
    }
}

/// Shared requested Windows Wintun identity for every TUN engine.
pub const WINTUN_ADAPTER_GUID: &str = "24198F4C-7895-434C-AD65-9E29A92DDC61";
pub const WINTUN_ADAPTER_GUID_U128: u128 = 0x24198f4c_7895_434c_ad65_9e29a92ddc61;

/// Read an optional C string: NULL, invalid UTF-8 and empty/whitespace all
/// collapse to `None` so callers never have to distinguish "" from NULL.
///
/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
pub unsafe fn cstr_opt(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p)
        .to_str()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscationConfig {
    pub noize_profile: String,
    pub fragment_enabled: bool,
    pub frag_size: (u32, u32),
    pub frag_delay: (u32, u32),
    pub h2_enabled: bool,
    pub ech_enabled: bool,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            noize_profile: "balanced".into(),
            fragment_enabled: false,
            frag_size: (16, 32),
            frag_delay: (2, 10),
            h2_enabled: false,
            ech_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsConfig {
    pub server: Option<String>,
    pub doh_url: Option<String>,
    pub use_doh: bool,
    /// 4, 6 or 10 (dual).
    pub ip_prefer: i32,
    pub tls_groups: Option<String>,
    pub sni: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutingConfig {
    pub rules_file: Option<String>,
    /// Hostnames/CIDRs routed around the tunnel.
    pub direct: Vec<String>,
    /// Hostnames/CIDRs dropped entirely.
    pub block: Vec<String>,
}

/// Aether engine options projected one-to-one onto its AETHER_* variables.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AetherOptions {
    pub ech_dns: Option<String>,
    pub ech_domain: Option<String>,
    pub gool_inner: Option<String>,
    pub tls_ciphers: Option<String>,
    pub api_address: Option<String>,
    pub api_host: Option<String>,
    pub api_sni: Option<String>,
    pub exit_loc: Option<String>,
    pub tls13_ciphers: Option<String>,
    pub tls_key_shares: Option<String>,
    pub tls_sigalgs: Option<String>,
    pub tls_cert_compression: Option<String>,
    pub tls_alps: Option<String>,
    pub tls_trust_anchors: Option<String>,
    pub tls_server_padding: Option<String>,
    pub tls_verify: bool,
    pub disable_grease: bool,
    pub fragment_sni: bool,
    pub enable_grease_sigalgs: bool,
    pub enable_ech_grease: bool,
    pub disable_ocsp_stapling: bool,
    pub disable_sct: bool,
    pub disable_session_ticket: bool,
    pub disable_extension_permutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZeroTrustConfig {
    pub team_name: Option<String>,
    pub access_token: Option<String>,
    pub access_email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PsiphonConfig {
    pub config_json: Option<String>,
    pub embedded_server_list: Option<String>,
    pub egress_region: Option<String>,
    pub data_root_dir: Option<String>,
    /// Local SOCKS5 port for Psiphon's own proxy. 0 is normalised to
    /// [`DEFAULT_PSIPHON_SOCKS_PORT`] so the listener never moves between
    /// sessions; clients (TUN, system proxy, other apps) can rely on it.
    pub socks_port: u16,
    /// Local HTTP CONNECT port for Psiphon. 0 is normalised to
    /// [`DEFAULT_PSIPHON_HTTP_PORT`].
    pub http_port: u16,
    /// Egress "Psiphon through the tunnel": start Aether first, then Psiphon
    /// with UpstreamProxyURL = Aether's SOCKS. User traffic then enters
    /// Psiphon (tun2socks → Psiphon → Aether → Psiphon servers).
    ///
    /// Signalled via the legacy bits of FcaeConfig._reserved[0] so the ABI does not shift.
    pub through_tunnel: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirefoxConfig {
    pub account_id: Option<String>,
    pub location: Option<String>,
    pub server: Option<String>,
    pub transport: String,
}

impl Default for FirefoxConfig {
    fn default() -> Self {
        Self { account_id: None, location: None, server: None, transport: "auto".into() }
    }
}

/// Options for the built-in proxy cores (Xray-core, sing-box).
///
/// Both cores are compiled into the app and started in-process, so the session
/// carries only what their bridges need to write a config: the outbound profile
/// and the core's own log verbosity. There is no executable to point at.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreConfig {
    /// The outbound the core dials, already parsed and validated — a malformed
    /// link is a config error, not a failed start. `None` only when no core is
    /// in the route.
    pub profile: Option<CoreProfile>,
    /// The core's own log verbosity.
    pub log_level: FcaeEngineLog,
    /// The user's saved configs. A route names one of these by position or
    /// name; nothing else can introduce a profile.
    pub library: SavedConfigs,
    /// The saved config the main backend runs, when it runs one.
    pub selection: Option<SavedConfig>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            profile: None,
            // Silent unless asked otherwise: a core at info writes a line per
            // connection through the app's own log ring.
            log_level: FcaeEngineLog::Off,
            library: SavedConfigs::default(),
            selection: None,
        }
    }
}

impl CoreConfig {
    /// The label the UI shows for this session's core, if it named one.
    pub fn selection_name(&self) -> Option<&str> {
        self.selection.as_ref().map(|entry| entry.name.as_str())
    }
}

pub const DEFAULT_TCP_BUFFER: u32 = 256000;
// gVisor TCP MinBufferSize/MaxBufferSize in the pinned tun2socks dependency.
pub const MIN_TCP_BUFFER: u32 = 4 * 1024;
pub const MAX_TCP_BUFFER: u32 = 4 * 1024 * 1024;

/// Verbosity of the tun2socks data plane (bridge + gVisor netstack logs).
/// Values mirror the `FcaeT2sLog` ABI enum: 0 = unset (treated as silent),
/// then silent/error/warn/info/debug. Silent still lets through rare error-level
/// bridge lines but suppresses the per-flow and per-query chatter.
pub const T2S_LOG_DEFAULT: u8 = 0;
pub const T2S_LOG_SILENT: u8 = 1;
pub const T2S_LOG_ERROR: u8 = 2;
pub const T2S_LOG_WARN: u8 = 3;
pub const T2S_LOG_INFO: u8 = 4;
pub const T2S_LOG_DEBUG: u8 = 5;

impl TunConfig {
    /// The tun2socks log-level string for `t2s_start`. `0` (the default)
    /// resolves to silent; the `FCAE_TUN2SOCKS_LOG` env var remains as an
    /// out-of-band debugging override on top of the default only.
    pub fn t2s_log_str(&self) -> String {
        match self.t2s_log_level {
            T2S_LOG_SILENT => "silent".to_string(),
            T2S_LOG_ERROR => "error".to_string(),
            T2S_LOG_WARN => "warn".to_string(),
            T2S_LOG_INFO => "info".to_string(),
            T2S_LOG_DEBUG => "debug".to_string(),
            _ => {
                if let Ok(v) = std::env::var("FCAE_TUN2SOCKS_LOG") {
                    let v = v.trim().to_ascii_lowercase();
                    if matches!(v.as_str(), "debug" | "info" | "warn" | "error" | "silent") {
                        return v;
                    }
                }
                "silent".to_string()
            }
        }
    }
}

pub fn parse_tcp_buffer_size(text: &str) -> Result<u32> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CoreError::InvalidConfig("TCP buffer: enter a whole byte count (4096..4194304)".into()));
    }
    let bytes = text.parse::<u32>().map_err(|_| CoreError::InvalidConfig("TCP buffer byte count is too large".into()))?;
    if !(MIN_TCP_BUFFER..=MAX_TCP_BUFFER).contains(&bytes) {
        return Err(CoreError::InvalidConfig("TCP buffer must be 4096..4194304 bytes".into()));
    }
    Ok(bytes)
}

fn tcp_buffer_or_default(bytes: u32, field: &str) -> Result<u32> {
    if bytes == 0 { return Ok(DEFAULT_TCP_BUFFER); }
    if !(MIN_TCP_BUFFER..=MAX_TCP_BUFFER).contains(&bytes) {
        return Err(CoreError::InvalidConfig(format!("{field} must be 4096..4194304 bytes (or 0 for 256000)")));
    }
    Ok(bytes)
}

/// TUN data-plane engine: which in-process bridge converts the backend's
/// SOCKS endpoint into a TUN device. Mirrors `FCAE_TUN_ENGINE_*` in the ABI.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum TunEngine {
    /// Go tun2socks + gVisor netstack — the long-tested default.
    #[default]
    Tun2socks,
    /// Zig zeptun userspace engine (static C ABI, no runtime).
    Zeptun,
    /// C hev-socks5-tunnel engine (static library, coroutine-based I/O).
    Hev,
}

/// TUN parameters. Owned by the supervisor, not the backend: whichever
/// backend runs, TUN is raised the same way on top of its SOCKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Which TUN engine runs this session. The ffi crate installs a
    /// dispatcher bridge that reads this field per start.
    pub engine: TunEngine,
    pub tcp_sndbuf: u32,
    pub tcp_rcvbuf: u32,
    pub tcp_auto_tuning: bool,
    /// tun2socks log verbosity: one of the T2S_LOG_* values (0 = default/silent).
    /// The zeptun engine maps the same knob onto its own log tiers.
    pub t2s_log_level: u8,
    pub name: String,
    pub mtu: u32,
    pub ipv4: String,
    pub ipv6: Option<String>,
    /// Android VpnService descriptor; `None` on desktop.
    pub fd: Option<i32>,
    /// Keep private ranges off the device. On -- the default -- the LAN and
    /// carrier-grade NAT keep using the physical interface, so a printer, a
    /// NAS or the router's admin page stays reachable while the tunnel is up.
    /// Off routes everything into the device, private ranges included.
    pub exclude_private: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tcp_sndbuf: DEFAULT_TCP_BUFFER,
            tcp_rcvbuf: DEFAULT_TCP_BUFFER,
            // Auto-tuning grows the receive buffer up to the kernel cap; on
            // high-latency, lossy links (the common case for this VPN) it
            // tends to overshoot and add queueing delay, so it is OFF by
            // default on every platform and opt-in from both UIs.
            tcp_auto_tuning: false,
            engine: TunEngine::Tun2socks,
            t2s_log_level: T2S_LOG_DEFAULT,
            name: "FCAE_VPN".into(),
            exclude_private: true,
            mtu: 1500,
            ipv4: "198.18.0.1/24".into(),
            ipv6: Some("fc00::1/64".into()),
            fd: None,
        }
    }
}

/// Tor egress settings. Tor lives *inside* the Aether engine, so this is
/// projected onto the engine's `AETHER_TOR*` env vars rather than driving a
/// separate backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorConfig {
    pub http_port: u16,
    pub mode: FcaeTorMode,
    pub bridges: FcaeTorBridges,
    pub bind: Option<String>,
    pub state_dir: Option<String>,
    pub bridge_lines: Option<String>,
    pub pt_path: Option<String>,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            http_port: 0,
            mode: FcaeTorMode::Off,
            bridges: FcaeTorBridges::None,
            bind: None,
            state_dir: None,
            bridge_lines: None,
            pt_path: None,
        }
    }
}

impl TorConfig {
    pub fn is_enabled(&self) -> bool {
        self.mode != FcaeTorMode::Off
    }

    /// Tor is the traffic exit (Only or Chain). Reverse carries the tunnel
    /// *over* Tor, so DNS still exits through the WARP peer.
    pub fn is_exit(&self) -> bool {
        matches!(self.mode, FcaeTorMode::Only | FcaeTorMode::Chain)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainHop {
    pub backend: FcaeBackend,
    pub protocol: FcaeProtocol,
    pub h2_enabled: bool,
    /// The saved config this hop runs, resolved from the list. A core hop
    /// without one falls back to the session's `core.profile`, which is what a
    /// pre-library caller (ABI v24) necessarily meant.
    pub core: Option<SavedConfig>,
}

impl ChainHop {
    pub fn new(backend: FcaeBackend, protocol: FcaeProtocol, h2_enabled: bool) -> Self {
        Self { backend, protocol, h2_enabled, core: None }
    }

    /// The label the protocol list shows for this hop.
    pub fn label(&self) -> &str {
        self.core
            .as_ref()
            .map_or_else(|| backend_label(self.backend), |entry| entry.name.as_str())
    }
}

/// Which listeners each backend may open when it is a chain hop rather than the
/// session's exit.
///
/// A hop is dialled through its SOCKS5 listener, so that one is required; its
/// HTTP listener is the user's own switch and is opened exactly when they left
/// it on, the same as it is for the exit. Every backend is here for the same
/// reason: a hop this app starts is still the core the user configured, and one
/// of them silently losing half of its listener configuration is what made an
/// HTTP proxy available on an exit and missing on the hop in front of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerPolicy {
    pub aether_socks: bool,
    pub aether_http: bool,
    pub firefox_socks: bool,
    pub firefox_http: bool,
    pub tor_socks: bool,
    pub tor_http: bool,
    pub xray_socks: bool,
    pub xray_http: bool,
    pub singbox_socks: bool,
    pub singbox_http: bool,
}

impl Default for ListenerPolicy {
    /// What a caller that names no listeners at all means: every SOCKS5
    /// listener on, every HTTP listener off, which is the pair a chained hop
    /// needs and nothing more.
    fn default() -> Self {
        Self {
            aether_socks: true,
            aether_http: false,
            firefox_socks: true,
            firefox_http: false,
            tor_socks: true,
            tor_http: false,
            xray_socks: true,
            xray_http: false,
            singbox_socks: true,
            singbox_http: false,
        }
    }
}

/// Fully validated session configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionConfig {
    pub backend: FcaeBackend,
    pub protocol: FcaeProtocol,
    pub mode: FcaeMode,
    pub scan_mode: FcaeScanMode,
    /// 4, 6 or 10.
    pub ip_version: i32,
    pub sys_profile: FcaeSysProfile,

    pub lan_sharing: bool,
    pub quick_reconnect: bool,
    /// SOCKS port; zero disables the listener.
    pub socks_port: u16,
    pub http_port: u16,
    pub internal_socks: bool,
    pub internal_http: bool,
    pub require_udp_proxy: bool,
    pub listener_policy: Option<ListenerPolicy>,
    pub force_peer: Option<String>,
    pub config_path: String,
    pub data_dir: Option<String>,
    pub udp_buf_kb: Option<u32>,
    /// Verbosity of the engine's own logging.
    pub engine_log: FcaeEngineLog,

    pub obfuscation: ObfuscationConfig,
    pub dns: DnsConfig,
    pub routing: RoutingConfig,
    pub zero_trust: ZeroTrustConfig,
    pub psiphon: PsiphonConfig,
    pub tor: TorConfig,
    pub tun: TunConfig,
    pub aether: AetherOptions,
    /// Proxy every outbound connection of the session goes through.
    pub upstream_proxy: Option<UpstreamProxy>,
    pub firefox: FirefoxConfig,
    /// Xray-core / sing-box options.
    pub core: CoreConfig,
    /// Additional exits in carrier-to-final-exit order.
    pub chain: Vec<ChainHop>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            backend: FcaeBackend::Aether,
            protocol: FcaeProtocol::Masque,
            mode: FcaeMode::Proxy,
            scan_mode: FcaeScanMode::Balanced,
            ip_version: 4,
            sys_profile: FcaeSysProfile::Auto,
            lan_sharing: false,
            quick_reconnect: true,
            socks_port: 1819,
            http_port: 1820,
            internal_socks: false,
            internal_http: false,
            require_udp_proxy: false,
            listener_policy: None,
            force_peer: None,
            config_path: "aether.toml".into(),
            data_dir: None,
            udp_buf_kb: None,
            engine_log: FcaeEngineLog::Info,
            obfuscation: ObfuscationConfig::default(),
            dns: DnsConfig::default(),
            routing: RoutingConfig::default(),
            zero_trust: ZeroTrustConfig::default(),
            psiphon: PsiphonConfig::default(),
            tor: TorConfig::default(),
            tun: TunConfig::default(),
            aether: AetherOptions::default(),
            upstream_proxy: None,
            firefox: FirefoxConfig::default(),
            core: CoreConfig::default(),
            chain: Vec::new(),
        }
    }
}

impl SessionConfig {
    /// Address the local SOCKS listener binds to.
    pub fn socks_bind_host(&self) -> &'static str {
        if self.lan_sharing {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        }
    }

    /// TUN mode always needs a SOCKS endpoint for the bridge to dial, even
    /// when the user disabled the *public* listener.
    pub fn needs_socks(&self) -> bool {
        self.socks_port != 0 || self.mode == FcaeMode::Tun
    }

    pub fn is_tun(&self) -> bool {
        self.mode == FcaeMode::Tun
    }

    pub fn exit_backend(&self) -> FcaeBackend {
        self.chain.last().map(|hop| hop.backend).unwrap_or(self.backend)
    }

    pub fn upstream_requires_udp(&self) -> bool {
        aether_carrier_is_udp(self)
    }

    /// How long to let a backend reach a usable state before giving up.
    pub fn start_timeout(&self) -> Duration {
        // Psiphon does not scan; its establishment (server list fetch plus
        // handshake, possibly through an upstream proxy) has its own budget.
        if self.backend == FcaeBackend::Psiphon {
            return PSIPHON_START_TIMEOUT;
        }
        // A core needs to parse its config and open its listener, and a REALITY
        // handshake on a censored line is not instant.
        if is_core_backend(self.backend) {
            return CORE_START_TIMEOUT;
        }
        if self.backend == FcaeBackend::Aether && self.scan_mode == FcaeScanMode::Ironclad {
            return Duration::from_secs(240);
        }
        match self.scan_mode {
            FcaeScanMode::Turbo => Duration::from_secs(30),
            FcaeScanMode::Balanced => Duration::from_secs(60),
            FcaeScanMode::Stealth => Duration::from_secs(90),
            FcaeScanMode::Thorough | FcaeScanMode::Ironclad => Duration::from_secs(150),
        }
    }

    /// How long to wait for tor to open its SOCKS port, on top of the carrier
    /// tunnel already being up.
    ///
    /// Bootstrapping a tor circuit is far slower than opening a local
    /// listener, and slower again over obfs4/snowflake bridges where the
    /// engine retries whole waves of them, so this is deliberately generous
    /// compared to [`start_timeout`](Self::start_timeout).
    pub fn tor_start_timeout(&self) -> Duration {
        let base = match self.tor.bridges {
            FcaeTorBridges::None => Duration::from_secs(120),
            // Bridge bootstrap probes run to 360s per wave in the engine.
            _ => Duration::from_secs(420),
        };
        base + self.start_timeout()
    }
}

/// Ranges a TUN device leaves alone while [`TunConfig::exclude_private`] is on:
/// every IPv4 block the IANA special-purpose registry marks as not globally
/// reachable.
///
/// They keep using the physical interface instead of the device, which is what
/// keeps a printer, a NAS, a router's admin page or a WireGuard endpoint
/// reachable while the VPN is up, and what keeps multicast and link-local
/// traffic off a gateway that could not route it anyway.
///
/// The installs are add-only, so a block that already has a more specific route
/// of its own — loopback, link-local, multicast — keeps it; nothing here is ever
/// overwritten, and an address in one of these blocks can only leave through the
/// interface it already uses.
pub const PRIVATE_PREFIXES: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),      // this network
    (Ipv4Addr::new(10, 0, 0, 0), 8),     // RFC 1918
    (Ipv4Addr::new(100, 64, 0, 0), 10),  // shared address space, carrier-grade NAT
    (Ipv4Addr::new(127, 0, 0, 0), 8),    // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16), // link-local
    (Ipv4Addr::new(172, 16, 0, 0), 12),  // RFC 1918
    (Ipv4Addr::new(192, 168, 0, 0), 16), // RFC 1918
    (Ipv4Addr::new(224, 0, 0, 0), 4),    // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),    // reserved, broadcast included
];

/// The IPv6 half of [`PRIVATE_PREFIXES`]: unique local addresses, link-local,
/// the deprecated site-local scope, multicast, and loopback.
///
/// A global unicast address is the only IPv6 destination a tunnel can carry, so
/// everything else on this list is a scope no gateway is allowed to forward.
pub const PRIVATE_PREFIXES_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::LOCALHOST, 128),                        // loopback
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),   // unique local
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),  // link-local
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),  // site-local, deprecated
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),   // multicast
];

/// Every prefix a device must not capture, both families, when private ranges
/// are excluded.
pub fn excluded_prefixes() -> impl Iterator<Item = (IpAddr, u8)> {
    PRIVATE_PREFIXES
        .iter()
        .map(|(network, bits)| (IpAddr::V4(*network), *bits))
        .chain(PRIVATE_PREFIXES_V6.iter().map(|(network, bits)| (IpAddr::V6(*network), *bits)))
}

/// Insert `UpstreamProxyURL` into a Psiphon config object.
///
/// Used when Psiphon is the egress hop: it must dial through Aether's SOCKS
/// rather than the underlay. The URL is a loopback URI and contains no
/// characters that need JSON escaping.
///
/// tunnel-core's `upstreamproxy` package accepts the `socks5://`,
/// `socks4a://` and `http://` URI schemes (golang.org/x/net/proxy plus its
/// own registrations); anything else fails config load inside psi.Start.
pub fn inject_upstream_proxy_url(config_json: &str, url: &str) -> String {
    let trimmed = config_json.trim();
    let body = trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')).unwrap_or(trimmed);
    let body = body.trim().trim_end_matches(',');
    if body.is_empty() {
        format!("{{\"UpstreamProxyURL\":\"{url}\"}}")
    } else {
        format!("{{{body},\"UpstreamProxyURL\":\"{url}\"}}")
    }
}

/// Default local SOCKS port for Tor's own listener.
///
/// Not 1820: that is the default HTTP proxy port, and sharing it meant
/// whichever listener bound second died with "address already in use".
pub const DEFAULT_TOR_SOCKS_PORT: u16 = 1821;

/// Psiphon's own local listeners. Fixed rather than "let Psiphon pick":
/// an ephemeral port changed on every connect, so anything pointed at
/// it (a browser's proxy setting, LAN clients, the TUN bridge between
/// reconnects) silently broke. 1823/1824 sit after the engine (1819/1820)
/// and Tor (1821/1822) so the four backends never collide by default.
pub const DEFAULT_PSIPHON_SOCKS_PORT: u16 = 1823;
/// Psiphon establishment budget, whatever the WARP scan mode.
pub const PSIPHON_START_TIMEOUT: Duration = Duration::from_secs(150);
/// Budget for a core to come up: config parse, listener bind and the first
/// successful SOCKS5 handshake on its inbound.
pub const CORE_START_TIMEOUT: Duration = Duration::from_secs(45);

/// Whether `backend` is one of the built-in proxy cores (Xray-core, sing-box).
pub const fn is_core_backend(backend: FcaeBackend) -> bool {
    matches!(backend, FcaeBackend::Xray | FcaeBackend::SingBox)
}
pub const DEFAULT_PSIPHON_HTTP_PORT: u16 = 1824;

/// Reject two listeners sharing a port, with a message naming both.
fn check_port_clash(what: &str, port: u16, other: u16, other_name: &str) -> Result<()> {
    if other != 0 && port == other {
        return Err(CoreError::InvalidConfig(format!(
            "{what} port {port} collides with {other_name}; they must differ"
        )));
    }
    Ok(())
}

/// Validate the caller's struct header. Checked *before* any field is read,
/// which is what makes adding fields non-fatal for older UI binaries.
fn check_abi(struct_size: u32, abi_version: u32, expected_size: usize, what: &str) -> Result<()> {
    if abi_version != FCAE_ABI_VERSION {
        return Err(CoreError::AbiMismatch(format!(
            "{what}: caller abi_version={abi_version}, library={FCAE_ABI_VERSION}"
        )));
    }
    if struct_size as usize != expected_size {
        return Err(CoreError::AbiMismatch(format!(
            "{what}: caller struct_size={struct_size}, library={expected_size}"
        )));
    }
    Ok(())
}

/// The engine drops country codes it cannot read, so a typo would quietly
/// turn the exit filter off; refuse it instead.
fn valid_exit_loc(spec: &str) -> bool {
    let codes = spec.strip_prefix('!').unwrap_or(spec);
    codes.split(',').all(|code| {
        let code = code.trim();
        code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic())
    })
}

unsafe fn parse_aether(raw: &FcaeAether) -> Result<AetherOptions> {
    let gool_inner = cstr_opt(raw.gool_inner);
    if let Some(peer) = gool_inner.as_deref() {
        if peer.parse::<std::net::SocketAddr>().is_err() {
            return Err(CoreError::InvalidConfig(format!(
                "aether.gool_inner={peer:?} is not a valid ip:port"
            )));
        }
    }
    let ech_dns = cstr_opt(raw.ech_dns);
    if let Some(dns) = ech_dns.as_deref() {
        if !["udp://", "tcp://", "https://"].iter().any(|scheme| dns.starts_with(scheme)) {
            return Err(CoreError::InvalidConfig(format!(
                "aether.ech_dns={dns:?} must start with udp://, tcp:// or https://"
            )));
        }
    }
    let exit_loc = cstr_opt(raw.exit_loc);
    if let Some(spec) = exit_loc.as_deref() {
        if !valid_exit_loc(spec) {
            return Err(CoreError::InvalidConfig(format!(
                "aether.exit_loc={spec:?} must be two-letter country codes, e.g. DE,SE or !IR,RU"
            )));
        }
    }
    Ok(AetherOptions {
        ech_dns,
        ech_domain: cstr_opt(raw.ech_domain),
        gool_inner,
        tls_ciphers: cstr_opt(raw.tls_ciphers),
        api_address: cstr_opt(raw.api_address),
        api_host: cstr_opt(raw.api_host),
        api_sni: cstr_opt(raw.api_sni),
        exit_loc,
        tls13_ciphers: cstr_opt(raw.tls13_ciphers),
        tls_key_shares: cstr_opt(raw.tls_key_shares),
        tls_sigalgs: cstr_opt(raw.tls_sigalgs),
        tls_cert_compression: cstr_opt(raw.tls_cert_compression),
        tls_alps: cstr_opt(raw.tls_alps),
        tls_trust_anchors: cstr_opt(raw.tls_trust_anchors),
        tls_server_padding: cstr_opt(raw.tls_server_padding),
        tls_verify: raw.tls_verify,
        disable_grease: raw.disable_grease,
        fragment_sni: raw.fragment_sni,
        enable_grease_sigalgs: raw.enable_grease_sigalgs,
        enable_ech_grease: raw.enable_ech_grease,
        disable_ocsp_stapling: raw.disable_ocsp_stapling,
        disable_sct: raw.disable_sct,
        disable_session_ticket: raw.disable_session_ticket,
        disable_extension_permutation: raw.disable_extension_permutation,
    })
}

/// Parse the saved configs a session may point at, and resolve the one the main
/// backend runs.
///
/// The list is parsed before anything else can use it: a malformed document
/// or a dangling reference is worth reporting even on a route that never dials
/// a core, because the editor that wrote it will write it again.
///
/// # Safety
/// `raw` must be a valid `FcaeCore` whose string fields are NULL or valid
/// NUL-terminated strings that outlive this call.
unsafe fn parse_saved_configs(raw: &FcaeCore) -> Result<(SavedConfigs, Option<SavedConfig>)> {
    let saved = match cstr_opt(raw.library) {
        Some(text) => SavedConfigs::parse(&text)
            .map_err(|error| CoreError::InvalidConfig(format!("core.library: {error}")))?,
        None => SavedConfigs::default(),
    };
    let selection = match cstr_opt(raw.config_ref) {
        Some(reference) => {
            let entry = saved
                .resolve(&reference)
                .map_err(|error| CoreError::InvalidConfig(format!("core.config_ref: {error}")))?;
            Some(entry.clone())
        }
        None => None,
    };
    Ok((saved, selection))
}

/// Parse and validate the external-core options.
///
/// Only the shape is checked here. The share-link grammar lives in the bridge
/// that expands it — duplicating it would let the two copies drift apart, and
/// the bridge reports the offending field with the same `InvalidConfig` status.
unsafe fn parse_core(
    raw: &FcaeCore,
    required: bool,
    saved: SavedConfigs,
    selection: Option<SavedConfig>,
) -> Result<CoreConfig> {
    let log_level = FcaeEngineLog::try_from(raw.log_level as u32).map_err(|_| {
        CoreError::InvalidConfig(format!("core.log_level={} is invalid", raw.log_level as u32))
    })?;

    // A selected saved config is the profile: it was validated when the list
    // was parsed, and it is the entry the user picked out of the protocol list.
    let mut profile = selection.as_ref().map(|entry| entry.profile.clone());
    if profile.is_none() {
        profile = match cstr_opt(raw.profile).as_deref() {
            Some(text) => match CoreProfile::parse(text) {
                Ok(profile) => Some(profile),
                // A stale profile must not block a session that never dials a
                // core, but on a core route it is the difference between a
                // working tunnel and a child process that exits a second after
                // start.
                Err(error) if !required => {
                    log::warn!("[config] ignoring core.profile: {error}");
                    None
                }
                Err(error) => {
                    return Err(CoreError::InvalidConfig(format!("core.profile: {error}")));
                }
            },
            None if required => {
                return Err(CoreError::InvalidConfig(
                    "the Xray/sing-box backend needs a saved config (core.config_ref) or core.profile"
                        .into(),
                ))
            }
            None => None,
        };
    }

    Ok(CoreConfig {
        profile,
        log_level,
        library: saved,
        selection,
    })
}

/// Parse and validate an ABI config struct.
///
/// # Safety
/// `raw` must point to a valid `FcaeConfig` whose string fields are NULL or
/// valid NUL-terminated strings that outlive this call.
pub unsafe fn parse(raw: *const FcaeConfig) -> Result<SessionConfig> {
    let raw = raw.as_ref().ok_or(CoreError::NullArgument("config"))?;
    check_abi(
        raw.struct_size,
        raw.abi_version,
        std::mem::size_of::<FcaeConfig>(),
        "FcaeConfig",
    )?;

    // Validate enum discriminants crossing FFI before relying on them
    let backend_val = raw.backend as u32;
    let backend = FcaeBackend::try_from(backend_val)
        .map_err(|_| CoreError::InvalidConfig(format!("backend={backend_val} is invalid")))?;

    let protocol_val = raw.protocol as u32;
    let protocol = FcaeProtocol::try_from(protocol_val)
        .map_err(|_| CoreError::InvalidConfig(format!("protocol={protocol_val} is invalid")))?;

    let mode_val = raw.mode as u32;
    let mode = FcaeMode::try_from(mode_val)
        .map_err(|_| CoreError::InvalidConfig(format!("mode={mode_val} is invalid")))?;

    let scan_mode_val = raw.scan_mode as u32;
    let scan_mode = FcaeScanMode::try_from(scan_mode_val)
        .map_err(|_| CoreError::InvalidConfig(format!("scan_mode={scan_mode_val} is invalid")))?;

    let ip_version_val = raw.ip_version as u32;
    let ip_version = FcaeIpVersion::try_from(ip_version_val)
        .map_err(|_| CoreError::InvalidConfig(format!("ip_version={ip_version_val} is invalid")))?;

    let sys_profile_val = raw.sys_profile as u32;
    let sys_profile = FcaeSysProfile::try_from(sys_profile_val)
        .map_err(|_| CoreError::InvalidConfig(format!("sys_profile={sys_profile_val} is invalid")))?;

    let engine_log_val = raw.engine_log as u32;
    let engine_log = FcaeEngineLog::try_from(engine_log_val)
        .map_err(|_| CoreError::InvalidConfig(format!("engine_log={engine_log_val} is invalid")))?;

    let _ = FcaeDnsMode::try_from(raw.dns.mode as u32)
        .map_err(|_| CoreError::InvalidConfig(format!("dns.mode={} is invalid", raw.dns.mode as u32)))?;

    let _ = FcaeIpVersion::try_from(raw.dns.ip_prefer as u32)
        .map_err(|_| CoreError::InvalidConfig(format!("dns.ip_prefer={} is invalid", raw.dns.ip_prefer as u32)))?;

    let _ = FcaeTorMode::try_from(raw.tor.mode as u32)
        .map_err(|_| CoreError::InvalidConfig(format!("tor.mode={} is invalid", raw.tor.mode as u32)))?;

    let _ = FcaeTorBridges::try_from(raw.tor.bridges as u32)
        .map_err(|_| CoreError::InvalidConfig(format!("tor.bridges={} is invalid", raw.tor.bridges as u32)))?;

    // The saved core configs, and the one the main backend runs. Resolved here
    // rather than after the chain so that a selected config decides its own
    // backend for every check below: it is the only thing that knows whether it
    // is an Xray or a sing-box profile, and a UI that sends both a config
    // reference and a stale backend id must not end up running the wrong core.
    let (saved, main_core) = parse_saved_configs(&raw.core)?;
    let (backend, protocol) = match &main_core {
        Some(entry) => (entry.backend, FcaeProtocol::Auto),
        None => (backend, protocol),
    };

    let mut cfg = SessionConfig {
        backend,
        protocol,
        mode,
        scan_mode,
        ip_version: ip_version as i32,
        sys_profile,
        lan_sharing: raw.lan_sharing,
        quick_reconnect: raw.quick_reconnect,
        socks_port: raw.socks_port,
        http_port: raw.http_port,
        force_peer: cstr_opt(raw.force_peer),
        config_path: cstr_opt(raw.config_path).unwrap_or_else(|| "aether.toml".into()),
        data_dir: cstr_opt(raw.data_dir),
        udp_buf_kb: None,
        engine_log,
        ..SessionConfig::default()
    };

    // Ports
    // An old TUN caller may carry a default HTTP port without requesting a listener.
    if cfg.mode == FcaeMode::Tun && raw._reserved[0] & FCAE_CONFIG_TUN_HTTP == 0 {
        cfg.http_port = 0;
    }
    if cfg.protocol != FcaeProtocol::Tor && raw.tor.mode != FcaeTorMode::Only
        && cfg.http_port != 0 && cfg.http_port == cfg.socks_port {
        return Err(CoreError::InvalidConfig(format!(
            "socks_port and http_port are both {}; they must differ",
            cfg.socks_port
        )));
    }

    // UDP buffer
    // Out-of-range values used to be dropped silently; say so instead.
    cfg.udp_buf_kb = match raw.udp_buf_kb {
        0 => None,
        v if (64..=8192).contains(&v) => Some(v),
        v => {
            return Err(CoreError::InvalidConfig(format!(
                "udp_buf_kb={v} out of range (64..=8192, or 0 for default)"
            )))
        }
    };

    // Obfuscation
    let o = &raw.obfuscation;
    let noize = cstr_opt(o.noize_profile).unwrap_or_else(|| "balanced".into());
    if !matches!(noize.as_str(), "off" | "light" | "balanced" | "aggressive" | "firewall" | "gfw") {
        return Err(CoreError::InvalidConfig(format!(
            "noize_profile={noize:?} (expected off|light|balanced|aggressive|firewall|gfw)"
        )));
    }
    if o.fragment_enabled {
        if o.frag_min_size == 0 || o.frag_min_size > o.frag_max_size {
            return Err(CoreError::InvalidConfig(format!(
                "fragment size range {}..{} is invalid",
                o.frag_min_size, o.frag_max_size
            )));
        }
        if o.frag_min_delay_ms > o.frag_max_delay_ms {
            return Err(CoreError::InvalidConfig(format!(
                "fragment delay range {}..{} is invalid",
                o.frag_min_delay_ms, o.frag_max_delay_ms
            )));
        }
    }
    cfg.obfuscation = ObfuscationConfig {
        noize_profile: noize,
        fragment_enabled: o.fragment_enabled,
        frag_size: (o.frag_min_size, o.frag_max_size),
        frag_delay: (o.frag_min_delay_ms, o.frag_max_delay_ms),
        h2_enabled: o.h2_enabled,
        ech_enabled: o.ech_enabled,
    };

    // DNS
    let d = &raw.dns;
    let use_doh = d.mode == FcaeDnsMode::Doh;
    let doh_url = cstr_opt(d.doh_url);
    if use_doh && doh_url.is_none() {
        return Err(CoreError::InvalidConfig(
            "dns.mode = Doh but dns.doh_url is empty".into(),
        ));
    }
    // Reject garbage curve lists up front: the old code accepted them, the
    // probe then found zero endpoints and the user saw "no gateways".
    let tls_groups = match cstr_opt(d.tls_groups) {
        Some(g) if g.split(':').all(|p| !p.trim().is_empty()) => Some(g),
        Some(g) => {
            return Err(CoreError::InvalidConfig(format!(
                "tls_groups={g:?} is malformed (expected colon-separated curve names)"
            )))
        }
        None => None,
    };
    cfg.dns = DnsConfig {
        server: cstr_opt(d.server),
        doh_url,
        use_doh,
        ip_prefer: match d.ip_prefer {
            FcaeIpVersion::V4 => 4,
            FcaeIpVersion::V6 => 6,
            FcaeIpVersion::Dual => 10,
        },
        tls_groups,
        sni: cstr_opt(d.sni),
    };

    // Routing
    let (block, direct) = parse_inline_routes(cstr_opt(raw.routing.rules_inline).as_deref());
    cfg.routing = RoutingConfig {
        rules_file: cstr_opt(raw.routing.rules_file),
        direct,
        block,
    };

    // The listener switches travel inside the Psiphon config document, which is
    // the only free-form field the ABI carries. A flag is read as a flag: a
    // present `true` is on, a present `false` is off, and anything else -- a
    // string, a number, a key a caller this old does not send -- is the
    // documented default rather than a whole policy dropped, so one unreadable
    // switch cannot silence every other listener the session configured.
    cfg.listener_policy = cstr_opt(raw.psiphon.config_json)
        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
        .and_then(|json| {
            let document = json.get("FCAEListeners")?;
            let defaults = ListenerPolicy::default();
            let flag = |key: &str, fallback: bool| {
                document.get(key).and_then(serde_json::Value::as_bool).unwrap_or(fallback)
            };
            Some(ListenerPolicy {
                aether_socks: flag("aetherSocks", defaults.aether_socks),
                aether_http: flag("aetherHttp", defaults.aether_http),
                firefox_socks: flag("firefoxSocks", defaults.firefox_socks),
                firefox_http: flag("firefoxHttp", defaults.firefox_http),
                tor_socks: flag("torSocks", defaults.tor_socks),
                tor_http: flag("torHttp", defaults.tor_http),
                xray_socks: flag("xraySocks", defaults.xray_socks),
                xray_http: flag("xrayHttp", defaults.xray_http),
                singbox_socks: flag("singboxSocks", defaults.singbox_socks),
                singbox_http: flag("singboxHttp", defaults.singbox_http),
            })
        });

    // Zero Trust and Psiphon
    cfg.zero_trust = ZeroTrustConfig {
        team_name: cstr_opt(raw.zero_trust.team_name),
        access_token: cstr_opt(raw.zero_trust.access_token),
        access_email: cstr_opt(raw.zero_trust.access_email),
    };
    cfg.psiphon = PsiphonConfig {
        config_json: cstr_opt(raw.psiphon.config_json),
        embedded_server_list: cstr_opt(raw.psiphon.embedded_server_list),
        egress_region: cstr_opt(raw.psiphon.egress_region),
        data_root_dir: cstr_opt(raw.psiphon.data_root_dir),
        socks_port: raw.psiphon.socks_port,
        http_port: raw.psiphon.http_port,
        // Egress "Psiphon through the tunnel": the UI signals it via
        // _reserved[0] (see FcaeConfig in fcae.h) so the ABI does not shift.
        // This used to be dropped here — the flag was set by the UI, parsed
        // by nothing, and the supervisor chained nothing, so Psiphon always
        // dialled the underlay directly instead of through Aether.
        through_tunnel: raw._reserved[0] & !FCAE_CONFIG_TUN_HTTP != 0,
    };

    cfg.aether = parse_aether(&raw.aether)?;
    cfg.upstream_proxy = UpstreamProxy::from_c(raw.upstream_proxy)
        .map_err(|e| CoreError::InvalidConfig(format!("upstream_proxy: {e}")))?;
    let firefox_transport = cstr_opt(raw.firefox.transport).unwrap_or_else(|| "auto".into());
    if !matches!(firefox_transport.as_str(), "auto" | "h1" | "h2" | "h3") {
        return Err(CoreError::InvalidConfig(format!(
            "firefox.transport={firefox_transport:?} is invalid (expected auto, h1, h2 or h3)"
        )));
    }
    cfg.firefox = FirefoxConfig {
        account_id: cstr_opt(raw.firefox.account_id),
        location: cstr_opt(raw.firefox.location),
        server: cstr_opt(raw.firefox.server),
        transport: firefox_transport,
    };
    if raw.chain.hop_count > 0 {
        if raw.chain.hops.is_null() {
            return Err(CoreError::InvalidConfig("chain.hops is null with a nonzero hop_count".into()));
        }
        for (index, exit) in std::slice::from_raw_parts(raw.chain.hops, raw.chain.hop_count as usize)
            .iter()
            .enumerate()
        {
            let backend = FcaeBackend::try_from(exit.backend as u32)
                .map_err(|_| CoreError::InvalidConfig("chain contains an unknown backend".into()))?;
            let protocol = FcaeProtocol::try_from(exit.protocol as u32)
                .map_err(|_| CoreError::InvalidConfig("chain contains an unknown protocol".into()))?;
            let mut hop = ChainHop::new(backend, protocol, exit.h2_enabled);
            if let Some(reference) = cstr_opt(exit.config_ref) {
                let entry = saved.resolve(&reference).map_err(|error| {
                    CoreError::InvalidConfig(format!("chain hop {}: {error}", index + 1))
                })?;
                // A saved config knows which core reads it and has no protocol
                // dimension of its own, so the entry wins over both fields.
                hop = ChainHop {
                    backend: entry.backend,
                    protocol: FcaeProtocol::Auto,
                    h2_enabled: exit.h2_enabled,
                    core: Some(entry.clone()),
                };
            }
            cfg.chain.push(hop);
        }
    } else {
        if raw.chain.count > raw.chain.exits.len() as u32 {
            return Err(CoreError::InvalidConfig(format!(
                "chain.count={} exceeds the {} legacy additional exits available in the ABI",
                raw.chain.count,
                raw.chain.exits.len()
            )));
        }
        for exit in raw.chain.exits.iter().take(raw.chain.count as usize) {
            let exit = FcaeBackend::try_from(*exit as u32)
                .map_err(|_| CoreError::InvalidConfig("chain contains an unknown backend".into()))?;
            cfg.chain.push(ChainHop::new(exit, cfg.protocol, cfg.obfuscation.h2_enabled));
        }
    }
    if cfg.chain.is_empty() && cfg.psiphon.through_tunnel && cfg.backend != FcaeBackend::Psiphon {
        cfg.chain.push(ChainHop::new(FcaeBackend::Psiphon, cfg.protocol, cfg.obfuscation.h2_enabled));
    }
    cfg.psiphon.through_tunnel = cfg.chain.len() == 1 && cfg.chain[0].backend == FcaeBackend::Psiphon;
    // A Tor carrier can have an Aether/Firefox exit with its own listeners.
    if cfg.chain.last().is_some_and(|hop| {
        hop.backend == FcaeBackend::Firefox
            || is_core_backend(hop.backend)
            || (hop.backend == FcaeBackend::Aether && hop.protocol != FcaeProtocol::Tor)
    }) && cfg.http_port != 0 && cfg.http_port == cfg.socks_port {
        return Err(CoreError::InvalidConfig(format!(
            "socks_port and http_port are both {}; they must differ", cfg.socks_port
        )));
    }
    // A hop behind Tor or Psiphon reaches the internet over a CONNECT stream, so
    // it cannot reach an endpoint that answers on datagrams alone. That is not a
    // reason to refuse the session: the engine's own Tor carrier answers the same
    // way, by running MASQUE and MASQUE-in-MASQUE over http/2, which rides that
    // stream. The hop is moved onto the same carrier, and only a hop whose
    // endpoint has no TCP form at all is refused.
    let mut previous_udp = hop_carries_udp(&cfg);
    for index in 0..cfg.chain.len() {
        let exit = cfg.chain[index].clone();
        let mut hop = cfg.clone();
        hop.backend = exit.backend;
        hop.protocol = exit.protocol;
        hop.obfuscation.h2_enabled = exit.h2_enabled;
        hop.chain.clear();
        if hop.upstream_requires_udp() && !previous_udp {
            let rides_tcp = exit.backend == FcaeBackend::Aether
                && matches!(
                    exit.protocol,
                    FcaeProtocol::Masque | FcaeProtocol::MasqueInMasque | FcaeProtocol::WarpInMasque
                );
            if !rides_tcp {
                return Err(CoreError::InvalidConfig(format!(
                    "the {} hop answers on UDP alone, and the hop above it carries TCP only, \
                     so it can never be reached through it; use a MASQUE or WARP-in-MASQUE \
                     hop instead",
                    exit.label()
                )));
            }
            log::info!(
                "[session] the hop above carries TCP only; {} rides the http/2 carrier",
                exit.label()
            );
            cfg.chain[index].h2_enabled = true;
            hop.obfuscation.h2_enabled = true;
        }
        previous_udp = hop_carries_udp(&hop);
    }

    // The built-in cores (Xray-core, sing-box) carry their own uplink, so their
    // profile is part of the session config: parsed here, with the chain known,
    // instead of after a supervisor task has already started.
    // A core hop that names its own saved config brings its own profile, so only
    // the ones falling back to the session profile make that profile required.
    let core_in_path = is_core_backend(cfg.backend)
        || cfg
            .chain
            .iter()
            .any(|hop| is_core_backend(hop.backend) && hop.core.is_none());
    cfg.core = parse_core(&raw.core, core_in_path, saved, main_core)?;

    // Tor
    let t = &raw.tor;
    if let Some(bind) = cstr_opt(t.bind) {
        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(CoreError::InvalidConfig(format!(
                "tor.bind={bind:?} is not a valid ip:port"
            )));
        }
    }
    let bridge_lines = cstr_opt(t.bridge_lines);
    if t.bridges == FcaeTorBridges::Custom
        && bridge_lines.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(CoreError::InvalidConfig(
            "tor.bridges = Custom but tor.bridge_lines is empty".into(),
        ));
    }
    // Protocol::Tor is sugar for tor.mode = Only: the user picked "Tor" from
    // the protocol list rather than setting the egress modifier by hand.
    // Normalise here, before the checks below, so both routes validate
    // identically and everything downstream only has to look at tor.mode.
    //
    // Tor + "Tor through the tunnel" (Chain) is not a real combo: there is
    // no WARP carrier to chain through. Overwrite instead of erroring so a
    // stale saved config cannot crash or deadlock the engine.
    let mut t = *t;
    if cfg.protocol == FcaeProtocol::Tor {
        if t.mode != FcaeTorMode::Off && t.mode != FcaeTorMode::Only {
            log::warn!(
                "[tor] protocol Tor plus egress mode {} is not a valid combo; using Tor only",
                t.mode as i32
            );
        }
        t.mode = FcaeTorMode::Only;
    }
    let t = &t;

    // Tor `Only` means "no WARP tunnel at all", so a pinned gateway or a
    // protocol choice would be silently ignored. Say so rather than pretend.
    if t.mode == FcaeTorMode::Only && cfg.force_peer.is_some() {
        return Err(CoreError::InvalidConfig(
            "tor.mode = Only runs without a WARP tunnel, so force_peer cannot apply".into(),
        ));
    }
    // Reverse carries the tunnel *over* Tor, and Tor is TCP-only. WARP's
    // WireGuard endpoints answer on UDP alone, so they can never be reached
    // this way. The engine rejects this too, but only after a full scan.
    if t.mode == FcaeTorMode::Reverse
        && matches!(cfg.protocol, FcaeProtocol::WireGuard | FcaeProtocol::Gool)
    {
        return Err(CoreError::InvalidConfig(
            "tor.mode = Reverse dials the tunnel through tor, which is TCP-only, but the \
             selected protocol is UDP-based (WireGuard/WARP-in-WARP). Use MASQUE, or put \
             tor inside the tunnel with tor.mode = Chain."
                .into(),
        ));
    }
    // Tor opens its OWN socks listener. Defaulting it to 1820 put it on the
    // same port as the HTTP proxy, so whichever bound second failed with
    // "address already in use" -- tor came up only when the http proxy was
    // disabled, which is why it "worked sometimes". The default is now 1821;
    // reject an explicit collision too rather than lose the race at runtime.
    // Every listener that can be up at once must have its own port. In Chain
    // mode tor and the engine both listen; with Psiphon chained behind Aether
    // there is a third. An explicit tor.bind wins over tor.socks_port.
    let tor_port = cstr_opt(t.bind)
        .as_deref()
        .and_then(|b| b.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.port())
        .unwrap_or(if t.socks_port != 0 {
            t.socks_port
        } else {
            DEFAULT_TOR_SOCKS_PORT
        });
    if t.mode != FcaeTorMode::Off && t.mode != FcaeTorMode::Only {
        check_port_clash("tor", tor_port, cfg.http_port, "http_port")?;
    }
    if t.mode != FcaeTorMode::Off && t.mode != FcaeTorMode::Only {
        // In Only mode the tor port IS the session endpoint (the engine
        // serves tor on AETHER_SOCKS) and no WARP listener exists, so a
        // sharing socks_port is harmless; the HTTP port must still differ.
        check_port_clash("tor", tor_port, cfg.socks_port, "socks_port")?;
    }

    // Psiphon's own proxies. 0 used to mean "Psiphon chooses a free port",
    // which moved on every connect. Pin the defaults instead; the clash
    // checks below then cover them like any explicit value.
    if cfg.psiphon.socks_port == 0 { cfg.psiphon.socks_port = DEFAULT_PSIPHON_SOCKS_PORT; }
    if cfg.psiphon.http_port == 0 { cfg.psiphon.http_port = DEFAULT_PSIPHON_HTTP_PORT; }
    let psi_options = cfg.psiphon.config_json.as_deref()
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok());
    let disabled = |key: &str| psi_options.as_ref().and_then(|v| v.get(key))
        .and_then(|v| v.as_bool()).unwrap_or(false);
    let psi_socks = if disabled("DisableLocalSocksProxy") { 0 } else { cfg.psiphon.socks_port };
    let psi_http = if disabled("DisableLocalHTTPProxy") { 0 } else { cfg.psiphon.http_port };
    if psi_socks != 0 {
        check_port_clash("psiphon.socks_port", psi_socks, cfg.socks_port, "socks_port")?;
        check_port_clash("psiphon.socks_port", psi_socks, cfg.http_port, "http_port")?;
        if t.mode != FcaeTorMode::Off {
            check_port_clash("psiphon.socks_port", psi_socks, tor_port, "tor")?;
        }
    }
    if psi_http != 0 {
        check_port_clash("psiphon.http_port", psi_http, cfg.socks_port, "socks_port")?;
        check_port_clash("psiphon.http_port", psi_http, cfg.http_port, "http_port")?;
        if t.mode != FcaeTorMode::Off {
            check_port_clash("psiphon.http_port", psi_http, tor_port, "tor")?;
        }
        if psi_socks != 0 && psi_http == psi_socks {
            return Err(CoreError::InvalidConfig(
                "psiphon.socks_port and psiphon.http_port must differ".into(),
            ));
        }
    }
    let tor_http = u16::try_from(raw.tor_http_port)
        .map_err(|_| CoreError::InvalidConfig("tor_http_port must be 0..65535".into()))?;
    if t.mode != FcaeTorMode::Off && tor_http != 0 {
        check_port_clash("tor_http_port", tor_http, tor_port, "tor SOCKS")?;
        if t.mode != FcaeTorMode::Only {
            check_port_clash("tor_http_port", tor_http, cfg.socks_port, "socks_port")?;
            check_port_clash("tor_http_port", tor_http, cfg.http_port, "http_port")?;
        }
        check_port_clash("tor_http_port", tor_http, psi_socks, "psiphon SOCKS")?;
        check_port_clash("tor_http_port", tor_http, psi_http, "psiphon HTTP")?;
    }
    cfg.tor = TorConfig {
        http_port: tor_http,
        mode: t.mode,
        bridges: t.bridges,
        // Resolved once here so every consumer (env projection, the bridge's
        // readiness probe) agrees on the port instead of each re-deriving it.
        bind: Some(
            cstr_opt(t.bind).unwrap_or_else(|| format!("{}:{tor_port}", if cfg.lan_sharing { "0.0.0.0" } else { "127.0.0.1" })),
        ),
        state_dir: cstr_opt(t.state_dir),
        bridge_lines,
        pt_path: cstr_opt(t.pt_path),
    };

    // One Aether engine per session.
    //
    // The engine reads its settings from process-wide variables and resolves
    // AETHER_UPSTREAM again on every connection it makes, so two engines in one
    // process cannot hold two upstreams: the second start rewrites the first
    // one's dial-out address, and the first then reaches the network through
    // the SOCKS listener the second was pointed at -- its own. A route that
    // stacks Aether on Aether therefore has to become the one engine that
    // expresses it, or be refused with the reason.
    let aether_hops: Vec<usize> = cfg
        .chain
        .iter()
        .enumerate()
        .filter(|(_, hop)| hop.backend == FcaeBackend::Aether)
        .map(|(index, _)| index)
        .collect();
    let aether_layers = usize::from(cfg.backend == FcaeBackend::Aether) + aether_hops.len();
    if aether_layers > 1 {
        // The layers one engine runs are a single run of Aether hops. A hop on
        // both sides of another one would be two engines.
        let start = aether_hops[0];
        let contiguous = aether_hops[aether_hops.len() - 1] == start + aether_hops.len() - 1;
        if !contiguous {
            let route = cfg
                .chain
                .iter()
                .map(|hop| hop.label())
                .collect::<Vec<_>>()
                .join("→");
            return Err(CoreError::InvalidConfig(format!(
                "this route ({route}) has another hop between its Aether layers, and Aether is one \
                 engine per session: its upstream proxy is a process-wide setting, so a second \
                 engine would dial the first one through its own SOCKS listener. Keep the Aether \
                 hops next to each other"
            )));
        }
        // A route whose own engine is Aether starts there: a second Aether layer
        // behind another hop would be the second engine again.
        if cfg.backend == FcaeBackend::Aether && start != 0 {
            let route = cfg
                .chain
                .iter()
                .map(|hop| hop.label())
                .collect::<Vec<_>>()
                .join("→");
            return Err(CoreError::InvalidConfig(format!(
                "this route ({route}) puts a second Aether layer behind {}, and Aether is one \
                 engine per session: its upstream proxy is a process-wide setting, so the second \
                 engine would dial the first one through its own SOCKS listener",
                cfg.chain[0].label()
            )));
        }
        collapse_aether_layers(&mut cfg, start, aether_hops.len())?;
    }

    // TUN
    let mtu = match raw.tun_mtu {
        0 => 1500,
        v if (1280..=9000).contains(&v) => v,
        v => {
            return Err(CoreError::InvalidConfig(format!(
                "tun_mtu={v} out of range (1280..=9000, or 0 for 1500)"
            )))
        }
    };
    if cfg.backend == FcaeBackend::Psiphon {
        cfg.psiphon.through_tunnel = false;
    }
    let psiphon_exit = cfg.chain.last().map(|hop| hop.backend).unwrap_or(cfg.backend) == FcaeBackend::Psiphon;
    cfg.tun = TunConfig {
        engine: match raw.tun_engine {
            0 => TunEngine::Tun2socks,
            1 => TunEngine::Zeptun,
            2 => TunEngine::Hev,
            _ => {
                return Err(CoreError::InvalidConfig(
                    "tun_engine must be 0 (tun2socks), 1 (zeptun), or 2 (hev)".into(),
                ))
            }
        },
        tcp_sndbuf: tcp_buffer_or_default(raw.tun_tcp_sndbuf, "tun_tcp_sndbuf")?,
        tcp_rcvbuf: tcp_buffer_or_default(raw.tun_tcp_rcvbuf, "tun_tcp_rcvbuf")?,
        // 0 = default (now OFF), 1 = explicitly on, 2 = explicitly off.
        tcp_auto_tuning: match raw.tun_tcp_auto_tuning {
            1 => true,
            0 | 2 => false,
            _ => return Err(CoreError::InvalidConfig("tun_tcp_auto_tuning must be 0, 1 or 2".into())),
        },
        // Private ranges stay off the device unless the host asks for them:
        // the bit is "route them in", so an absent bit is the default.
        exclude_private: raw._reserved[0] & FCAE_CONFIG_TUN_ROUTE_PRIVATE == 0,
        t2s_log_level: match raw.tun2socks_log_level {
            v @ 0..=5 => v as u8,
            _ => {
                return Err(CoreError::InvalidConfig(
                    "tun2socks_log_level must be 0..=5 (0=default/silent, 5=debug)".into(),
                ))
            }
        },
        name: cstr_opt(raw.tun_name).unwrap_or_else(|| "FCAE_VPN".into()),
        mtu,
        fd: if raw.tun_fd >= 0 { Some(raw.tun_fd) } else { None },
        // Psiphon exits are IPv4-only. An IPv6 address on the TUN makes the
        // OS resolver ask AAAA and prefer the v6 answer, so every hostname
        // connection became a CONNECT to an IPv6 literal the exit rejects
        // ("administratively prohibited"); hosts reached by IPv4 literal
        // kept working, which is what made this look like a DNS fault.
        // Android does the same in FCAEVpnService.establishTunNow().
        ipv6: if psiphon_exit { None } else { TunConfig::default().ipv6 },
        ..TunConfig::default()
    };

    if let Some(proxy) = &cfg.upstream_proxy {
        if !proxy.kind.carries_udp() && aether_carrier_is_udp(&cfg) {
            return Err(CoreError::InvalidConfig(
                "an HTTP upstream proxy carries TCP only, but the selected transport runs over UDP \
                 (WireGuard, WARP-in-WARP or HTTP/3); pick an HTTP/2 transport or use a SOCKS5 proxy"
                    .into(),
            ));
        }
    }

    Ok(cfg)
}

/// One layer of a route, before it is folded into the single Aether engine that
/// runs it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    Tor,
    Warp(FcaeProtocol, bool),
}

/// How a layer reads in a message.
fn lane_label(lane: Lane) -> &'static str {
    match lane {
        Lane::Tor => "Tor",
        Lane::Warp(protocol, _) => match protocol {
            FcaeProtocol::Masque | FcaeProtocol::Auto | FcaeProtocol::Tor => "MASQUE",
            FcaeProtocol::WireGuard => "WireGuard",
            FcaeProtocol::Gool => "WARP-in-WARP",
            FcaeProtocol::MasqueInMasque => "MASQUE-in-MASQUE",
            FcaeProtocol::WarpInMasque => "WARP-in-MASQUE",
        },
    }
}

/// The route as the user built it, carrier first.
fn route_label(lanes: &[Lane]) -> String {
    lanes
        .iter()
        .map(|lane| lane_label(*lane))
        .collect::<Vec<_>>()
        .join(" → ")
}

/// The route an Aether engine would have to run, in the order the engine runs
/// it: Tor carrying the tunnel in front, the tunnel itself, then the hops over
/// it, and finally Tor riding inside it.
fn aether_lanes(cfg: &SessionConfig, block: std::ops::Range<usize>) -> Vec<Lane> {
    let tor_alone = cfg.tor.mode == FcaeTorMode::Only || cfg.protocol == FcaeProtocol::Tor;
    let mut lanes = Vec::with_capacity(block.len() + 2);
    if cfg.backend == FcaeBackend::Aether {
        lanes.push(if tor_alone {
            Lane::Tor
        } else {
            Lane::Warp(cfg.protocol, cfg.obfuscation.h2_enabled)
        });
    }
    for hop in &cfg.chain[block] {
        lanes.push(if hop.protocol == FcaeProtocol::Tor {
            Lane::Tor
        } else {
            Lane::Warp(hop.protocol, hop.h2_enabled)
        });
    }
    // The engine's own Tor egress, where the engine puts it: in front of the
    // tunnel when it carries it, directly behind the tunnel when it rides
    // inside it, so a hop behind Tor reads as one and is refused with that
    // reason rather than folded into a tunnel Tor cannot reach.
    match cfg.tor.mode {
        FcaeTorMode::Off | FcaeTorMode::Only => {}
        FcaeTorMode::Reverse => lanes.insert(0, Lane::Tor),
        FcaeTorMode::Chain => lanes.insert(1.min(lanes.len()), Lane::Tor),
    }
    lanes
}

/// Whether a tunnel's own transport answers on datagrams alone, which Tor --
/// a TCP-only carrier -- can never reach.
fn needs_udp_from_its_carrier(protocol: FcaeProtocol) -> bool {
    matches!(protocol, FcaeProtocol::WireGuard | FcaeProtocol::Gool)
}

/// Rewrites a route that asks for more than one Aether layer into the one engine
/// that runs it, and refuses the shapes it has no form for.
///
/// What the engine can do natively is exactly what stacking Aether hops means:
/// Tor inside the tunnel (`Chain`) and the tunnel dialled through Tor
/// (`Reverse`). Those three are the only rewrites made here, and each of them
/// is a mode the user asked for by putting Tor in the route. Two WARP tunnels
/// are *not* folded into one double-WARP protocol: the engine runs them as one
/// protocol, not as two hops, so a route that adds a second Aether hop instead
/// of choosing WARP-in-WARP or MASQUE-in-MASQUE is wrong and says so.
fn collapse_aether_layers(cfg: &mut SessionConfig, start: usize, len: usize) -> Result<()> {
    let aether_backend = cfg.backend == FcaeBackend::Aether;
    let block = start..start + len;
    let mut lanes = aether_lanes(cfg, block.clone());
    // One Tor layer, however many times the route says it: a hop repeating the
    // mode, or a mode repeating the hop, is one Tor.
    let mut deduped: Vec<Lane> = Vec::with_capacity(lanes.len());
    for lane in lanes.drain(..) {
        if lane == Lane::Tor && deduped.last() == Some(&Lane::Tor) {
            continue;
        }
        deduped.push(lane);
    }
    let lanes = deduped;
    let route = route_label(&lanes);
    if lanes.iter().filter(|lane| **lane == Lane::Tor).count() > 1 {
        return Err(CoreError::InvalidConfig(format!(
            "this route ({route}) uses Tor twice: a tunnel is either dialled through Tor or \
             carries Tor, never both. Keep one Tor hop"
        )));
    }
    let tor_at = lanes.iter().position(|lane| *lane == Lane::Tor);
    // Tor in front of the route is a mode of the engine that dials the tunnel,
    // so it is only expressible while Aether is that engine. Tor behind the
    // route is a mode of the Aether layer it rides inside, and that layer is as
    // validly a hop -- a WARP hop behind Xray carries Tor just as well.
    if tor_at == Some(0) && !aether_backend {
        return Err(CoreError::InvalidConfig(format!(
            "this route ({route}) dials through Tor in front of {}: Tor carrying a route is a mode \
             of the Aether engine that dials it, so the route has to start from Aether. Select an \
             Aether transport as the protocol, or put Tor behind one of the Aether hops",
            backend_label(cfg.backend)
        )));
    }
    let warps: Vec<(FcaeProtocol, bool)> = lanes
        .iter()
        .filter_map(|lane| match lane {
            Lane::Warp(protocol, h2) => Some((*protocol, *h2)),
            Lane::Tor => None,
        })
        .collect();
    if warps.len() > 1 {
        return Err(CoreError::InvalidConfig(format!(
            "this route ({route}) stacks {} Aether tunnels, and the engine runs both layers as one \
             transport, not as two hops. Choose WARP-in-WARP, WARP-in-MASQUE or \
             MASQUE-in-MASQUE instead of adding a second Aether hop",
            warps.len()
        )));
    }
    let carrier = warps.first().map(|layer| layer.0);
    let mode = match tor_at {
        None => FcaeTorMode::Off,
        Some(_) if carrier.is_none() => FcaeTorMode::Only,
        // Tor in front of the tunnel: the tunnel is dialled through it, so it
        // has to be a tunnel Tor can pass.
        Some(0) => {
            let carrier = carrier.expect("a WARP layer is present");
            if needs_udp_from_its_carrier(carrier) {
                return Err(CoreError::InvalidConfig(format!(
                    "this route ({route}) dials {} through Tor, and Tor carries TCP only: \
                     WireGuard and WARP-in-WARP answer on UDP alone, so neither can be reached \
                     through it. Use MASQUE or WARP-in-MASQUE for the layer Tor carries",
                    lane_label(Lane::Warp(carrier, false))
                )));
            }
            FcaeTorMode::Reverse
        }
        // Tor behind the only tunnel: it rides inside it.
        Some(index) if index == lanes.len() - 1 => FcaeTorMode::Chain,
        Some(_) => {
            return Err(CoreError::InvalidConfig(format!(
                "this route ({route}) puts Tor between two elements, and the engine runs Tor \
                 either in front of its tunnel or inside it. Move Tor to one end"
            )))
        }
    };
    let protocol = carrier.unwrap_or(cfg.protocol);
    // A tunnel Tor carries rides http/2, and so do the two-layer protocols.
    let h2 = warps.iter().any(|layer| layer.1)
        || matches!(protocol, FcaeProtocol::MasqueInMasque | FcaeProtocol::WarpInMasque)
        || mode == FcaeTorMode::Reverse;
    cfg.tor.mode = mode;
    if aether_backend {
        cfg.protocol = protocol;
        cfg.obfuscation.h2_enabled = h2;
        cfg.chain.drain(block).for_each(drop);
        if mode == FcaeTorMode::Chain {
            // The tunnel keeps no listener of its own: Tor's is the session
            // endpoint, and the engine asks the OS for the port it dials itself.
            cfg.socks_port = 0;
            cfg.http_port = 0;
            cfg.internal_socks = true;
            cfg.internal_http = false;
        }
    } else {
        // The engine the route ends in is a hop behind the hosts above it, and
        // the run of Aether hops it replaces starts at `start`. A saved config
        // brings its own transport, so it is the one hop that cannot take one
        // of the session's choosing.
        if cfg.chain[start].core.is_some() {
            return Err(CoreError::InvalidConfig(format!(
                "this route ({route}) folds two Aether layers into one, but the first of them is a \
                 saved config, which carries its own transport. Keep one Aether hop there"
            )));
        }
        let hop = &mut cfg.chain[start];
        hop.protocol = protocol;
        hop.h2_enabled = h2;
        cfg.chain.drain(start + 1..start + len).for_each(drop);
    }
    log::info!(
        "[session] {} Aether layer(s) run as one {}: {}, Tor {}, h2 {}",
        usize::from(aether_backend) + len,
        if aether_backend { "engine" } else { "hop" },
        lane_label(Lane::Warp(protocol, h2)),
        match mode {
            FcaeTorMode::Off => "off",
            FcaeTorMode::Chain => "inside the tunnel",
            FcaeTorMode::Reverse => "carrying the tunnel",
            FcaeTorMode::Only => "alone",
        },
        h2
    );
    Ok(())
}

/// Whether a hop can carry datagrams for the hop behind it.
///
/// Tor -- the protocol, and either Tor mode that serves the user-facing
/// listener -- and Psiphon carry CONNECT streams only. Everything else does:
/// MASQUE over http/2 rides a stream, but its CONNECT-UDP still delivers
/// datagrams, which is why the carrier is the transport rather than the
/// question. Unlike [`aether_carrier_is_udp`], this asks what the hop *gives*
/// its downstream, not what it needs from its upstream.
fn hop_carries_udp(hop: &SessionConfig) -> bool {
    match hop.backend {
        FcaeBackend::Aether => {
            hop.protocol != FcaeProtocol::Tor
                && !matches!(hop.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain)
        }
        FcaeBackend::Psiphon => false,
        // A generated SOCKS5 inbound always offers UDP ASSOCIATE.
        FcaeBackend::Firefox | FcaeBackend::Xray | FcaeBackend::SingBox => true,
    }
}

/// Whether the Aether carrier dials the network over UDP. Tor Only has no
/// carrier and Reverse forces it onto HTTP/2 through Tor.
fn aether_carrier_is_udp(cfg: &SessionConfig) -> bool {
    cfg.backend == FcaeBackend::Aether
        && !matches!(cfg.tor.mode, FcaeTorMode::Only | FcaeTorMode::Reverse)
        && match cfg.protocol {
            FcaeProtocol::WireGuard | FcaeProtocol::Gool => true,
            FcaeProtocol::Masque
            | FcaeProtocol::Auto
            | FcaeProtocol::MasqueInMasque
            | FcaeProtocol::WarpInMasque => !cfg.obfuscation.h2_enabled,
            FcaeProtocol::Tor => false,
        }
}

/// Validate an [`FcaeInitOptions`] header.
///
/// # Safety
/// `raw` must be NULL or point to a valid `FcaeInitOptions`.
pub unsafe fn check_init_options(raw: *const FcaeInitOptions) -> Result<()> {
    let raw = raw.as_ref().ok_or(CoreError::NullArgument("options"))?;
    check_abi(
        raw.struct_size,
        raw.abi_version,
        std::mem::size_of::<FcaeInitOptions>(),
        "FcaeInitOptions",
    )
}

/// Parse the inline routing grammar `[direct]a,b [block]c,d`.
///
/// Entries before any section header default to `direct`, matching the
/// previous behaviour. Returns `(block, direct)`.
pub fn parse_inline_routes(input: Option<&str>) -> (Vec<String>, Vec<String>) {
    let Some(input) = input else {
        return (Vec::new(), Vec::new());
    };

    #[derive(Clone, Copy)]
    enum Section {
        Block,
        Direct,
    }

    let mut block = Vec::new();
    let mut direct = Vec::new();
    let mut section = Section::Direct;

    for token in input.split([',', '\n', '\r']) {
        // A header may be glued to its first entry ("[direct]a.com"), so peel
        // any leading "[...]" off rather than treating the whole token as one
        // entry — that silently filed `a.com` under the *previous* section.
        let mut t = token.trim();
        while t.starts_with('[') {
            let Some(end) = t.find(']') else { break };
            section = match t[..=end].to_ascii_lowercase().as_str() {
                "[block]" => Section::Block,
                // Unknown headers fall back to direct, never to "whatever was
                // active before".
                _ => Section::Direct,
            };
            t = t[end + 1..].trim();
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match section {
            Section::Block => block.push(t.to_string()),
            Section::Direct => direct.push(t.to_string()),
        }
    }
    (block, direct)
}

/// Legacy bridge: project a [`SessionConfig`] onto the `AETHER_*` environment
/// variables that today's `aether-engine` still reads.
///
/// This is the **only** place in the new stack that touches process env, and
/// it always writes every variable it owns (setting or removing), so a stale
/// value from a previous session can never leak into the next one — the old
/// code left several vars set after a stop.
pub mod env_compat {
    use super::*;

    fn set(key: &str, value: Option<impl AsRef<str>>) {
        match value {
            Some(v) => std::env::set_var(key, v.as_ref()),
            None => std::env::remove_var(key),
        }
    }

    fn flag(key: &str, on: bool) {
        set(key, on.then_some("1"));
    }

    pub fn apply(cfg: &SessionConfig) {
        let protocol = match cfg.protocol {
            // Protocol::Tor means tor-only, so no WARP carrier is dialled at
            // all; the engine still wants a nominal protocol string.
            FcaeProtocol::Masque | FcaeProtocol::Auto | FcaeProtocol::Tor => "masque",
            FcaeProtocol::WireGuard => "wg",
            FcaeProtocol::Gool | FcaeProtocol::WarpInMasque => "gool",
            FcaeProtocol::MasqueInMasque => "mim",
        };
        let scan = match cfg.scan_mode {
            FcaeScanMode::Turbo => "turbo",
            FcaeScanMode::Balanced => "balanced",
            FcaeScanMode::Thorough => "thorough",
            FcaeScanMode::Ironclad => "ironclad",
            FcaeScanMode::Stealth => "verified",
        };
        let ip = match cfg.ip_version {
            6 => "v6",
            10 => "both",
            _ => "v4",
        };

        set("AETHER_PROTOCOL", Some(protocol));
        // The engine's bare "gool" is WARP-in-MASQUE; WARP-in-WARP is its
        // classic mode and has to be asked for.
        set("AETHER_GOOL_MODE", (cfg.protocol == FcaeProtocol::Gool).then_some("classic"));
        set(
            "AETHER_GOOL_INNER",
            if cfg.protocol == FcaeProtocol::WarpInMasque { cfg.aether.gool_inner.as_deref() } else { None },
        );
        // Ironclad rides along in AETHER_SCAN, which the engine parses with
        // ScanMode::parse. There is no separate AETHER_VALIDATE.
        set("AETHER_SCAN", Some(scan));
        set("AETHER_IP", Some(ip));
        set("AETHER_CONFIG", Some(&cfg.config_path));
        // Engine verbosity. The FFI's own log callback level is separate and
        // deliberately fixed at info; this only controls how chatty the
        // aether engine itself is.
        set("AETHER_LOG_LEVEL", Some(cfg.engine_log.as_str()));
        flag("AETHER_STATS", true);

        // Listeners.
        //
        // Only mode has no WARP tunnel: the engine's tor-only path binds tor
        // directly to AETHER_SOCKS (tor::run_only), so that variable must
        // carry the Tor SOCKS port from the config (default 127.0.0.1:1821)
        // instead of the session's socks port, which is unused in this mode.
        let host = cfg.socks_bind_host();
        // There is no "disable" for the engine's SOCKS listener: it always
        // binds one, and AETHER_SOCKS_DISABLED was never read. Port 0 asks the
        // OS for an ephemeral port, which is what "no public listener" means
        // here -- the supervisor's TUN bridge still needs somewhere to dial.
        //
        // In Chain mode this listener is Tor's uplink and nothing else: it
        // carries the tunnel and no client ever dials it, so it stays on the
        // loopback even when LAN sharing is on. Sharing it would publish a
        // listener that leaves around Tor instead of through it.
        let socks_host = if cfg.tor.mode == FcaeTorMode::Chain { "127.0.0.1" } else { host };
        if cfg.tor.mode == FcaeTorMode::Only {
            set("AETHER_SOCKS", cfg.tor.bind.clone());
        } else if cfg.socks_port != 0 {
            set("AETHER_SOCKS", Some(format!("{socks_host}:{}", cfg.socks_port)));
        } else {
            set("AETHER_SOCKS", Some(format!("{socks_host}:0")));
        }
        // The engine reads exactly one variable for the HTTP proxy:
        // AETHER_HTTP_PROXY, an ip:port it parses with SocketAddr::parse.
        // An unset or empty value means "no http proxy" -- there is no
        // separate disable flag, and "0.0.0.0:0" is NOT a disable: it parses
        // fine and binds a real listener on an ephemeral port.
        //
        // AETHER_HTTP / AETHER_HTTP_PORT / AETHER_HTTP_DISABLED are names
        // nothing in the engine ever reads, so the http proxy silently never
        // came up, and in tor Only mode the "0.0.0.0:0" branch could bind a
        // stray listener instead of staying off. Write the name the engine
        // actually reads, and clear it to disable.
        if cfg.http_port != 0 && cfg.tor.mode != FcaeTorMode::Only {
            set("AETHER_HTTP_PROXY", Some(format!("{host}:{}", cfg.http_port)));
        } else {
            set("AETHER_HTTP_PROXY", None::<&str>);
        }

        set("AETHER_TOR_HTTP_PROXY", None::<&str>);
        set("AETHER_TOR_HTTP", if cfg.tor.is_enabled() && cfg.tor.http_port != 0 {
            Some(format!("{host}:{}", cfg.tor.http_port))
        } else { None });

        // The engine must NOT raise TUN itself any more -- the supervisor owns
        // the in-process bridge -- so it always runs in proxy mode. That is
        // the engine's only behaviour under run_from_env(), so there is
        // nothing to select; AETHER_MODE was never read.
        //
        // LAN sharing likewise needs no variable: it is expressed by the host
        // part of AETHER_SOCKS / AETHER_HTTP_PROXY above, which
        // socks_bind_host() sets to 0.0.0.0 when sharing is on.
        set(
            "AETHER_QUICK_RECONNECT",
            Some(if cfg.quick_reconnect { "1" } else { "0" }),
        );

        // Obfuscation.
        set("AETHER_NOIZE", Some(&cfg.obfuscation.noize_profile));
        // Always explicit: unset, the engine asks for the MASQUE transport on
        // stdin whenever the host was started from a terminal.
        set("AETHER_MASQUE_HTTP2", Some(if cfg.obfuscation.h2_enabled { "1" } else { "0" }));
        // With ECH on, a failed key lookup stops the session rather than
        // send the server name in the clear; these say where the key is.
        let ech = cfg.obfuscation.ech_enabled;
        set("AETHER_ECH", ech.then_some("auto"));
        set("AETHER_ECH_DNS", cfg.aether.ech_dns.as_deref().filter(|_| ech));
        set("AETHER_ECH_DOMAIN", cfg.aether.ech_domain.as_deref().filter(|_| ech));
        if cfg.obfuscation.fragment_enabled {
            let (lo, hi) = cfg.obfuscation.frag_size;
            let (dlo, dhi) = cfg.obfuscation.frag_delay;
            set("AETHER_MASQUE_H2_FRAGMENT", Some("1"));
            set("AETHER_MASQUE_H2_FRAGMENT_SIZE", Some(format!("{lo}-{hi}")));
            set("AETHER_MASQUE_H2_FRAGMENT_DELAY", Some(format!("{dlo}-{dhi}")));
            set("AETHER_MASQUE_H2_FRAGMENT_SNI", Some(if cfg.aether.fragment_sni { "1" } else { "0" }));
        } else {
            set("AETHER_MASQUE_H2_FRAGMENT", None::<&str>);
            set("AETHER_MASQUE_H2_FRAGMENT_SIZE", None::<&str>);
            set("AETHER_MASQUE_H2_FRAGMENT_DELAY", None::<&str>);
            set("AETHER_MASQUE_H2_FRAGMENT_SNI", None::<&str>);
        }

        // DNS / TLS.
        //
        // AETHER_DNS is a comma/space/semicolon separated list of resolvers,
        // each "ip" or "ip:port"; unparsable entries are skipped and an empty
        // list falls back to the engine's own defaults.
        set("AETHER_DNS", cfg.dns.server.as_deref());
        // The IP-family preference for the *tunnel* is carried by AETHER_IP
        // (set above from the same cfg.dns.ip_prefer). AETHER_DNS_IP was a
        // second name for it that nothing reads.
        set("AETHER_TLS_GROUPS", cfg.dns.tls_groups.as_deref());
        set("AETHER_TLS_CIPHERS", cfg.aether.tls_ciphers.as_deref());
        set("AETHER_TLS13_CIPHERS", cfg.aether.tls13_ciphers.as_deref());
        set("AETHER_TLS_KEY_SHARES", cfg.aether.tls_key_shares.as_deref());
        set("AETHER_TLS_SIGALGS", cfg.aether.tls_sigalgs.as_deref());
        set("AETHER_TLS_CERT_COMPRESSION", cfg.aether.tls_cert_compression.as_deref());
        set("AETHER_TLS_ALPS", cfg.aether.tls_alps.as_deref());
        set("AETHER_TLS_TRUST_ANCHORS", cfg.aether.tls_trust_anchors.as_deref());
        set("AETHER_TLS_SERVER_PADDING", cfg.aether.tls_server_padding.as_deref());
        flag("AETHER_TLS_VERIFY", cfg.aether.tls_verify);
        flag("AETHER_DISABLE_GREASE", cfg.aether.disable_grease);
        flag("AETHER_ENABLE_GREASE_SIGALGS", cfg.aether.enable_grease_sigalgs);
        flag("AETHER_ENABLE_ECH_GREASE", cfg.aether.enable_ech_grease);
        flag("AETHER_DISABLE_OCSP_STAPLING", cfg.aether.disable_ocsp_stapling);
        flag("AETHER_DISABLE_SCT", cfg.aether.disable_sct);
        flag("AETHER_DISABLE_SESSION_TICKET", cfg.aether.disable_session_ticket);
        flag("AETHER_DISABLE_EXTENSION_PERMUTATION", cfg.aether.disable_extension_permutation);
        set("AETHER_API_ADDRESS", cfg.aether.api_address.as_deref());
        set("AETHER_API_HOST", cfg.aether.api_host.as_deref());
        set("AETHER_API_SNI", cfg.aether.api_sni.as_deref());
        set("AETHER_EXIT_LOC", cfg.aether.exit_loc.as_deref());
        set("AETHER_MASQUE_SNI", cfg.dns.sni.as_deref());
        // These v2.3 names are deliberately cleared. Keeping them around
        // risks stale process-global state when an application upgrades the
        // embedded engine between sessions.
        set("AETHER_ENROLL_ADDRESS", None::<&str>);
        set("AETHER_SNI", None::<&str>);
        // NOTE: cfg.dns.use_doh / cfg.dns.doh_url are accepted by the ABI but
        // cannot be honoured: the engine resolves over plain UDP (see
        // socks::resolver_addresses) and has no DoH client. They were
        // projected as AETHER_DNS_MODE / AETHER_DOH_URL, which nothing reads,
        // so enabling DoH silently changed nothing. Left unprojected rather
        // than faking support; wiring a real DoH resolver is a separate job.
        //
        // cfg.udp_buf_kb is in the same position (no AETHER_UDP_BUF_KB reader).

        set(
            "AETHER_PERF_PROFILE",
            Some(match cfg.sys_profile {
                FcaeSysProfile::Low => "low",
                FcaeSysProfile::Medium => "medium",
                FcaeSysProfile::High => "high",
                FcaeSysProfile::Auto => "auto",
            }),
        );

        set("AETHER_PEER", cfg.force_peer.as_deref());
        // Written on every start: the engine repoints this variable at its
        // own Tor/Psiphon carrier in the reverse modes, and that value would
        // otherwise outlive the session.
        set("AETHER_UPSTREAM", cfg.upstream_proxy.as_ref().map(UpstreamProxy::url));
        // cfg.data_dir reaches the engine as the directory part of
        // AETHER_CONFIG, which is what it derives its sibling paths (identity,
        // lastconn, the tor state dir) from. AETHER_DATA_DIR was never read.

        // Routing.
        set("AETHER_ROUTES_FILE", cfg.routing.rules_file.as_deref());
        set(
            "AETHER_ROUTE_BLOCK",
            (!cfg.routing.block.is_empty()).then(|| cfg.routing.block.join("\n")),
        );
        set(
            "AETHER_ROUTE_DIRECT",
            (!cfg.routing.direct.is_empty()).then(|| cfg.routing.direct.join("\n")),
        );

        // Zero Trust.
        set("AETHER_TEAM", cfg.zero_trust.team_name.as_deref());
        set("AETHER_ACCESS_TOKEN", cfg.zero_trust.access_token.as_deref());
        set("AETHER_ACCESS_EMAIL", cfg.zero_trust.access_email.as_deref());

        // Tor
        // Tor is an egress inside the engine, so it is configured the same
        // way the engine configures itself: through AETHER_TOR*. Every
        // variable is written unconditionally (or removed) so a previous
        // session can never leak Tor settings into a non-Tor one.
        set(
            "AETHER_TOR",
            Some(match cfg.tor.mode {
                FcaeTorMode::Off => "off",
                FcaeTorMode::Chain => "chain",
                FcaeTorMode::Reverse => "reverse",
                FcaeTorMode::Only => "only",
            }),
        );

        if cfg.tor.is_enabled() {
            // Pluggable transports are separate executables (lyrebird,
            // snowflake-client) that the engine spawns. Android ships none of
            // them and cannot exec arbitrary binaries from app storage, so a
            // bridge request there can only ever fail -- and it fails late,
            // after a long bootstrap, which reads as "tor is broken". Ask for
            // a direct connection instead and say so once.
            #[cfg(target_os = "android")]
            if !matches!(cfg.tor.bridges, FcaeTorBridges::None) {
                log::warn!(
                    "[tor] bridges need a pluggable-transport binary, which this build cannot \
                     provide on Android; connecting to tor directly instead"
                );
            }

            set("AETHER_TOR_BIND", cfg.tor.bind.as_deref());
            set("AETHER_TOR_DIR", cfg.tor.state_dir.as_deref());
            set("AETHER_TOR_PT", cfg.tor.pt_path.as_deref());
            // The engine reads one variable for both "which family" and
            // "these exact lines": a keyword means built-in, anything else is
            // treated as literal bridge lines.
            set(
                "AETHER_TOR_BRIDGES",
                match cfg.tor.bridges {
                    FcaeTorBridges::None => Some("off".to_string()),
                    // "auto" forces bridges on and lets the engine pick from
                    // whatever pluggable transports it can find. Obfs4 and
                    // Snowflake land here only while the lines box is empty:
                    // as soon as the user pastes their own lines those are
                    // used verbatim -- the engine selects the transport per
                    // bridge line rather than taking a family name. Makes the
                    // bridge-lines field meaningful for every bridge mode,
                    // not just "Custom lines".
                    FcaeTorBridges::Obfs4 | FcaeTorBridges::Snowflake => {
                        match cfg.tor.bridge_lines.as_deref().map(str::trim) {
                            Some(lines) if !lines.is_empty() => Some(lines.to_string()),
                            _ => Some("auto".to_string()),
                        }
                    }
                    FcaeTorBridges::Custom => cfg.tor.bridge_lines.clone(),
                },
            );
        } else {
            set("AETHER_TOR_BIND", None::<&str>);
            set("AETHER_TOR_DIR", None::<&str>);
            set("AETHER_TOR_PT", None::<&str>);
            set("AETHER_TOR_BRIDGES", None::<&str>);
        }

        // Psiphon.
        //
        // FCAE runs its own Psiphon -- tunnel-core's `psi` package compiled into
        // bridges/psiphon, chained like any other hop -- and the engine's, a
        // launcher for an external `psiphon-tunnel-core` that FCAE does not
        // build, is not compiled at all: upstream gates it behind its `psiphon`
        // feature and this workspace never enables it. Until the pinned submodule
        // carries that gate the module is still linked, so the switch it answers
        // to is cleared here as well -- AETHER_PSIPHON* is the only input its
        // mode has, and a host exporting it would turn the session into an
        // install hint instead of a tunnel.
        let engine_psiphon: Vec<String> = std::env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .filter(|key| key.starts_with("AETHER_PSIPHON"))
            .collect();
        for key in engine_psiphon {
            std::env::remove_var(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wintun_guid_text_and_windows_identity_match() {
        let digits = WINTUN_ADAPTER_GUID.replace('-', "");
        assert_eq!(u128::from_str_radix(&digits, 16).unwrap(), WINTUN_ADAPTER_GUID_U128);
    }

    fn raw_test_config() -> FcaeConfig {
        // Initialize nonzero-only enums before creating a typed value.
        let mut raw = std::mem::MaybeUninit::<FcaeConfig>::zeroed();
        unsafe {
            let p = raw.as_mut_ptr();
            std::ptr::addr_of_mut!((*p).ip_version).write(FcaeIpVersion::V4);
            std::ptr::addr_of_mut!((*p).dns.ip_prefer).write(FcaeIpVersion::Dual);
            raw.assume_init()
        }
    }

    #[test]
    fn ironclad_has_time_to_finish_its_aether_scan() {
        let mut cfg = SessionConfig {
            scan_mode: FcaeScanMode::Ironclad,
            ..Default::default()
        };
        assert_eq!(cfg.start_timeout(), Duration::from_secs(240));
        cfg.backend = FcaeBackend::Psiphon;
        assert_eq!(cfg.start_timeout(), Duration::from_secs(150));
    }

    #[test]
    fn all_aether_21_noize_profiles_pass_ffi_validation() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        for profile in ["off", "light", "balanced", "aggressive", "firewall", "gfw"] {
            let name = std::ffi::CString::new(profile).unwrap();
            raw.obfuscation.noize_profile = name.as_ptr();
            assert_eq!(unsafe { parse(&raw) }.unwrap().obfuscation.noize_profile, profile);
        }
        let invalid = std::ffi::CString::new("unknown").unwrap();
        raw.obfuscation.noize_profile = invalid.as_ptr();
        assert!(unsafe { parse(&raw) }.is_err());
    }

    #[test]
    fn tun_engine_selection_is_validated() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        assert_eq!(unsafe { parse(&raw) }.unwrap().tun.engine, TunEngine::Tun2socks);
        raw.tun_engine = 1;
        assert_eq!(unsafe { parse(&raw) }.unwrap().tun.engine, TunEngine::Zeptun);
        raw.tun_engine = 2;
        assert_eq!(unsafe { parse(&raw) }.unwrap().tun.engine, TunEngine::Hev);
        for invalid in [3, u64::MAX] {
            raw.tun_engine = invalid;
            assert!(matches!(unsafe { parse(&raw) }, Err(CoreError::InvalidConfig(_))));
        }
    }

    #[test]
    fn core_profiles_are_parsed_with_the_session_config() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Xray;
        let link = std::ffi::CString::new(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls",
        )
        .unwrap();
        raw.core.profile = link.as_ptr();
        let cfg = unsafe { parse(&raw) }.expect("a core route with a valid profile parses");
        assert_eq!(
            cfg.core.profile.as_ref().and_then(|profile| profile.endpoint()),
            Some(("example.com", 443))
        );

        // A malformed link is a config error on a core route: starting anyway
        // would fail a second later, after the UI already showed "connecting".
        let bad = std::ffi::CString::new("vless://example.com:443").unwrap();
        raw.core.profile = bad.as_ptr();
        assert!(matches!(unsafe { parse(&raw) }, Err(CoreError::InvalidConfig(message)) if message.contains("core.profile")));

        // …and no profile at all is equally fatal there.
        raw.core.profile = std::ptr::null();
        assert!(matches!(unsafe { parse(&raw) }, Err(CoreError::InvalidConfig(_))));
    }

    #[test]
    fn a_saved_config_is_the_route_and_decides_its_own_core() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        // A stale Aether id and no profile at all: the reference is the route.
        raw.backend = FcaeBackend::Aether;
        let library = std::ffi::CString::new(
            r##"[{"name": "Home", "backend": "xray", "config": "socks5://127.0.0.1:1080"}]"##,
        )
        .unwrap();
        let reference = std::ffi::CString::new("#0").unwrap();
        raw.core.library = library.as_ptr();
        raw.core.config_ref = reference.as_ptr();
        let cfg = unsafe { parse(&raw) }.expect("a selected saved config is a whole route");
        assert_eq!(cfg.backend, FcaeBackend::Xray);
        assert_eq!(cfg.protocol, FcaeProtocol::Auto);
        assert_eq!(cfg.core.selection_name(), Some("Home"));
        assert!(cfg.core.profile.is_some());
        assert_eq!(cfg.core.library.len(), 1);

        // A dangling reference is reported, not ignored: the editor wrote it.
        let missing = std::ffi::CString::new("#1").unwrap();
        raw.core.config_ref = missing.as_ptr();
        assert!(matches!(
            unsafe { parse(&raw) },
            Err(CoreError::InvalidConfig(message)) if message.contains("core.config_ref")
        ));
    }

    #[test]
    fn a_chained_saved_config_carries_its_own_profile() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Aether;
        raw.protocol = FcaeProtocol::Masque;
        let library = std::ffi::CString::new(
            r##"[{"name": "Exit", "backend": "sing-box", "config": "socks5://127.0.0.1:1090"}]"##,
        )
        .unwrap();
        raw.core.library = library.as_ptr();
        let reference = std::ffi::CString::new("#0").unwrap();
        let hops = [FcaeChainHop {
            // The entry overrides both of these.
            backend: FcaeBackend::Aether,
            protocol: FcaeProtocol::WireGuard,
            h2_enabled: true,
            config_ref: reference.as_ptr(),
        }];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = 1;
        // No core.profile and no main core.config_ref: every core hop brought
        // its own saved config, so nothing else is required.
        let cfg = unsafe { parse(&raw) }.expect("a chained saved config needs no session profile");
        assert_eq!(cfg.backend, FcaeBackend::Aether);
        assert_eq!(cfg.chain.len(), 1);
        assert_eq!(cfg.chain[0].backend, FcaeBackend::SingBox);
        assert_eq!(cfg.chain[0].protocol, FcaeProtocol::Auto);
        assert_eq!(cfg.chain[0].label(), "Exit");
        assert!(cfg.core.profile.is_none());
        assert_eq!(cfg.core.library.len(), 1);
    }

    #[test]
    fn a_broken_library_is_reported_even_without_a_core_in_the_route() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Aether;
        let broken = std::ffi::CString::new(r#"[{"name": "X", "backend": "xray"}]"#).unwrap();
        raw.core.library = broken.as_ptr();
        assert!(matches!(
            unsafe { parse(&raw) },
            Err(CoreError::InvalidConfig(message)) if message.contains("core.library")
        ));
    }

    #[test]
    fn a_stale_profile_never_blocks_a_session_that_does_not_use_a_core() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Aether;
        let bad = std::ffi::CString::new("vless://nonsense").unwrap();
        raw.core.profile = bad.as_ptr();
        let cfg = unsafe { parse(&raw) }.expect("Aether ignores core.profile");
        assert!(cfg.core.profile.is_none());

        // A core in the chain needs it just as much as the carrier does.
        raw.chain.count = 1;
        raw.chain.exits[0] = FcaeBackend::SingBox;
        assert!(matches!(unsafe { parse(&raw) }, Err(CoreError::InvalidConfig(_))));
    }

    #[test]
    fn proxy_cores_get_their_own_start_budget() {
        for backend in [FcaeBackend::Xray, FcaeBackend::SingBox] {
            let cfg = SessionConfig { backend, ..Default::default() };
            assert_eq!(cfg.start_timeout(), CORE_START_TIMEOUT);
        }
    }

    #[test]
    fn tcp_buffer_sizes_are_plain_bytes_only() {
        for (text, expected) in [("128000", 128000), (" 256000 ", 256000),
                                 ("4096", MIN_TCP_BUFFER), ("4194304", MAX_TCP_BUFFER)] {
            assert_eq!(parse_tcp_buffer_size(text).unwrap(), expected);
        }
        for text in ["", "0", "-128000", "+128000", "NaN", "1e6", "128K", "128kb",
                     "1m", "1mb", "128 m", "128000.0", "4095", "4194305", "999999999999"] {
            assert!(parse_tcp_buffer_size(text).is_err(), "{text}");
        }
    }

    #[test]
    fn tcp_defaults_and_explicit_off_survive_config_parsing() {
        let mut raw: FcaeConfig = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.tun.tcp_sndbuf, 256000);
        assert_eq!(cfg.tun.tcp_rcvbuf, 256000);
        // 0 = default: auto-tuning is now OFF unless explicitly enabled.
        assert!(!cfg.tun.tcp_auto_tuning);
        assert_eq!(cfg.tun.t2s_log_level, T2S_LOG_DEFAULT);
        raw.tun_tcp_sndbuf = 256 * 1024;
        raw.tun_tcp_rcvbuf = 512 * 1024;
        raw.tun_tcp_auto_tuning = 2;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.tun.tcp_sndbuf, 256 * 1024);
        assert_eq!(cfg.tun.tcp_rcvbuf, 512 * 1024);
        assert!(!cfg.tun.tcp_auto_tuning);
        raw.tun_tcp_auto_tuning = 1;
        assert!(unsafe { parse(&raw) }.unwrap().tun.tcp_auto_tuning);
        raw.tun_tcp_auto_tuning = 3;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.tun_tcp_auto_tuning = 0;
        raw.tun2socks_log_level = T2S_LOG_DEBUG as u64;
        assert_eq!(unsafe { parse(&raw) }.unwrap().tun.t2s_log_level, T2S_LOG_DEBUG);
        raw.tun2socks_log_level = 6;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.tun2socks_log_level = 0;
        raw.tun_mtu = 9000;
        assert_eq!(unsafe { parse(&raw) }.unwrap().tun.mtu, 9000);
        raw.tun_mtu = 1279;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.tun_mtu = 9001;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.tun_mtu = 1500;
        raw.tun_tcp_sndbuf = MAX_TCP_BUFFER + 1;
        assert!(unsafe { parse(&raw) }.is_err());
    }

    #[test]
    fn tcp_fields_use_only_the_two_free_reserved_slots() {
        use std::mem::{offset_of, size_of};
        let base = offset_of!(FcaeConfig, _reserved);
        assert_eq!(offset_of!(FcaeConfig, tun_tcp_sndbuf), base + 8);
        assert_eq!(offset_of!(FcaeConfig, tun_tcp_rcvbuf), base + 12);
        assert_eq!(offset_of!(FcaeConfig, tun_tcp_auto_tuning), base + 16);
        assert_eq!(offset_of!(FcaeConfig, tor_http_port), base + 24);
        // Appended after the former reserved slots; ABI v7, v8, v19, v20, v21.
        assert_eq!(offset_of!(FcaeConfig, tun2socks_log_level), base + 32);
        assert_eq!(offset_of!(FcaeConfig, tun_engine), base + 40);
        assert_eq!(offset_of!(FcaeConfig, aether), base + 48);
        let proxy = base + 48 + size_of::<FcaeAether>();
        assert_eq!(offset_of!(FcaeConfig, upstream_proxy), proxy);
        // Appended after the proxy, in this order: ABI v13 (firefox), v14
        // (chain), v24 (core). Each starts where the previous field ends.
        let firefox = proxy + size_of::<*const c_char>();
        assert_eq!(offset_of!(FcaeConfig, firefox), firefox);
        let chain = firefox + size_of::<FcaeFirefox>();
        assert_eq!(offset_of!(FcaeConfig, chain), chain);
        let core = chain + size_of::<FcaeChain>();
        assert_eq!(offset_of!(FcaeConfig, core), core);
        assert_eq!(size_of::<FcaeConfig>(), core + size_of::<FcaeCore>());
    }

    #[test]
    fn inline_routes_default_to_direct() {
        let (block, direct) = parse_inline_routes(Some("a.com,b.com"));
        assert!(block.is_empty());
        assert_eq!(direct, vec!["a.com", "b.com"]);
    }

    #[test]
    fn inline_routes_respect_sections() {
        let (block, direct) =
            parse_inline_routes(Some("[direct]a.com, 10.0.0.0/8 ,[block]ads.example, tracker.net"));
        assert_eq!(direct, vec!["a.com", "10.0.0.0/8"]);
        assert_eq!(block, vec!["ads.example", "tracker.net"]);
    }

    #[test]
    fn inline_routes_skip_comments_and_blanks() {
        let (block, direct) = parse_inline_routes(Some("# note\n\n[block]\nx.com\n"));
        assert_eq!(block, vec!["x.com"]);
        assert!(direct.is_empty());
    }

    // env_compat writes process-global state, so the tor cases share one test
    // rather than racing each other under the parallel test runner.
    #[test]
    fn tor_env_projection_round_trip() {
        let mut cfg = SessionConfig::default();
        cfg.tor = TorConfig {
            mode: FcaeTorMode::Chain,
            bridges: FcaeTorBridges::Obfs4,
            bind: Some("127.0.0.1:9150".into()),
            ..Default::default()
        };
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_TOR").unwrap(), "chain");
        assert_eq!(std::env::var("AETHER_TOR_BRIDGES").unwrap(), "auto");
        assert_eq!(std::env::var("AETHER_TOR_BIND").unwrap(), "127.0.0.1:9150");

        // Custom bridge lines reach the engine verbatim.
        cfg.tor.bridges = FcaeTorBridges::Custom;
        cfg.tor.bridge_lines = Some("obfs4 1.2.3.4:443 CERT=xyz".into());
        env_compat::apply(&cfg);
        assert_eq!(
            std::env::var("AETHER_TOR_BRIDGES").unwrap(),
            "obfs4 1.2.3.4:443 CERT=xyz"
        );

        // In Only mode the engine serves tor ON AETHER_SOCKS
        // (tor::run_only binds to it), so the variable must carry the Tor
        // SOCKS port, not the session's socks port -- otherwise the UI says
        // "1821" while tor actually listens on the session port.
        cfg.tor = TorConfig {
            mode: FcaeTorMode::Only,
            bridges: FcaeTorBridges::None,
            bind: Some("127.0.0.1:9150".into()),
            ..Default::default()
        };
        cfg.socks_port = 9151;
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_SOCKS").unwrap(), "127.0.0.1:9150");

        // The http proxy is projected under the name the engine actually
        // reads. It used to be written as AETHER_HTTP, which nothing reads,
        // so the proxy never bound; and http_port = 0 was projected as
        // "0.0.0.0:0", which parses and binds rather than disabling.
        cfg.http_port = 8087;
        cfg.tor.http_port = 1822;
        env_compat::apply(&cfg);
        assert!(std::env::var("AETHER_HTTP_PROXY").is_err());
        assert_eq!(std::env::var("AETHER_TOR_HTTP").unwrap(), "127.0.0.1:1822");
        cfg.tor.mode = FcaeTorMode::Chain;
        env_compat::apply(&cfg);
        assert_eq!(
            std::env::var("AETHER_HTTP_PROXY").unwrap(),
            "127.0.0.1:8087"
        );
        cfg.http_port = 0;
        env_compat::apply(&cfg);
        assert!(
            std::env::var("AETHER_HTTP_PROXY").is_err(),
            "http_port = 0 must clear the variable, not bind an ephemeral port"
        );

        for (mode, expected) in [
            (FcaeScanMode::Turbo, "turbo"),
            (FcaeScanMode::Balanced, "balanced"),
            (FcaeScanMode::Thorough, "thorough"),
            (FcaeScanMode::Stealth, "verified"),
            (FcaeScanMode::Ironclad, "ironclad"),
        ] {
            cfg.scan_mode = mode;
            env_compat::apply(&cfg);
            assert_eq!(std::env::var("AETHER_SCAN").unwrap(), expected);
        }
        assert_eq!(FcaeScanMode::Stealth as u32, 3);
        assert!(std::env::var("AETHER_TOR_HTTP_PROXY").is_err());

        // Regression: turning tor off must clear every variable, or a later
        // non-tor session inherits them.
        cfg.tor = TorConfig::default();
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_TOR").unwrap(), "off");
        assert!(std::env::var("AETHER_TOR_HTTP").is_err());
        assert!(std::env::var("AETHER_TOR_HTTP_PROXY").is_err());
        assert!(std::env::var("AETHER_TOR_BRIDGES").is_err());
        assert!(std::env::var("AETHER_TOR_BIND").is_err());

        // A carrier address the engine wrote in a reverse mode never
        // survives into the next session.
        std::env::set_var("AETHER_UPSTREAM", "socks5://127.0.0.1:1821");
        env_compat::apply(&cfg);
        assert!(std::env::var("AETHER_UPSTREAM").is_err());
        cfg.upstream_proxy = Some("http://u:p@10.0.0.1:3128".parse().unwrap());
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_UPSTREAM").unwrap(), "http://u:p@10.0.0.1:3128");
        std::env::remove_var("AETHER_UPSTREAM");

        // The engine's own Psiphon is never used -- it would exec an external
        // client FCAE does not ship -- so an inherited switch must not survive
        // into the engine, where it would replace our bridge with that failure.
        for key in [
            "AETHER_PSIPHON",
            "AETHER_PSIPHON_MODE",
            "AETHER_PSIPHON_BIND",
            "AETHER_PSIPHON_CONFIG",
        ] {
            std::env::set_var(key, "chain");
        }
        env_compat::apply(&cfg);
        for key in [
            "AETHER_PSIPHON",
            "AETHER_PSIPHON_MODE",
            "AETHER_PSIPHON_BIND",
            "AETHER_PSIPHON_CONFIG",
        ] {
            assert!(std::env::var(key).is_err(), "{key} must not reach the engine");
        }

        // Tor inside the tunnel means the engine's SOCKS is Tor's uplink and
        // nothing else, so it stays on the loopback even when the session
        // shares its own listeners.
        cfg.tor = TorConfig {
            mode: FcaeTorMode::Chain,
            bridges: FcaeTorBridges::None,
            bind: Some("127.0.0.1:9150".into()),
            ..Default::default()
        };
        cfg.lan_sharing = true;
        cfg.socks_port = 9000;
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_SOCKS").unwrap(), "127.0.0.1:9000");
    }

    #[test]
    fn tun_mode_forces_a_socks_endpoint() {
        let mut cfg = SessionConfig {
            mode: FcaeMode::Tun,
            socks_port: 0,
            ..Default::default()
        };
        assert!(cfg.needs_socks());
        cfg.mode = FcaeMode::Proxy;
        assert!(!cfg.needs_socks());
    }

    #[test]
    fn lan_sharing_picks_the_bind_host() {
        let mut cfg = SessionConfig::default();
        assert_eq!(cfg.socks_bind_host(), "127.0.0.1");
        cfg.lan_sharing = true;
        assert_eq!(cfg.socks_bind_host(), "0.0.0.0");
    }

    #[test]
    fn upstream_proxy_url_is_spliced_into_the_object() {
        let out = inject_upstream_proxy_url(
            r#"{"PropagationChannelId":"X"}"#,
            "socks5://127.0.0.1:1819",
        );
        assert!(out.contains(r#""UpstreamProxyURL":"socks5://127.0.0.1:1819""#), "{out}");
        assert!(out.contains(r#""PropagationChannelId":"X""#), "{out}");
    }

    /// The UI signals "Psiphon through the tunnel" via FcaeConfig._reserved[0];
    /// parse() must read it, or the supervisor never chains Psiphon behind
    /// Aether and the flag silently does nothing (regression test).
    #[test]
    fn independent_tor_http_ports_are_validated() {
        let mut raw: FcaeConfig = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.tor.mode = FcaeTorMode::Chain;
        raw.socks_port = 1819;
        raw.http_port = 1820;
        raw.tor.socks_port = 1821;
        raw.tor_http_port = 1822;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.tor.http_port, 1822);
        assert!(!cfg.psiphon.through_tunnel);
        for port in [1819, 1820, 1821, 65536] {
            raw.tor_http_port = port;
            assert!(unsafe { parse(&raw) }.is_err());
        }
        raw.tor_http_port = 0;
        assert!(unsafe { parse(&raw) }.is_ok());
    }

    #[test]
    fn upstream_proxy_is_parsed_and_tcp_only_kinds_refuse_udp_carriers() {
        let mut raw: FcaeConfig = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.upstream_proxy = c"http://10.0.0.1:3128".as_ptr();
        raw.obfuscation.h2_enabled = true;
        let cfg = unsafe { parse(&raw) }.expect("http proxy with MASQUE over HTTP/2");
        assert_eq!(cfg.upstream_proxy.unwrap().kind, crate::upstream::ProxyKind::Http);

        raw.obfuscation.h2_enabled = false;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.protocol = FcaeProtocol::WireGuard;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.tor.mode = FcaeTorMode::Only;
        assert!(unsafe { parse(&raw) }.is_ok());

        raw.tor.mode = FcaeTorMode::Off;
        raw.upstream_proxy = c"socks5://10.0.0.1:1080".as_ptr();
        assert!(unsafe { parse(&raw) }.is_ok());
        raw.upstream_proxy = c"ftp://10.0.0.1:21".as_ptr();
        assert!(unsafe { parse(&raw) }.is_err());
        raw.upstream_proxy = c"  ".as_ptr();
        assert!(unsafe { parse(&raw) }.unwrap().upstream_proxy.is_none());
    }

    #[test]
    fn dynamic_chain_preserves_every_hop_without_a_slot_limit() {
        let mut raw: FcaeConfig = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        // Aether runs one engine per session, so a long route is built out of
        // the bridges that each own their own process-wide state.
        let hops = [
            FcaeChainHop { backend: FcaeBackend::Firefox, protocol: FcaeProtocol::Auto, h2_enabled: false, config_ref: std::ptr::null() },
            FcaeChainHop { backend: FcaeBackend::Psiphon, protocol: FcaeProtocol::Auto, h2_enabled: false, config_ref: std::ptr::null() },
            FcaeChainHop { backend: FcaeBackend::Firefox, protocol: FcaeProtocol::Auto, h2_enabled: true, config_ref: std::ptr::null() },
            FcaeChainHop { backend: FcaeBackend::Psiphon, protocol: FcaeProtocol::Auto, h2_enabled: true, config_ref: std::ptr::null() },
            FcaeChainHop { backend: FcaeBackend::Firefox, protocol: FcaeProtocol::Auto, h2_enabled: false, config_ref: std::ptr::null() },
        ];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = hops.len() as u32;

        let cfg = unsafe { parse(&raw) }.expect("five explicit hops parse, in order");
        assert_eq!(cfg.chain.len(), hops.len());
        for (actual, expected) in cfg.chain.iter().zip(hops) {
            assert_eq!(actual.backend, expected.backend);
            assert_eq!(actual.protocol, expected.protocol);
            assert_eq!(actual.h2_enabled, expected.h2_enabled);
        }
    }

    #[test]
    fn tor_carrier_still_validates_final_firefox_listener_ports() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.protocol = FcaeProtocol::Tor;
        raw.socks_port = 1819;
        raw.http_port = 1819;
        let hops = [FcaeChainHop {
            backend: FcaeBackend::Firefox, protocol: FcaeProtocol::Auto, h2_enabled: true,
            config_ref: std::ptr::null(),
        }];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = 1;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.http_port = 1820;
        assert!(unsafe { parse(&raw) }.is_ok());
    }

    #[test]
    fn firefox_h1_tun_and_udp_chains_are_not_rejected_by_configuration() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.mode = FcaeMode::Tun;
        raw.backend = FcaeBackend::Firefox;
        raw.firefox.transport = c"h1".as_ptr();
        raw.socks_port = 1819;
        assert_eq!(unsafe { parse(&raw) }.unwrap().firefox.transport, "h1");
        let hops = [FcaeChainHop {
            backend: FcaeBackend::Aether, protocol: FcaeProtocol::WireGuard, h2_enabled: false,
            config_ref: std::ptr::null(),
        }];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = 1;
        assert!(unsafe { parse(&raw) }.is_ok());
    }

    #[test]
    fn a_hop_behind_a_stream_only_carrier_rides_http2_and_an_udp_only_one_is_refused() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        // Psiphon carries CONNECT streams only, exactly as a Tor carrier does.
        raw.backend = FcaeBackend::Psiphon;
        let masque = [FcaeChainHop {
            backend: FcaeBackend::Aether, protocol: FcaeProtocol::Masque, h2_enabled: false,
            config_ref: std::ptr::null(),
        }];
        raw.chain.hops = masque.as_ptr();
        raw.chain.hop_count = 1;
        let cfg = unsafe { parse(&raw) }.expect("a MASQUE hop behind a stream-only carrier runs over http/2");
        assert!(cfg.chain[0].h2_enabled);

        let wireguard = [FcaeChainHop {
            backend: FcaeBackend::Aether, protocol: FcaeProtocol::WireGuard, h2_enabled: false,
            config_ref: std::ptr::null(),
        }];
        raw.chain.hops = wireguard.as_ptr();
        assert!(unsafe { parse(&raw) }.is_err());
    }

    #[test]
    fn tor_in_a_route_becomes_the_engines_own_mode_and_two_tunnels_are_refused() {
        let hop = |protocol: FcaeProtocol, h2: bool| FcaeChainHop {
            backend: FcaeBackend::Aether,
            protocol,
            h2_enabled: h2,
            config_ref: std::ptr::null(),
        };
        let build = |protocol: FcaeProtocol, hops: &[FcaeChainHop]| {
            let mut raw = raw_test_config();
            raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
            raw.abi_version = FCAE_ABI_VERSION;
            raw.protocol = protocol;
            raw.socks_port = 1819;
            raw.http_port = 1820;
            raw.chain.hops = hops.as_ptr();
            raw.chain.hop_count = hops.len() as u32;
            unsafe { parse(&raw) }
        };

        // Tor behind the WARP carrier is the engine's own chain mode, and the
        // carrier keeps no listener of its own that would leave around Tor.
        let cfg = build(FcaeProtocol::Masque, &[hop(FcaeProtocol::Tor, false)])
            .expect("tor behind a carrier is one engine");
        assert!(cfg.chain.is_empty());
        assert_eq!(cfg.tor.mode, FcaeTorMode::Chain);
        assert_eq!((cfg.socks_port, cfg.http_port), (0, 0));
        assert!(cfg.internal_socks);

        // Tor in front of it dials the tunnel through Tor: reverse mode, on the
        // http/2 carrier Tor can pass.
        let cfg = build(FcaeProtocol::Tor, &[hop(FcaeProtocol::Masque, false)])
            .expect("the tunnel dialled through tor is one engine");
        assert!(cfg.chain.is_empty());
        assert_eq!(cfg.tor.mode, FcaeTorMode::Reverse);
        assert_eq!(cfg.protocol, FcaeProtocol::Masque);
        assert!(cfg.obfuscation.h2_enabled);

        // A tunnel Tor carries has to ride TCP, and WireGuard does not.
        let error = build(FcaeProtocol::Tor, &[hop(FcaeProtocol::WireGuard, false)])
            .expect_err("wireguard cannot be reached through tor");
        assert!(error.to_string().contains("UDP alone"), "{error}");
        assert!(error.to_string().contains("MASQUE"), "{error}");

        // Two WARP tunnels are one protocol, not two hops: the route is wrong
        // and names the transports that express what it meant.
        let error = build(FcaeProtocol::WireGuard, &[hop(FcaeProtocol::WireGuard, false)])
            .expect_err("two wireguard layers are refused");
        assert!(error.to_string().contains("WARP-in-WARP"), "{error}");
        let error = build(FcaeProtocol::Masque, &[hop(FcaeProtocol::Masque, false)])
            .expect_err("two masque layers are refused");
        assert!(error.to_string().contains("MASQUE-in-MASQUE"), "{error}");
        let error = build(
            FcaeProtocol::Masque,
            &[hop(FcaeProtocol::Masque, false), hop(FcaeProtocol::Tor, false)],
        )
        .expect_err("two tunnels behind tor are refused");
        assert!(error.to_string().contains("stacks 2 Aether tunnels"), "{error}");

        // The single-engine transports themselves are untouched: they arrive as
        // one Aether layer and are not rewritten.
        let cfg = build(FcaeProtocol::MasqueInMasque, &[])
            .expect("masque in masque is one layer");
        assert_eq!(cfg.protocol, FcaeProtocol::MasqueInMasque);
        assert!(cfg.chain.is_empty());
        assert_eq!(cfg.tor.mode, FcaeTorMode::Off);

        // Shapes the engine has no form for are named, not run.
        let error = build(
            FcaeProtocol::Masque,
            &[hop(FcaeProtocol::Tor, false), hop(FcaeProtocol::Masque, false)],
        )
        .expect_err("tor is never a middle hop");
        assert!(error.to_string().contains("between two elements"), "{error}");
        let error = build(
            FcaeProtocol::Tor,
            &[hop(FcaeProtocol::Masque, false), hop(FcaeProtocol::Tor, false)],
        )
        .expect_err("tor cannot be used twice");
        assert!(error.to_string().contains("uses Tor twice"), "{error}");

        // A route that starts on another backend still gets its Aether layers
        // folded: the WARP hop carries Tor, and the host above it never sees it.
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Xray;
        raw.socks_port = 1819;
        raw.http_port = 1820;
        let hops = [
            hop(FcaeProtocol::WireGuard, false),
            hop(FcaeProtocol::Tor, false),
        ];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = hops.len() as u32;
        let cfg = unsafe { parse(&raw) }.expect("a warp hop behind the host carries tor");
        assert_eq!(cfg.chain.len(), 1);
        assert_eq!(cfg.chain[0].backend, FcaeBackend::Aether);
        assert_eq!(cfg.chain[0].protocol, FcaeProtocol::WireGuard);
        assert_eq!(cfg.tor.mode, FcaeTorMode::Chain);

        // Tor in front of the route needs the Aether engine to dial it, and
        // the host here is Xray.
        let hops = [
            hop(FcaeProtocol::Tor, false),
            hop(FcaeProtocol::Masque, false),
        ];
        raw.chain.hops = hops.as_ptr();
        let error = unsafe { parse(&raw) }.expect_err("tor cannot dial a non-Aether host");
        assert!(error.to_string().contains("in front of Xray"), "{error}");

        // A run of Aether hops behind hosts that are not Aether is still one
        // engine: two saved cores carry it, and Tor rides inside it.
        let core = |backend: FcaeBackend| FcaeChainHop {
            backend,
            protocol: FcaeProtocol::Auto,
            h2_enabled: false,
            config_ref: std::ptr::null(),
        };
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.backend = FcaeBackend::Xray;
        raw.socks_port = 1819;
        raw.http_port = 1820;
        let hops = [
            core(FcaeBackend::SingBox),
            hop(FcaeProtocol::WireGuard, false),
            hop(FcaeProtocol::Tor, false),
        ];
        raw.chain.hops = hops.as_ptr();
        raw.chain.hop_count = hops.len() as u32;
        let cfg = unsafe { parse(&raw) }.expect("two cores carry one Aether engine and its tor");
        assert_eq!(cfg.chain.len(), 2);
        assert_eq!(cfg.chain[0].backend, FcaeBackend::SingBox);
        assert_eq!(cfg.chain[1].backend, FcaeBackend::Aether);
        assert_eq!(cfg.chain[1].protocol, FcaeProtocol::WireGuard);
        assert_eq!(cfg.tor.mode, FcaeTorMode::Chain);

        // The same hosts, with the Aether layers apart: two engines.
        let hops = [
            hop(FcaeProtocol::WireGuard, false),
            core(FcaeBackend::SingBox),
            hop(FcaeProtocol::Tor, false),
        ];
        raw.chain.hops = hops.as_ptr();
        let error = unsafe { parse(&raw) }.expect_err("aether on both sides of a hop");
        assert!(error.to_string().contains("another hop between"), "{error}");
    }

    #[test]
    fn tun_does_not_silently_restore_a_disabled_socks_listener() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.mode = FcaeMode::Tun;
        raw.socks_port = 0;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.socks_port, 0);
    }

    #[test]
    fn tun_http_requires_an_explicit_opt_in() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.mode = FcaeMode::Tun;
        raw.socks_port = 1819;
        raw.http_port = 1820;
        raw.lan_sharing = true;

        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.http_port, 0);
        assert!(!cfg.psiphon.through_tunnel);

        raw._reserved[0] = 1;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.http_port, 0);
        assert!(cfg.psiphon.through_tunnel);

        raw._reserved[0] = FCAE_CONFIG_TUN_HTTP;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.http_port, 1820);
        assert_eq!(cfg.socks_port, 1819);
        assert!(!cfg.psiphon.through_tunnel);
        assert!(cfg.lan_sharing);

        raw._reserved[0] |= 1;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.http_port, 1820);
        assert!(cfg.psiphon.through_tunnel);

        raw.http_port = 1819;
        assert!(unsafe { parse(&raw) }.is_err());
        raw.http_port = 0;
        assert_eq!(unsafe { parse(&raw) }.unwrap().http_port, 0);
    }

    #[test]
    fn tun_http_flag_does_not_change_proxy_mode_or_enable_psiphon() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.http_port = 1820;
        raw._reserved[0] = FCAE_CONFIG_TUN_HTTP;
        let cfg = unsafe { parse(&raw) }.unwrap();
        assert_eq!(cfg.http_port, 1820);
        assert_eq!(cfg.socks_port, 0);
        assert!(!cfg.psiphon.through_tunnel);
    }

    #[test]
    fn private_ranges_stay_off_the_device_unless_asked_for() {
        let mut raw = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;
        raw.mode = FcaeMode::Tun;

        let cfg = unsafe { parse(&raw) }.expect("default config parses");
        assert!(cfg.tun.exclude_private, "private ranges are excluded unless the host opts in");

        raw._reserved[0] = FCAE_CONFIG_TUN_ROUTE_PRIVATE;
        let cfg = unsafe { parse(&raw) }.expect("config parses");
        assert!(!cfg.tun.exclude_private);

        // Three meanings share slot zero; none of them may claim another's bit.
        assert_eq!(FCAE_CONFIG_TUN_ROUTE_PRIVATE & FCAE_CONFIG_TUN_HTTP, 0);
        assert_eq!(FCAE_CONFIG_TUN_ROUTE_PRIVATE & 1, 0);
    }

    #[test]
    fn private_prefixes_are_canonical_and_disjoint() {
        let v4: Vec<(u32, u8)> = PRIVATE_PREFIXES.iter().map(|(network, bits)| (u32::from(*network), *bits)).collect();
        for (index, (network, bits)) in v4.iter().enumerate() {
            assert!((1..=32).contains(bits), "prefix length out of range: {network}/{bits}");
            assert_eq!(network >> (32 - bits) << (32 - bits), *network, "prefix has host bits set");
            for (other, other_bits) in &v4[index + 1..] {
                let shared = *bits.min(other_bits);
                assert_ne!(network >> (32 - shared), other >> (32 - shared), "private prefixes overlap");
            }
        }
        let v6: Vec<(u128, u8)> = PRIVATE_PREFIXES_V6.iter().map(|(network, bits)| (u128::from(*network), *bits)).collect();
        for (index, (network, bits)) in v6.iter().enumerate() {
            assert!((1..=128).contains(bits));
            assert_eq!(network >> (128 - bits) << (128 - bits), *network, "prefix has host bits set");
            for (other, other_bits) in &v6[index + 1..] {
                let shared = *bits.min(other_bits);
                assert_ne!(network >> (128 - shared), other >> (128 - shared), "private prefixes overlap");
            }
        }
        assert_eq!(excluded_prefixes().filter(|(network, _)| network.is_ipv4()).count(), v4.len());
        assert_eq!(excluded_prefixes().filter(|(network, _)| network.is_ipv6()).count(), v6.len());
    }

    #[test]
    fn reserved_slot_zero_sets_through_tunnel() {
        // Reserved slots and pointers are zero; enum fields are valid.
        let mut raw: FcaeConfig = raw_test_config();
        raw.struct_size = std::mem::size_of::<FcaeConfig>() as u32;
        raw.abi_version = FCAE_ABI_VERSION;

        let cfg = unsafe { parse(&raw) }.expect("default config parses");
        assert!(!cfg.psiphon.through_tunnel);

        raw._reserved[0] = 1;
        let cfg = unsafe { parse(&raw) }.expect("config parses");
        assert!(cfg.psiphon.through_tunnel);
    }
}
