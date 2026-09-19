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
use std::os::raw::c_char;
use std::time::Duration;

use fcae_abi::*;

use crate::error::{CoreError, Result};

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
    /// Signalled via FcaeConfig._reserved[0] != 0 so the ABI does not shift.
    pub through_tunnel: bool,
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

/// Fully validated session configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Effective SOCKS port after applying the TUN-mode fallback.
    pub socks_port: u16,
    pub http_port: u16,
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

    /// How long to let a backend reach a usable state before giving up.
    pub fn start_timeout(&self) -> Duration {
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

    let mut cfg = SessionConfig {
        backend: raw.backend,
        protocol: raw.protocol,
        mode: raw.mode,
        scan_mode: raw.scan_mode,
        ip_version: raw.ip_version as i32,
        sys_profile: raw.sys_profile,
        lan_sharing: raw.lan_sharing,
        quick_reconnect: raw.quick_reconnect,
        socks_port: raw.socks_port,
        http_port: raw.http_port,
        force_peer: cstr_opt(raw.force_peer),
        config_path: cstr_opt(raw.config_path).unwrap_or_else(|| "aether.toml".into()),
        data_dir: cstr_opt(raw.data_dir),
        udp_buf_kb: None,
        engine_log: raw.engine_log,
        ..SessionConfig::default()
    };

    // ── Ports ───────────────────────────────────────────────────────────
    // TUN mode needs an internal SOCKS endpoint even if the user zeroed the
    // port, so fall back rather than failing.
    if cfg.socks_port == 0 && (cfg.mode == FcaeMode::Tun || raw._reserved[0] != 0
        || matches!(raw.tor.mode, FcaeTorMode::Chain | FcaeTorMode::Reverse)) {
        cfg.socks_port = 1819;
    }
    if cfg.protocol != FcaeProtocol::Tor && raw.tor.mode != FcaeTorMode::Only
        && cfg.http_port != 0 && cfg.http_port == cfg.socks_port {
        return Err(CoreError::InvalidConfig(format!(
            "socks_port and http_port are both {}; they must differ",
            cfg.socks_port
        )));
    }

    // ── UDP buffer ──────────────────────────────────────────────────────
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

    // ── Obfuscation ─────────────────────────────────────────────────────
    let o = &raw.obfuscation;
    let noize = cstr_opt(o.noize_profile).unwrap_or_else(|| "balanced".into());
    if !matches!(noize.as_str(), "off" | "light" | "balanced" | "aggressive") {
        return Err(CoreError::InvalidConfig(format!(
            "noize_profile={noize:?} (expected off|light|balanced|aggressive)"
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

    // ── DNS ─────────────────────────────────────────────────────────────
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

    // ── Routing ─────────────────────────────────────────────────────────
    let (block, direct) = parse_inline_routes(cstr_opt(raw.routing.rules_inline).as_deref());
    cfg.routing = RoutingConfig {
        rules_file: cstr_opt(raw.routing.rules_file),
        direct,
        block,
    };

    // ── Zero Trust / Psiphon ────────────────────────────────────────────
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
        through_tunnel: raw._reserved[0] != 0,
    };

    // ── Tor ─────────────────────────────────────────────────────────────
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
    let psi_socks = cfg.psiphon.socks_port;
    let psi_http = cfg.psiphon.http_port;
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

    // ── TUN ─────────────────────────────────────────────────────────────
    let mtu = match raw.tun_mtu {
        0 => 1500,
        v if (1280..=9000).contains(&v) => v,
        v => {
            return Err(CoreError::InvalidConfig(format!(
                "tun_mtu={v} out of range (1280..=9000, or 0 for 1500)"
            )))
        }
    };
    let psiphon_exit = cfg.backend == FcaeBackend::Psiphon || cfg.psiphon.through_tunnel;
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

    Ok(cfg)
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
            FcaeProtocol::Gool => "gool",
            FcaeProtocol::MasqueInMasque => "mim",
        };
        let scan = match cfg.scan_mode {
            FcaeScanMode::Turbo => "turbo",
            FcaeScanMode::Balanced => "balanced",
            // Ironclad is a *validation* depth, not a scan speed: scan
            // thoroughly and flag validation separately.
            FcaeScanMode::Thorough | FcaeScanMode::Ironclad => "thorough",
            FcaeScanMode::Stealth => "stealth",
        };
        let ip = match cfg.ip_version {
            6 => "v6",
            10 => "both",
            _ => "v4",
        };

        set("AETHER_PROTOCOL", Some(protocol));
        // Ironclad rides along in AETHER_SCAN, which the engine parses with
        // ScanMode::parse. There is no separate AETHER_VALIDATE.
        set("AETHER_SCAN", Some(scan));
        set("AETHER_IP", Some(ip));
        set("AETHER_CONFIG", Some(&cfg.config_path));
        // Engine verbosity. The FFI's own log callback level is separate and
        // deliberately fixed at info; this only controls how chatty the
        // aether engine itself is.
        set("AETHER_LOG_LEVEL", Some(cfg.engine_log.as_str()));

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
        if cfg.tor.mode == FcaeTorMode::Only {
            set("AETHER_SOCKS", cfg.tor.bind.clone());
        } else if cfg.socks_port != 0 {
            set("AETHER_SOCKS", Some(format!("{host}:{}", cfg.socks_port)));
        } else {
            set("AETHER_SOCKS", Some(format!("{host}:0")));
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

        set("AETHER_TOR_HTTP_PROXY", if cfg.tor.is_enabled() && cfg.tor.http_port != 0 {
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
        flag("AETHER_MASQUE_HTTP2", cfg.obfuscation.h2_enabled);
        set("AETHER_ECH", cfg.obfuscation.ech_enabled.then_some("auto"));
        if cfg.obfuscation.fragment_enabled {
            let (lo, hi) = cfg.obfuscation.frag_size;
            let (dlo, dhi) = cfg.obfuscation.frag_delay;
            set("AETHER_MASQUE_H2_FRAGMENT", Some("1"));
            set("AETHER_MASQUE_H2_FRAGMENT_SIZE", Some(format!("{lo}-{hi}")));
            set("AETHER_MASQUE_H2_FRAGMENT_DELAY", Some(format!("{dlo}-{dhi}")));
        } else {
            set("AETHER_MASQUE_H2_FRAGMENT", None::<&str>);
            set("AETHER_MASQUE_H2_FRAGMENT_SIZE", None::<&str>);
            set("AETHER_MASQUE_H2_FRAGMENT_DELAY", None::<&str>);
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
        // Overrides the SNI presented on MASQUE TLS handshakes; empty means
        // the engine's built-in name.
        set("AETHER_SNI", cfg.dns.sni.as_deref());
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

        // ── Tor ─────────────────────────────────────────────────────────
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Appended after the former reserved slots; ABI v7.
        assert_eq!(offset_of!(FcaeConfig, tun2socks_log_level), base + 32);
        assert_eq!(size_of::<FcaeConfig>(), base + 40);
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
        assert_eq!(std::env::var("AETHER_TOR_HTTP_PROXY").unwrap(), "127.0.0.1:1822");
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

        // Regression: turning tor off must clear every variable, or a later
        // non-tor session inherits them.
        cfg.tor = TorConfig::default();
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_TOR").unwrap(), "off");
        assert!(std::env::var("AETHER_TOR_HTTP_PROXY").is_err());
        assert!(std::env::var("AETHER_TOR_BRIDGES").is_err());
        assert!(std::env::var("AETHER_TOR_BIND").is_err());
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
