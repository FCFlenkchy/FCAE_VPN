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
}

/// TUN parameters. Owned by the supervisor, not the backend: whichever
/// backend runs, TUN is raised the same way on top of its SOCKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
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
    if cfg.socks_port == 0 && cfg.mode == FcaeMode::Tun {
        cfg.socks_port = 1819;
    }
    if cfg.http_port != 0 && cfg.http_port == cfg.socks_port {
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
    cfg.tor = TorConfig {
        mode: t.mode,
        bridges: t.bridges,
        bind: cstr_opt(t.bind),
        state_dir: cstr_opt(t.state_dir),
        bridge_lines,
        pt_path: cstr_opt(t.pt_path),
    };

    // ── TUN ─────────────────────────────────────────────────────────────
    let mtu = match raw.tun_mtu {
        0 => 1500,
        v if (576..=9000).contains(&v) => v,
        v => {
            return Err(CoreError::InvalidConfig(format!(
                "tun_mtu={v} out of range (576..=9000, or 0 for 1500)"
            )))
        }
    };
    cfg.tun = TunConfig {
        name: cstr_opt(raw.tun_name).unwrap_or_else(|| "FCAE_VPN".into()),
        mtu,
        fd: if raw.tun_fd >= 0 { Some(raw.tun_fd) } else { None },
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
            FcaeProtocol::Masque | FcaeProtocol::Auto => "masque",
            FcaeProtocol::WireGuard => "wg",
            FcaeProtocol::Gool => "gool",
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
        set("AETHER_SCAN", Some(scan));
        set(
            "AETHER_VALIDATE",
            (cfg.scan_mode == FcaeScanMode::Ironclad).then_some("ironclad"),
        );
        set("AETHER_IP", Some(ip));
        set("AETHER_CONFIG", Some(&cfg.config_path));
        set("AETHER_NONINTERACTIVE", Some("1"));
        // Engine verbosity. The FFI's own log callback level is separate and
        // deliberately fixed at info; this only controls how chatty the
        // aether engine itself is.
        set("AETHER_LOG_LEVEL", Some(cfg.engine_log.as_str()));

        // Listeners.
        let host = cfg.socks_bind_host();
        if cfg.socks_port != 0 {
            set("AETHER_SOCKS", Some(format!("{host}:{}", cfg.socks_port)));
            set("AETHER_SOCKS_DISABLED", None::<&str>);
        } else {
            set("AETHER_SOCKS", Some("0.0.0.0:0"));
            set("AETHER_SOCKS_DISABLED", Some("1"));
        }
        if cfg.http_port != 0 {
            set("AETHER_HTTP", Some(format!("{host}:{}", cfg.http_port)));
            set("AETHER_HTTP_PORT", Some(cfg.http_port.to_string()));
            set("AETHER_HTTP_DISABLED", None::<&str>);
        } else {
            set("AETHER_HTTP", Some("0.0.0.0:0"));
            set("AETHER_HTTP_PORT", Some("0"));
            set("AETHER_HTTP_DISABLED", Some("1"));
        }

        // Mode. The engine must NOT raise TUN itself any more — the
        // supervisor owns the in-process bridge — so it always runs in proxy
        // mode and we expose the user's choice separately.
        set("AETHER_MODE", Some("proxy"));
        flag("AETHER_LAN_SHARING", cfg.lan_sharing);
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
        set("AETHER_DNS", cfg.dns.server.as_deref());
        set("AETHER_DNS_MODE", cfg.dns.use_doh.then_some("doh"));
        set("AETHER_DOH_URL", cfg.dns.doh_url.as_deref());
        set(
            "AETHER_DNS_IP",
            Some(match cfg.dns.ip_prefer {
                6 => "v6",
                10 => "both",
                _ => "v4",
            }),
        );
        set("AETHER_TLS_GROUPS", cfg.dns.tls_groups.as_deref());
        set("AETHER_SNI", cfg.dns.sni.as_deref());
        set("AETHER_UDP_BUF_KB", cfg.udp_buf_kb.map(|v| v.to_string()));

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
        set("AETHER_DATA_DIR", cfg.data_dir.as_deref());

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
                    FcaeTorBridges::Obfs4 | FcaeTorBridges::Snowflake => Some("auto".to_string()),
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

        // Regression: turning tor off must clear every variable, or a later
        // non-tor session inherits them.
        cfg.tor = TorConfig::default();
        env_compat::apply(&cfg);
        assert_eq!(std::env::var("AETHER_TOR").unwrap(), "off");
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
}
