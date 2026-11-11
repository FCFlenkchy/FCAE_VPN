//! TUN bridge over hev-socks5-tunnel. Windows runs the upstream executable
//! as a supervised sidecar; other platforms use the in-process C ABI.

#[cfg(not(windows))]
mod engine;
#[cfg(windows)]
#[path = "windows.rs"]
mod engine;

/// Platform glue: the privilege probe compiles on every target (the FFI
/// layer's `fcae_is_privileged()` reaches it as
/// `fcae_bridge_hev_socks5_tunnel::platform::is_privileged`), the Wintun
/// DLL staging is Windows-only and cfg-gated inside the module.
pub mod platform;

pub use engine::{HevSocks5TunnelBridge, unavailable_reason};

/// The wintun adapter GUID every FCAE TUN engine pins.
///
/// Wintun identifies an adapter by name *and* GUID: the GUID decides the NLA
/// entry and the NetCfgInstanceId, so a stable one keeps the firewall profile,
/// DNS assignment and registered-network settings across engines, sessions and
/// reinstalls, and makes repeated creation idempotent instead of accruing
/// `FCAE_VPN 2`, `FCAE_VPN 3` duplicates. `fcae-bridge-tun2socks` passes it in
/// the device URL, `fcae-bridge-zeptun` through `zeptun_set_adapter_guid`, and
/// the hev engine (every platform) receives it as `tunnel.guid` in the config
/// this bridge renders.
pub const WINTUN_ADAPTER_GUID: &str = "24198F4C-7895-434C-AD65-9E29A92DDC61";

/// True when the engine is linked or its Windows sidecar is embedded.
pub fn is_supported() -> bool {
    engine::is_supported()
}

/// Re-exported so the FFI layer's `fcae_is_privileged()` covers hev-only
/// builds too.
pub fn is_privileged() -> bool {
    platform::is_privileged()
}

/// Traffic statistics from the engine.
///
/// The Windows sidecar does not expose counters through its CLI.
#[derive(Default, Clone, Copy, Debug)]
pub struct HevStats {
    pub tx_packets: usize,
    pub tx_bytes: usize,
    pub rx_packets: usize,
    pub rx_bytes: usize,
}

/// `tunnel.ipv4`/`tunnel.ipv6` take bare addresses: the engine derives the
/// netmask itself (`inet_pton` plus a fixed /32 and /128), so a CIDR from the
/// session config is reduced to its address.
#[cfg(target_os = "android")]
pub(crate) fn bare_address(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

/// Map the UI's TUN log knob onto the engine's levels.
///
/// `FcaeT2sLog`: 0 = default, 1 = silent, 2 = error, 3 = warn, 4 = info,
/// 5 = debug. The engine takes exactly `debug`, `info`, `warn`, `error` (and
/// falls back to warn), so a quiet setting still keeps failures — the log is
/// what a failed startup is diagnosed from.
pub(crate) fn log_level(t2s_log_level: u8) -> &'static str {
    match t2s_log_level {
        5 => "debug",
        4 => "info",
        3 => "warn",
        _ => "error",
    }
}

/// Runs the engine's `main`, absorbing a stale stop request.
///
/// `hev_socks5_tunnel_quit` latches `SYNC_STOP` whenever no run is live, and
/// the next run consumes it by returning 0 before it starts. A quit racing
/// the previous engine's own exit therefore makes this run end at once; a
/// clean exit nobody in this generation asked for is exactly that latch.
pub(crate) fn run_engine(closing: &std::sync::atomic::AtomicBool, mut main: impl FnMut() -> std::ffi::c_int) -> std::ffi::c_int {
    let code = main();
    if code != 0 || closing.load(std::sync::atomic::Ordering::SeqCst) {
        return code;
    }
    log::debug!("[hev] discarding a stop latched by the previous engine");
    main()
}

pub(crate) fn generate_config(cfg: &fcae_runtime::config::SessionConfig, socks: std::net::SocketAddr) -> fcae_runtime::error::Result<(std::net::SocketAddr, String)> {
    let mut yaml = String::with_capacity(256);
    yaml.push_str("tunnel:\n");
    yaml.push_str(&format!("  name: '{}'\n", cfg.tun.name.replace('\'', "''")));
    #[cfg(windows)]
    yaml.push_str(&format!("  guid: {}\n", crate::WINTUN_ADAPTER_GUID));
    yaml.push_str(&format!("  mtu: {}\n", cfg.tun.mtu));
    yaml.push_str("  multi-queue: false\n");
    #[cfg(target_os = "android")]
    {
        yaml.push_str(&format!("  ipv4: {}\n", bare_address(&cfg.tun.ipv4)));
        if let Some(ipv6) = &cfg.tun.ipv6 {
            yaml.push_str(&format!("  ipv6: '{}'\n", bare_address(ipv6)));
        }
    }
    yaml.push_str("  icmp: 'off'\n\n");
    yaml.push_str("socks5:\n");
    yaml.push_str(&format!("  port: {}\n", socks.port()));
    yaml.push_str(&format!("  address: {}\n", socks.ip()));
    yaml.push_str("  udp: 'udp'\n");
    yaml.push_str("\nmisc:\n");
    yaml.push_str(&format!("  log-level: '{}'\n", log_level(cfg.tun.t2s_log_level)));
    Ok((socks, yaml))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "android"))]
    fn desktop_host_guard_owns_address_configuration() {
        let config = fcae_runtime::config::SessionConfig::default();
        let (_, yaml) = generate_config(&config, "127.0.0.1:1080".parse().unwrap()).unwrap();
        assert!(!yaml.contains("  ipv4:"));
        assert!(!yaml.contains("  ipv6:"));
        assert!(yaml.contains("  mtu:"));
    }

    /// Only levels the engine understands may be emitted: an unknown string
    /// silently becomes `warn`, which would hide the errors a failed start is
    /// diagnosed from.
    #[test]
    fn the_engine_log_level_follows_the_ui_knob() {
        for level in [0u8, 1, 2, 3, 4, 5] {
            let emitted = log_level(level);
            assert!(
                ["debug", "info", "warn", "error"].contains(&emitted),
                "level {level} became {emitted}"
            );
        }
        assert_eq!(log_level(5), "debug");
        assert_eq!(log_level(4), "info");
        assert_eq!(log_level(3), "warn");
        assert_eq!(log_level(2), "error");
        assert_eq!(log_level(0), "error");
    }
}
