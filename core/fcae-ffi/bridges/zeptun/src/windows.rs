use std::time::Duration;

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::{SessionConfig, T2S_LOG_DEBUG, T2S_LOG_INFO, T2S_LOG_WARN};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::windows_sidecar::Sidecar;

pub mod platform { pub fn is_privileged() -> bool { fcae_runtime::windows_tun::is_privileged() } }

#[cfg(all(zeptun_sidecar, wintun_staged))]
static ASSETS: &[(&str, &[u8])] = &[
    ("zeptun.exe", include_bytes!(env!("FCAE_ZEPTUN_EXE"))),
    ("wintun.dll", include_bytes!(env!("FCAE_WINTUN_DLL"))),
];
#[cfg(not(all(zeptun_sidecar, wintun_staged)))]
static ASSETS: &[(&str, &[u8])] = &[];

pub fn is_supported() -> bool { cfg!(all(zeptun_sidecar, wintun_staged)) }
pub fn platform_enabled() -> bool { is_supported() }
pub fn is_privileged() -> bool { platform::is_privileged() }
pub fn version() -> String { "zeptun sidecar".into() }

pub struct ZeptunBridge { sidecar: Sidecar }
impl Default for ZeptunBridge { fn default() -> Self { Self::new() } }
impl ZeptunBridge {
    pub fn new() -> Self { Self { sidecar: Sidecar::new("zeptun", "zeptun.exe", ASSETS) } }
    pub fn set_external_fd(&self, fd: i32) { self.sidecar.set_fd(fd); }
}
fn config(cfg: &SessionConfig, socks: std::net::SocketAddr, udp: bool) -> Result<String> {
    let name = &cfg.tun.name;
    if name.is_empty() || name.len() >= 16 || name.contains('\0') {
        return Err(CoreError::InvalidConfig("Zeptun TUN name must be shorter than 16 bytes".into()));
    }
    let level = match cfg.tun.t2s_log_level { T2S_LOG_DEBUG => "debug", T2S_LOG_INFO => "info", T2S_LOG_WARN => "warn", _ => "err" };
    let mut addresses = vec![cfg.tun.ipv4.clone()];
    if let Some(v6) = &cfg.tun.ipv6 { addresses.push(v6.clone()); }
    Ok(serde_json::json!({
        "preset": "desktop", "log_level": level,
        "tun": { "name": name, "guid": "24198F4C-7895-434C-AD65-9E29A92DDC61", "mtu": cfg.tun.mtu, "configure": false, "address": addresses },
        "stack": { "mode": "userspace" },
        "handler": { "kind": "socks5", "socks5": { "server": socks.to_string(), "udp": udp } },
        "route": { "auto_route": false }
    }).to_string())
}

impl TunBridge for ZeptunBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() { return Err(CoreError::Internal("Zeptun Windows sidecar or Wintun not embedded".into())); }
        let mut network_cfg = cfg.clone();
        if network_cfg.tun.name.is_empty() { network_cfg.tun.name = "FCAE_VPN".into(); }
        self.sidecar.launch(&network_cfg, endpoints, config, &["run", "-c"])
    }

    fn abort(&self) { self.sidecar.abort(); }
    fn stop(&self, timeout: Duration) { self.sidecar.stop(timeout); }
    fn preauthorised_fd(&self) -> Option<i32> { self.sidecar.fd() }
    fn is_running(&self) -> bool { self.sidecar.is_running() }
    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> { self.sidecar.check_health() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sidecar_leaves_windows_networking_to_fcae() {
        let mut cfg = SessionConfig::default();
        cfg.tun.name = "FCAE_VPN".into();
        let text = config(&cfg, "127.0.0.1:1080".parse().unwrap(), false).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["tun"]["configure"], false);
        assert_eq!(doc["route"]["auto_route"], false);
        assert_eq!(doc["handler"]["socks5"]["udp"], false);
        assert_eq!(doc["handler"]["socks5"]["server"], "127.0.0.1:1080");
    }
}
