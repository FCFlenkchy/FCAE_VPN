use std::time::Duration;

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::windows_sidecar::Sidecar;
use crate::{generate_config, HevStats};

#[cfg(all(hev_dynamic, wintun_staged))]
static ASSETS: &[(&str, &[u8])] = &[
    ("hev-socks5-tunnel.exe", include_bytes!(env!("FCAE_HEV_EXE"))),
    ("wintun.dll", include_bytes!(env!("FCAE_HEV_WINTUN_DLL"))),
];
#[cfg(not(all(hev_dynamic, wintun_staged)))]
static ASSETS: &[(&str, &[u8])] = &[];

pub fn unavailable_reason() -> Option<&'static str> {
    if cfg!(all(hev_dynamic, wintun_staged)) { None } else { Some("HEV Windows sidecar or Wintun not embedded") }
}
pub fn is_supported() -> bool { unavailable_reason().is_none() }

pub struct HevSocks5TunnelBridge { sidecar: Sidecar }
impl Default for HevSocks5TunnelBridge { fn default() -> Self { Self::new() } }
impl HevSocks5TunnelBridge {
    pub fn new() -> Self {
        Self { sidecar: Sidecar::new("hev", "hev-socks5-tunnel.exe", ASSETS) }
    }
    pub fn set_android_fd(&self, fd: i32) { self.sidecar.set_fd(fd); }
    pub fn clear_android_fd(&self) { self.sidecar.set_fd(-1); }
    pub fn android_fd(&self) -> Option<i32> { self.sidecar.fd() }
    pub fn stats(&self) -> Option<HevStats> { None }
}
impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() { return Err(CoreError::Internal(unavailable_reason().unwrap_or("HEV unavailable").into())); }
        self.sidecar.launch(cfg, endpoints, |cfg, socks, _| {
            let (_, mut yaml) = generate_config(cfg, socks)?;
            yaml.push_str("  log-file: stderr\n");
            Ok(yaml)
        }, &[])
    }
    fn abort(&self) { self.sidecar.abort(); }
    fn stop(&self, timeout: Duration) { self.sidecar.stop(timeout); }
    fn preauthorised_fd(&self) -> Option<i32> { self.android_fd() }
    fn is_running(&self) -> bool { self.sidecar.is_running() }
    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> { self.sidecar.check_health() }
}
