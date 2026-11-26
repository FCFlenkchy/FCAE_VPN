//! Shared infrastructure for Xray, sing-box and Mihomo.
//!
//! Core-specific validation and JSON generation live in `crate::xray`,
//! `crate::singbox` and `crate::mihomo`; bridges only bind their native shims.
//! This module owns the portable profile model, common URI syntax, listener
//! planning and the one in-process lifecycle used by all three engines.
mod driver;
pub mod mihomo;
mod planning;
pub(crate) mod profile;
#[path = "sing-box.rs"]
pub mod singbox;
pub mod xray;

pub use driver::{
    forward_log, halt, halt_all, live_instances, live_listeners, retire_all, start, CoreFfi,
    CoreListener, Dialect, LiveInstance, Running, CORE_LOG_TARGET,
};
pub use planning::{is_network, plan_listeners, resolve_peer, valid_domain, Level, Plan, Rules};
pub(crate) use profile::native_dialect_value;
pub use profile::{
    native_dialect, CoreProfile, DialOptions, Obfs, Outbound, PacketEncoding, Protocol, Security,
    ShadowSocksPlugin, Transport, Uot, WireGuardPeer,
};
