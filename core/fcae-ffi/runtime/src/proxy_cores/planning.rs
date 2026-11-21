//! Listener allocation, routing rules and platform peer resolution for all cores.
use super::CoreProfile;
use crate::config::{RoutingConfig, SessionConfig};
use crate::error::{CoreError, Result as CoreResult};
use crate::upstream::UpstreamProxy;
use fcae_abi::FcaeEngineLog;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Verbosity handed to a core's own logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn of(level: FcaeEngineLog) -> Self {
        match level {
            FcaeEngineLog::Off => Self::Off,
            FcaeEngineLog::Error => Self::Error,
            FcaeEngineLog::Warn => Self::Warn,
            FcaeEngineLog::Info => Self::Info,
            FcaeEngineLog::Debug => Self::Debug,
            FcaeEngineLog::Trace => Self::Trace,
        }
    }
}

/// Everything a config generator needs from the session.
pub struct Plan<'a> {
    pub profile: &'a CoreProfile,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    pub level: Level,
    pub upstream: Option<&'a UpstreamProxy>,
    pub routing: &'a RoutingConfig,
    /// Where the core must dial, when the platform had to resolve the server
    /// name for it. `None` means the core resolves and dials the name itself.
    pub dial: Option<IpAddr>,
}

/// Free loopback ports, held until every pick is made so two reservations in one
/// start cannot collide.
#[derive(Default)]
struct Reserved(Vec<std::net::TcpListener>);

impl Reserved {
    fn take(&mut self) -> CoreResult<u16> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
            CoreError::StartFailed(format!("cannot allocate an internal port: {error}"))
        })?;
        let port = listener
            .local_addr()
            .map_err(|error| {
                CoreError::StartFailed(format!("cannot inspect an internal port: {error}"))
            })?
            .port();
        self.0.push(listener);
        Ok(port)
    }
}

/// Resolve the listeners the core must open for this session.
///
/// `lan_sharing` widens the public listeners to 0.0.0.0; internal ones always
/// stay on loopback. TUN mode and chained hops force a SOCKS listener even when
/// the user switched the public one off, because both dial the core through it.
pub fn plan_listeners(
    config: &SessionConfig,
) -> CoreResult<(Option<SocketAddr>, Option<SocketAddr>)> {
    let mut reserved = Reserved::default();
    let bind = if config.lan_sharing {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    let mut socks = if config.internal_socks {
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)))
    } else if config.socks_port != 0 {
        Some(SocketAddr::from((bind, config.socks_port)))
    } else {
        None
    };
    let http = if config.internal_http {
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)))
    } else if config.http_port != 0 {
        Some(SocketAddr::from((bind, config.http_port)))
    } else {
        None
    };
    if socks.is_none() && (config.is_tun() || config.require_udp_proxy) {
        socks = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)));
    }
    drop(reserved);
    if socks.is_none() && http.is_none() {
        return Err(CoreError::InvalidConfig(
            "this core needs a SOCKS5 or HTTP listener; enable one for the session".into(),
        ));
    }
    Ok((socks, http))
}

/// Whether a split-routing entry is a network (IP or CIDR) rather than a name.
pub fn is_network(entry: &str) -> bool {
    match entry.split_once('/') {
        Some((address, prefix)) => {
            address.parse::<IpAddr>().is_ok() && prefix.parse::<u8>().is_ok_and(|p| p <= 128)
        }
        None => entry.parse::<IpAddr>().is_ok(),
    }
}

/// A hostname a split-routing rule may name. Wildcards are accepted because the
/// app's rule box accepts them; the `*.` prefix is stripped before use.
pub fn valid_domain(entry: &str) -> bool {
    let entry = entry.trim_start_matches("*.");
    !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && entry.chars().any(|c| c.is_ascii_alphabetic())
}

/// Split-routing entries, validated and classified once for the generator.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rules {
    pub direct_ips: Vec<String>,
    pub direct_domains: Vec<String>,
    pub block_ips: Vec<String>,
    pub block_domains: Vec<String>,
}

impl Rules {
    pub fn build(routing: &RoutingConfig) -> std::result::Result<Self, String> {
        if routing.rules_file.is_some() {
            return Err(
                "a routing rule file is not supported by these cores; use inline direct/block rules"
                    .into(),
            );
        }
        let mut rules = Self::default();
        for entry in &routing.direct {
            rules.push(entry, false)?;
        }
        for entry in &routing.block {
            rules.push(entry, true)?;
        }
        Ok(rules)
    }

    pub fn is_empty(&self) -> bool {
        self.direct_ips.is_empty()
            && self.direct_domains.is_empty()
            && self.block_ips.is_empty()
            && self.block_domains.is_empty()
    }

    fn push(&mut self, entry: &str, block: bool) -> std::result::Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        let (ips, domains) = if block {
            (&mut self.block_ips, &mut self.block_domains)
        } else {
            (&mut self.direct_ips, &mut self.direct_domains)
        };
        if is_network(entry) {
            ips.push(entry.to_string());
        } else if valid_domain(entry) {
            domains.push(entry.trim_start_matches("*.").to_ascii_lowercase());
        } else {
            return Err(format!(
                "routing entry {entry:?} is not an IP address, a CIDR or a hostname"
            ));
        }
        Ok(())
    }
}

/// Addresses the TUN bridge must keep off its own device, so the core's uplink
/// does not re-enter the tunnel it just created.
///
/// Resolved only in TUN mode: proxy mode has no route to loop, and a blocked
/// resolver must not fail a session that would otherwise work.
pub async fn resolve_peer(
    config: &SessionConfig,
    server: &str,
    port: u16,
) -> CoreResult<Option<String>> {
    if let Some(pin) = config.force_peer.as_deref() {
        let ip = parse_pin(pin).ok_or_else(|| {
            CoreError::InvalidConfig(format!("force_peer {pin:?} is not an IP address"))
        })?;
        return Ok(Some(ip.to_string()));
    }
    if !config.is_tun() {
        return Ok(None);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(routable(ip).then(|| ip.to_string()));
    }
    let resolved = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((server, port)))
        .await
        .map_err(|_| {
            CoreError::StartFailed(format!(
                "resolving {server} for the TUN bypass route timed out"
            ))
        })?
        .map_err(|error| CoreError::StartFailed(format!("cannot resolve {server}: {error}")))?;
    let mut peers: Vec<String> = Vec::new();
    for address in resolved {
        let ip = address.ip();
        let text = ip.to_string();
        if routable(ip) && !peers.contains(&text) {
            peers.push(text);
        }
    }
    if peers.is_empty() {
        return Err(CoreError::StartFailed(format!(
            "{server} resolved to no routable address; TUN mode would route the tunnel into itself"
        )));
    }
    Ok(Some(peers.join(",")))
}

fn parse_pin(pin: &str) -> Option<IpAddr> {
    let pin = pin.trim();
    if let Ok(address) = pin.parse::<SocketAddr>() {
        return Some(address.ip());
    }
    pin.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
}

fn routable(ip: IpAddr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

/// The address a core must dial in place of a hostname, or `None` when the
/// profile already names one.
///
/// A core that resolves names with the platform's resolver needs no help, but
/// sing-box's `local` DNS transport reads `/etc/resolv.conf` and nothing else:
/// a host without that file — every Android device — leaves it querying
/// `127.0.0.1:53` and `[::1]:53`, so no dial it makes ever leaves the device.
/// Handing it a resolved address takes DNS out of the dial path entirely, which
/// also keeps the lookup from being answered through the tunnel that is waiting
/// for it.
pub(super) async fn resolve_address(server: &str, port: u16) -> CoreResult<Option<IpAddr>> {
    if server.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let resolved = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((server, port)))
        .await
        .map_err(|_| CoreError::StartFailed(format!("resolving {server} timed out")))?
        .map_err(|error| CoreError::StartFailed(format!("cannot resolve {server}: {error}")))?;
    let address = preferred_address(resolved.map(|address| address.ip()))
        .ok_or_else(|| CoreError::StartFailed(format!("{server} resolved to no usable address")))?;
    Ok(Some(address))
}

/// The address worth dialling first: a routable IPv4 one, then a routable IPv6
/// one, then whatever the resolver returned at all.
fn preferred_address(addresses: impl Iterator<Item = IpAddr>) -> Option<IpAddr> {
    let (mut v4, mut v6, mut any) = (None, None, None);
    for address in addresses {
        any.get_or_insert(address);
        if routable(address) {
            if address.is_ipv4() {
                v4.get_or_insert(address);
            } else {
                v6.get_or_insert(address);
            }
        }
    }
    v4.or(v6).or(any)
}

// ---------------------------------------------------------------------------
// In-process driving
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    /// The address a core is handed is the first one a dial can use: a routable
    /// IPv4 address, then IPv6, and only then whatever else the resolver said.
    #[test]
    fn an_address_is_chosen_in_the_order_a_dial_can_use_it() {
        let loopback = "::1".parse::<IpAddr>().expect("an address");
        let v6 = "2001:db8::1".parse::<IpAddr>().expect("an address");
        let v4 = "203.0.113.7".parse::<IpAddr>().expect("an address");
        assert_eq!(preferred_address([loopback, v6, v4].into_iter()), Some(v4));
        assert_eq!(preferred_address([loopback, v6].into_iter()), Some(v6));
        assert_eq!(preferred_address([loopback].into_iter()), Some(loopback));
        assert_eq!(preferred_address(std::iter::empty()), None);
    }
}
