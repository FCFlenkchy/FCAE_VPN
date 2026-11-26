//! What the physical network can carry for the flows that split routing sends
//! around the tunnel.
//!
//! A flow that goes DIRECT is dialled out of the physical interface, and by
//! then the device has already answered the application's TCP handshake. When
//! that dial cannot succeed the application sees a connection that opened and
//! then died, not one that never opened, so nothing falls back to another
//! address. A browser tries IPv6 first as soon as the device offers it: on a
//! network that has no IPv6, every site with an IPv6 address that is routed
//! DIRECT ends in ERR_CONNECTION_RESET, _CLOSED or _ABORTED. The Psiphon exit
//! had this fault for the same reason and is kept IPv4-only in `config`.

use crate::config::SessionConfig;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};

/// Whether `source` is an address the IPv6 internet answers to: global
/// unicast, and not one of the transition tunnels Windows keeps configured
/// whether or not they work (Teredo, 6to4). The device's own address is a
/// unique local one, so a tunnel left up by an earlier session never passes
/// for an uplink.
fn is_global_source(source: Ipv6Addr) -> bool {
    let segments = source.segments();
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] == 0)
        && segments[0] != 0x2002
}

/// Whether the physical network has a route to the IPv6 internet. Nothing is
/// sent: connecting a UDP socket only asks the routing table which address a
/// packet would leave from.
fn uplink_has_ipv6() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    // Not the DNS port: a DNS firewall left behind by an earlier session
    // refuses that one on every interface but its own.
    let internet = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    if socket.connect((internet, 443)).is_err() {
        return false;
    }
    matches!(
        socket.local_addr().map(|address| address.ip()),
        Ok(IpAddr::V6(source)) if is_global_source(source)
    )
}

/// Keep the device IPv4-only when split routing sends flows DIRECT and the
/// physical network has no IPv6 to send them over. The device still captures
/// IPv6, so nothing leaves beside it; applications find no IPv6 address to
/// use and connect over IPv4. Call before the device and its routes exist.
pub fn settle_ipv6(cfg: &mut SessionConfig) {
    if cfg.tun.ipv6.is_none() {
        return;
    }
    // The macOS extension keeps bypassed applications out of the device
    // altogether: none of their flows is dialled from here.
    let flows_go_direct = cfg.destinations.is_some()
        || cfg
            .app_routing
            .as_ref()
            .is_some_and(|policy| policy.provider != "macos_ne");
    if !flows_go_direct || uplink_has_ipv6() {
        return;
    }
    cfg.tun.ipv6 = None;
    log::info!(
        "[tun] split routing on a network without IPv6: the device stays IPv4-only so DIRECT flows are never tried over IPv6"
    );
}

#[cfg(test)]
mod tests {
    use super::is_global_source;

    #[test]
    fn only_addresses_of_the_ipv6_internet_count_as_an_uplink() {
        for address in ["2a01:5ec0::1", "2001:4860:4860::8888", "2600:1f18::1"] {
            assert!(is_global_source(address.parse().unwrap()), "{address}");
        }
        // The device's own address, a link-local one, Teredo and 6to4.
        for address in ["fc00::1", "fd12:3456::1", "fe80::1", "2001:0:53aa::1", "2002:c000:204::1", "::1"] {
            assert!(!is_global_source(address.parse().unwrap()), "{address}");
        }
    }
}
