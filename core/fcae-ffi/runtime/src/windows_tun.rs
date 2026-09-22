use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

use crate::config::SessionConfig;
use crate::error::{CoreError, Result};
use crate::windows_dll::Library;

const ADAPTER_GUID: GUID = GUID::from_u128(0x24198f4c_7895_434c_ad65_9e29a92ddc61);

fn checked(code: u32, operation: &str) -> Result<()> {
    if code == 0 { return Ok(()); }
    Err(CoreError::Internal(format!("{operation}: {} (Win32 {code})", std::io::Error::from_raw_os_error(code as i32))))
}

fn wide(text: &str) -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() }

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => SOCKADDR_INET { Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(ip.octets()) } },
            ..Default::default()
        } },
        IpAddr::V6(ip) => SOCKADDR_INET { Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: ip.octets() } },
            ..Default::default()
        } },
    }
}

fn ip_of(address: &SOCKADDR_INET) -> IpAddr {
    unsafe {
        if address.si_family == AF_INET {
            Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()
        } else {
            Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte).into()
        }
    }
}

fn prefix(text: &str, family: u16) -> Result<(IpAddr, u8)> {
    let parsed = text.split_once('/').and_then(|(ip, bits)| Some((ip.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?)));
    match parsed {
        Some((ip, bits)) if (ip.is_ipv4() == (family == AF_INET)) && bits <= if ip.is_ipv4() { 32 } else { 128 }
            && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() => Ok((ip, bits)),
        _ => Err(CoreError::InvalidConfig(format!("invalid TUN address: {text}"))),
    }
}

fn adapter(name: &str) -> Result<(NET_LUID_LH, u32, GUID)> {
    if name.is_empty() || name.contains('\0') {
        return Err(CoreError::InvalidConfig("invalid TUN adapter name".into()));
    }
    let name_wide = wide(name);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut luid = NET_LUID_LH::default();
    loop {
        let code = unsafe { ConvertInterfaceAliasToLuid(name_wide.as_ptr(), &mut luid) };
        if code == 0 { break; }
        if Instant::now() >= deadline {
            checked(code, &format!("waiting for TUN adapter {name}"))?;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut guid = GUID::default();
    let mut index = 0;
    unsafe {
        checked(ConvertInterfaceLuidToGuid(&luid, &mut guid), "query TUN GUID")?;
        checked(ConvertInterfaceLuidToIndex(&luid, &mut index), "query TUN index")?;
    }
    if guid.data1 != ADAPTER_GUID.data1 || guid.data2 != ADAPTER_GUID.data2
        || guid.data3 != ADAPTER_GUID.data3 || guid.data4 != ADAPTER_GUID.data4 {
        return Err(CoreError::Internal(format!("refusing to configure unrelated adapter {name}")));
    }
    Ok((luid, index, guid))
}

fn best_route(peer: IpAddr) -> Result<MIB_IPFORWARD_ROW2> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    checked(unsafe { GetBestRoute2(ptr::null(), 0, ptr::null(), &sockaddr(peer), 0, &mut row, &mut source) }, "resolve outer endpoint route")?;
    Ok(row)
}

struct InterfaceChange {
    before: MIB_IPINTERFACE_ROW,
    applied: MIB_IPINTERFACE_ROW,
}

pub fn validate_backend(cfg: &SessionConfig, _peer: Option<&str>) -> Result<()> {
    if matches!(cfg.tor.mode, fcae_abi::FcaeTorMode::Only | fcae_abi::FcaeTorMode::Reverse) {
        return Err(CoreError::InvalidConfig(
            "Windows TUN does not support standalone Tor; use proxy mode or Tor as carrier".into()
        ));
    }
    Ok(())
}

pub struct TunGuard {
    peer: Option<IpAddr>,
    physical_luid: Option<NET_LUID_LH>,
    physical_next_hop: Option<IpAddr>,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
    interfaces: Vec<InterfaceChange>,
    dns: Option<DnsGuard>,
}

impl std::fmt::Debug for TunGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunGuard").field("owned_routes", &self.routes.len()).field("owned_addresses", &self.addresses.len()).finish()
    }
}

impl TunGuard {
    pub fn configure(cfg: &SessionConfig, peer: Option<&str>) -> Result<Self> {
        validate_backend(cfg, peer)?;
        let parsed_peer = peer.map(|text| text.parse::<IpAddr>().map_err(|_| CoreError::InvalidConfig("invalid outer endpoint IP".into()))).transpose()?;
        if let Some(ip) = parsed_peer {
            if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
                return Err(CoreError::InvalidConfig("outer endpoint is not a remote IP".into()));
            }
        }

        let address4 = prefix(&cfg.tun.ipv4, AF_INET)?;
        let address6 = cfg.tun.ipv6.as_deref().map(|s| prefix(s, AF_INET6)).transpose()?;
        if cfg.tun.mtu < 1280 || cfg.tun.mtu > 65535 {
            return Err(CoreError::InvalidConfig("Windows TUN MTU must be between 1280 and 65535".into()));
        }
        let servers = crate::tun_dns::servers(cfg)?;
        let (luid, index, guid) = adapter(&cfg.tun.name)?;
        let mut guard = Self { peer: parsed_peer, physical_luid: None, physical_next_hop: None, routes: Vec::with_capacity(5), addresses: Vec::with_capacity(2), interfaces: Vec::with_capacity(2), dns: None };
        if let Some(peer) = parsed_peer {
            let physical = best_route(peer)?;
            if unsafe { physical.InterfaceLuid.Value == luid.Value } {
                return Err(CoreError::Internal("outer endpoint already routes through FCAE; disconnect the stale tunnel before reconnecting".into()));
            }
            let mut bypass = MIB_IPFORWARD_ROW2::default();
            unsafe { InitializeIpForwardEntry(&mut bypass); }
            bypass.InterfaceLuid = physical.InterfaceLuid;
            bypass.InterfaceIndex = physical.InterfaceIndex;
            bypass.DestinationPrefix.Prefix = sockaddr(peer);
            bypass.DestinationPrefix.PrefixLength = if peer.is_ipv4() { 32 } else { 128 };
            bypass.NextHop = physical.NextHop;
            bypass.Metric = 0;
            bypass.Protocol = MIB_IPPROTO_NETMGMT;
            guard.add_route(bypass, true)?;
            guard.physical_luid = Some(physical.InterfaceLuid);
            guard.physical_next_hop = Some(ip_of(&physical.NextHop));
        }

        guard.configure_interface(luid, AF_INET, cfg.tun.mtu)?;
        guard.configure_interface(luid, AF_INET6, cfg.tun.mtu)?;
        guard.add_address(luid, address4)?;
        if let Some(address6) = address6 { guard.add_address(luid, address6)?; }

        for ip in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), Ipv4Addr::new(128, 0, 0, 0).into(), IpAddr::V6(Ipv6Addr::UNSPECIFIED), Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into()] {
            let mut row = MIB_IPFORWARD_ROW2::default();
            unsafe { InitializeIpForwardEntry(&mut row); }
            row.InterfaceLuid = luid;
            row.InterfaceIndex = index;
            row.DestinationPrefix.Prefix = sockaddr(ip);
            row.DestinationPrefix.PrefixLength = 1;
            row.NextHop = sockaddr(if ip.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() });
            row.Metric = 0;
            row.Protocol = MIB_IPPROTO_NETMGMT;
            guard.add_route(row, false)?;
        }
        if let Some(peer) = parsed_peer {
            let current = best_route(peer)?;
            if let (Some(expected_luid), Some(expected_hop)) = (guard.physical_luid, guard.physical_next_hop) {
                if unsafe { current.InterfaceLuid.Value != expected_luid.Value } || ip_of(&current.NextHop) != expected_hop {
                    return Err(CoreError::Internal("outer endpoint bypass verification failed".into()));
                }
            }
        }
        guard.dns = Some(DnsGuard::apply_to(guid, &servers)?);
        log::info!("[tun] Windows routing ready: interface {index}, outer endpoint {parsed_peer:?}");
        Ok(guard)
    }

    pub fn check_health(&self) -> Result<()> {
        if let Some(peer) = self.peer {
            let current = best_route(peer)?;
            if let (Some(expected_luid), Some(expected_hop)) = (self.physical_luid, self.physical_next_hop) {
                if unsafe { current.InterfaceLuid.Value != expected_luid.Value } || ip_of(&current.NextHop) != expected_hop {
                    return Err(CoreError::Internal("outer endpoint route changed; reconnect required".into()));
                }
            }
        }
        for owned in &self.routes {
            let mut current = *owned;
            checked(unsafe { GetIpForwardEntry2(&mut current) }, "verify owned TUN route")?;
        }
        Ok(())
    }

    fn add_route(&mut self, row: MIB_IPFORWARD_ROW2, borrow_existing: bool) -> Result<()> {
        let code = unsafe { CreateIpForwardEntry2(&row) };
        if code == ERROR_OBJECT_ALREADY_EXISTS && borrow_existing {
            let mut existing = row;
            return checked(unsafe { GetIpForwardEntry2(&mut existing) }, "verify existing outer endpoint route");
        }
        checked(code, &format!("add route {}/{} on interface {}", ip_of(&row.DestinationPrefix.Prefix), row.DestinationPrefix.PrefixLength, row.InterfaceIndex))?;
        self.routes.push(row);
        Ok(())
    }

    fn configure_interface(&mut self, luid: NET_LUID_LH, family: u16, mtu: u32) -> Result<()> {
        let mut before = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut before); }
        before.InterfaceLuid = luid;
        before.Family = family;
        checked(unsafe { GetIpInterfaceEntry(&mut before) }, "read TUN interface settings")?;
        let mut applied = before;
        applied.NlMtu = mtu;
        applied.UseAutomaticMetric = false;
        applied.Metric = 1;
        applied.DadTransmits = 0;
        if family == AF_INET { applied.SitePrefixLength = 0; }
        checked(unsafe { SetIpInterfaceEntry(&mut applied) }, "configure TUN interface")?;
        self.interfaces.push(InterfaceChange { before, applied });
        Ok(())
    }

    fn add_address(&mut self, luid: NET_LUID_LH, (ip, bits): (IpAddr, u8)) -> Result<()> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row); }
        row.InterfaceLuid = luid;
        row.Address = sockaddr(ip);
        row.OnLinkPrefixLength = bits;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row.DadState = IpDadStatePreferred;
        let code = unsafe { CreateUnicastIpAddressEntry(&row) };
        if code == ERROR_OBJECT_ALREADY_EXISTS {
            checked(unsafe { GetUnicastIpAddressEntry(&mut row) }, "read existing TUN address")?;
            if row.OnLinkPrefixLength != bits {
                return Err(CoreError::Internal(format!("existing TUN address {ip} has a conflicting prefix")));
            }
        } else {
            checked(code, "add TUN address")?;
            self.addresses.push(row);
        }
        Ok(())
    }
}

fn cleanup(code: u32, operation: &str) {
    if code != 0 && code != ERROR_NOT_FOUND {
        if let Err(error) = checked(code, operation) { log::warn!("{error}"); }
    }
}

impl Drop for TunGuard {
    fn drop(&mut self) {
        drop(self.dns.take());
        for row in self.routes.iter().rev() {
            let mut current = *row;
            let code = unsafe { GetIpForwardEntry2(&mut current) };
            if code == 0 && current.Metric == row.Metric && current.Protocol == row.Protocol {
                cleanup(unsafe { DeleteIpForwardEntry2(row) }, "remove owned TUN route");
            } else { cleanup(code, "read owned TUN route"); }
        }
        for row in self.addresses.iter().rev() {
            let mut current = *row;
            let code = unsafe { GetUnicastIpAddressEntry(&mut current) };
            if code == 0 && current.OnLinkPrefixLength == row.OnLinkPrefixLength {
                cleanup(unsafe { DeleteUnicastIpAddressEntry(row) }, "remove owned TUN address");
            } else { cleanup(code, "read owned TUN address"); }
        }
        for change in self.interfaces.iter().rev() {
            let mut current = change.applied;
            let code = unsafe { GetIpInterfaceEntry(&mut current) };
            if code != 0 { cleanup(code, "read TUN interface for restoration"); continue; }
            if current.NlMtu == change.applied.NlMtu { current.NlMtu = change.before.NlMtu; }
            if current.Metric == change.applied.Metric && current.UseAutomaticMetric == change.applied.UseAutomaticMetric {
                current.Metric = change.before.Metric;
                current.UseAutomaticMetric = change.before.UseAutomaticMetric;
            }
            if current.DadTransmits == change.applied.DadTransmits { current.DadTransmits = change.before.DadTransmits; }
            if current.Family == AF_INET { current.SitePrefixLength = 0; }
            cleanup(unsafe { SetIpInterfaceEntry(&mut current) }, "restore TUN interface settings");
        }
    }
}


pub fn restore_wrapper(guard: TunGuard) {
    drop(guard);
}

type SetDns = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32;

struct DnsApi {
    set: SetDns,
    _library: Library,
}

impl DnsApi {
    fn get() -> Result<&'static Self> {
        static API: OnceLock<std::result::Result<DnsApi, String>> = OnceLock::new();
        API.get_or_init(|| {
            (|| -> Result<Self> {
                let library = Library::system("iphlpapi.dll")?;
                unsafe {
                    Ok(Self {
                        set: library.symbol(c"SetInterfaceDnsSettings")?,
                        _library: library,
                    })
                }
            })().map_err(|e| e.to_string())
        }).as_ref().map_err(|e| CoreError::Internal(format!("Windows DNS API unavailable: {e}")))
    }

    fn read(&self, guid: GUID, ipv6: bool) -> Result<Vec<u16>> {
        let guid = format!("{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            guid.data1, guid.data2, guid.data3, guid.data4[0], guid.data4[1], guid.data4[2],
            guid.data4[3], guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);
        let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
        let key = wide(&format!(r"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{guid}"));
        let value = wide("NameServer");
        for _ in 0..4 {
            let mut size = 0u32;
            let code = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, ptr::null_mut(), ptr::null_mut(), &mut size) };
            if code == ERROR_FILE_NOT_FOUND { return Ok(vec![0]); }
            checked(code, "read configured adapter DNS")?;
            if size > 65536 || size % 2 != 0 { return Err(CoreError::Internal("invalid adapter DNS registry value".into())); }
            let mut buffer = vec![0u16; size as usize / 2 + 1];
            size = (buffer.len() * 2) as u32;
            let code = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
            if code == ERROR_MORE_DATA { continue; }
            if code == ERROR_FILE_NOT_FOUND { return Ok(vec![0]); }
            checked(code, "read configured adapter DNS")?;
            let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len() - 1);
            buffer.truncate(len + 1);
            return Ok(buffer);
        }
        Err(CoreError::Internal("adapter DNS changed repeatedly during snapshot".into()))
    }

    fn write(&self, guid: GUID, ipv6: bool, servers: &[u16]) -> Result<()> {
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64 | if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 },
            NameServer: servers.as_ptr().cast_mut(),
            ..Default::default()
        };
        checked(unsafe { (self.set)(guid, &settings) }, "set adapter DNS servers")
    }
}

struct DnsChange { ipv6: bool, before: Vec<u16>, applied: Vec<u16> }

pub struct DnsGuard {
    guid: GUID,
    api: &'static DnsApi,
    changes: Vec<DnsChange>,
}

impl DnsGuard {
    pub fn apply(cfg: &SessionConfig, name: &str) -> Result<Self> {
        let (_, _, guid) = adapter(name)?;
        Self::apply_to(guid, &crate::tun_dns::servers(cfg)?)
    }

    fn apply_to(guid: GUID, servers: &[String]) -> Result<Self> {
        let mut guard = Self { guid, api: DnsApi::get()?, changes: Vec::with_capacity(2) };
        for ipv6 in [false, true] {
            let family_servers: Vec<&str> = servers.iter().filter(|s| s.contains(':') == ipv6).map(String::as_str).collect();
            if family_servers.is_empty() { continue; }
            let before = guard.api.read(guid, ipv6)?;
            let applied = wide(&family_servers.join(","));
            guard.api.write(guid, ipv6, &applied)?;
            guard.changes.push(DnsChange { ipv6, before, applied });
        }
        Ok(guard)
    }
}

fn dns_equivalent(a: &[u16], b: &[u16]) -> bool {
    fn normalized(value: &[u16]) -> Vec<String> {
        String::from_utf16_lossy(value).trim_end_matches('\0').split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty()).map(|s| s.parse::<IpAddr>().map(|ip| ip.to_string()).unwrap_or_else(|_| s.to_owned())).collect()
    }
    normalized(a) == normalized(b)
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        for change in self.changes.iter().rev() {
            match self.api.read(self.guid, change.ipv6) {
                Ok(current) if dns_equivalent(&current, &change.applied) => {
                    if let Err(error) = self.api.write(self.guid, change.ipv6, &change.before) { log::warn!("{error}"); }
                }
                Ok(_) => log::debug!("[tun] DNS changed externally; leaving the new configuration intact"),
                Err(error) => log::warn!("cannot restore adapter DNS: {error}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_preserve_network_byte_order() {
        for text in ["198.18.0.1", "188.114.97.151", "fc00::1", "2606:4700:4700::1111"] {
            let ip: IpAddr = text.parse().unwrap();
            assert_eq!(ip_of(&sockaddr(ip)), ip);
        }
    }

    #[test]
    fn prefixes_validate_family_and_length() {
        assert_eq!(prefix("198.18.0.1/24", AF_INET).unwrap().1, 24);
        assert!(prefix("198.18.0.1/33", AF_INET).is_err());
        assert!(prefix("fc00::1/129", AF_INET6).is_err());
        assert!(prefix("fc00::1/64", AF_INET).is_err());
        assert!(prefix("127.0.0.1/8", AF_INET).is_err());
        assert!(prefix("198.18.0.1", AF_INET).is_err());
    }

    #[test]
    fn dns_comparison_preserves_order_and_automatic_mode() {
        assert!(dns_equivalent(&wide("1.1.1.1 1.0.0.1"), &wide("1.1.1.1,1.0.0.1")));
        assert!(!dns_equivalent(&wide("1.0.0.1,1.1.1.1"), &wide("1.1.1.1,1.0.0.1")));
        assert!(!dns_equivalent(&wide(""), &wide("1.1.1.1")));
        assert!(dns_equivalent(&wide("fc00:0:0:0:0:0:0:1"), &wide("fc00::1")));
    }
}
