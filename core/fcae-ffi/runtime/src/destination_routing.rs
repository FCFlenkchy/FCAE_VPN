//! Destination policy shared by packet and flow platforms. Matching is done
//! before the configured final exit, never by changing the user's exit chain.
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
pub const ENVELOPE: &str = "FCAE-DESTINATIONS/1\n";
/// How many rules a compiled policy opens with before any destination is
/// looked at: the two that keep DNS inside the tunnel.
const DNS_RULES: usize = 2;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub kind: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub ports: String,
    #[serde(default = "both")]
    pub protocol: String,
}
fn both() -> String {
    "both".into()
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub schema: u8,
    pub mode: u8,
    pub rules: Vec<Rule>,
}
fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::InvalidConfig(message.into())
}
fn address(n: u128, v4: bool) -> String {
    if v4 {
        Ipv4Addr::from(n as u32).to_string()
    } else {
        Ipv6Addr::from(n).to_string()
    }
}
fn number(ip: IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(ip) => (u32::from(ip) as u128, true),
        IpAddr::V6(ip) => (u128::from(ip), false),
    }
}
fn prefixes(text: &str) -> Result<Vec<String>> {
    let text = text.trim();
    let (ip, prefix) = text
        .split_once('/')
        .map_or((text, None), |(ip, bits)| (ip, Some(bits)));
    let (number, v4) = number(
        ip.parse()
            .map_err(|_| invalid("invalid IP address or CIDR"))?,
    );
    let bits = if v4 { 32 } else { 128 };
    let prefix = match prefix {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| invalid("invalid CIDR prefix"))?,
        None => bits,
    };
    if prefix > bits {
        return Err(invalid("CIDR prefix exceeds address family width"));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (bits - prefix)
    };
    Ok(vec![format!("{}/{}", address(number & mask, v4), prefix)])
}
fn domain(text: &str) -> Result<(String, bool)> {
    let text = text.trim().trim_end_matches('.').to_ascii_lowercase();
    if text.is_empty()
        || text.len() > 253
        || text.split('.').any(|part| {
            part.is_empty() || part.len() > 63 || part.starts_with('-') || part.ends_with('-')
        })
        || !text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".*-".contains(&c))
    {
        return Err(invalid("domain must be an ASCII hostname or wildcard pattern (use punycode for international names)"));
    }
    if text == "*" {
        return Ok(("(?i)^.+$".into(), true));
    }
    if !text.contains('*') {
        if text.parse::<IpAddr>().is_ok() {
            return Err(invalid("use the IP rule type for numeric addresses"));
        }
        return Ok((text, false));
    }
    let (prefix, rest) = if let Some(rest) = text.strip_prefix("*.") {
        ("(?:[^.]+\\.)+", rest)
    } else {
        ("", text.as_str())
    };
    let mut pattern = format!("(?i)^{prefix}");
    for c in rest.chars() {
        match c {
            '*' => pattern.push_str("[^.]*"),
            '.' => pattern.push_str("\\."),
            _ => pattern.push(c),
        }
    }
    pattern.push('$');
    Ok((pattern, true))
}
fn ports(text: &str) -> Result<(Vec<u16>, Vec<String>)> {
    if text.trim().is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    if text.len() > 512 {
        return Err(invalid("port selection is too long"));
    }
    let mut singles = Vec::new();
    let mut ranges = Vec::new();
    let port = |value: &str| -> Result<u16> {
        value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| invalid("destination ports must be between 1 and 65535"))
    };
    for value in text.split(',') {
        if let Some((a, b)) = value.trim().split_once('-') {
            let (a, b) = (port(a)?, port(b)?);
            if a > b {
                return Err(invalid("port range start exceeds end"));
            }
            ranges.push(format!("{a}:{b}"));
        } else {
            singles.push(port(value)?);
        }
        if singles.len() + ranges.len() > 64 {
            return Err(invalid("too many port selections in one rule"));
        }
    }
    Ok((singles, ranges))
}
impl Rule {
    fn compile(&self, outbound: &str) -> Result<Value> {
        let mut rule = json!({"action":"route","outbound":outbound});
        match self.kind.as_str() {
            "ip" => rule["ip_cidr"] = json!(prefixes(&self.target)?),
            "domain" => {
                let (value, regex) = domain(&self.target)?;
                if regex {
                    rule["domain_regex"] = json!([value]);
                } else {
                    // A name stands for the site: itself and every name under
                    // it. Matched exactly, "example.com" left "www.example.com"
                    // -- where the browser ends up -- to the other side of the
                    // policy. The leading dot keeps the suffix on a label
                    // boundary, so it never takes "notexample.com" with it.
                    rule["domain_suffix"] = json!([format!(".{value}")]);
                    rule["domain"] = json!([value]);
                }
            }
            "port" => {
                if !self.target.trim().is_empty() {
                    return Err(invalid(
                        "port-only rules cannot contain an IP or domain target",
                    ));
                }
            }
            _ => return Err(invalid("unknown destination rule type")),
        }
        let (singles, ranges) = ports(&self.ports)?;
        if self.kind == "port" && singles.is_empty() && ranges.is_empty() {
            return Err(invalid("port-only rules require at least one port"));
        }
        if !singles.is_empty() {
            rule["port"] = json!(singles);
        }
        if !ranges.is_empty() {
            rule["port_range"] = json!(ranges);
        }
        match self.protocol.as_str() {
            "both" => {}
            "tcp" | "udp" => rule["network"] = json!(self.protocol),
            _ => return Err(invalid("protocol must be both, tcp or udp")),
        }
        Ok(rule)
    }
}
impl Policy {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 65536 {
            return Err(invalid("destination policy exceeds 64 KiB"));
        }
        let value: Self = serde_json::from_str(text)
            .map_err(|error| invalid(format!("destination policy: {error}")))?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.mode > 2 || self.rules.len() > 256 {
            return Err(invalid(
                "invalid destination policy schema, mode or rule count",
            ));
        }
        let mut count = 0;
        for rule in &self.rules {
            if rule.target.len() > 1024 {
                return Err(invalid("destination target is too long"));
            }
            let value = rule.compile("fcae-exit")?;
            count += value["ip_cidr"].as_array().map_or(1, Vec::len);
        }
        if count > 4096 {
            return Err(invalid("IP prefixes exceed the policy safety limit"));
        }
        Ok(())
    }
    pub fn active(&self) -> bool {
        self.mode == 1 || (self.mode == 2 && !self.rules.is_empty())
    }
    pub fn config(&self, socks: SocketAddr, listen: u16, udp: bool) -> Result<Value> {
        self.validate()?;
        if !socks.ip().is_loopback() || socks.port() == 0 || listen == 0 {
            return Err(invalid("destination routing requires loopback listeners"));
        }
        let domains = self.rules.iter().any(|rule| rule.kind == "domain");
        // Only DNS captured by this router is handled here. Resolve over the
        // selected exit before any destination policy; never block host DNS.
        let mut rules = vec![json!({"port":53,"action":"hijack-dns"})];
        // DNS over TLS has nowhere else to go. The DNS firewall of every
        // desktop platform drops ports 53 and 853 on any interface but the
        // tunnel, so a policy that sends this flow DIRECT -- a rule that
        // matches the resolver, or the default of Include mode -- sends it
        // into that drop. The app-routing rules keep the port on the exit for
        // the same reason.
        rules.push(json!({"port":853,"action":"route","outbound":"fcae-exit"}));
        debug_assert_eq!(rules.len(), DNS_RULES);
        if domains {
            rules.push(json!({"action":"sniff","sniffer":["tls","http","quic"],"timeout":"500ms"}));
        }
        let selected = if self.mode == 1 {
            "fcae-exit"
        } else {
            "fcae-direct"
        };
        for rule in &self.rules {
            rules.push(rule.compile(selected)?);
        }
        let default = if self.mode == 1 {
            "fcae-direct"
        } else {
            "fcae-exit"
        };
        let mut exit = json!({"type":"socks","tag":"fcae-exit","server":socks.ip().to_string(),"server_port":socks.port(),"version":"5","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1"});
        if !udp {
            exit["network"] = json!("tcp");
        }
        let direct = json!({"type":"direct","tag":"fcae-direct"});
        Ok(
            json!({"log":{"level":"info"},"inbounds":[{"type":"socks","tag":"fcae-destinations","listen":"127.0.0.1","listen_port":listen}],"dns":{"servers":[{"type":if udp {"udp"} else {"tcp"},"tag":"fcae-system","server":"1.1.1.1","detour":"fcae-exit"}],"reverse_mapping":true},"outbounds":[exit,direct],"route":{"default_domain_resolver":"fcae-system","auto_detect_interface":cfg!(any(windows,target_os="linux",target_os="macos")),"rules":rules,"final":default}}),
        )
    }
}
/// Compile before capture routes are installed, retaining the session DNS choice.
pub fn session_config(
    policy: &Policy,
    cfg: &crate::config::SessionConfig,
    socks: SocketAddr,
    listen: u16,
    udp: bool,
) -> Result<Value> {
    let mut value = policy.config(socks, listen, udp)?;
    #[cfg(windows)]
    {
        value["outbounds"][1]["bind_interface"] =
            json!(crate::windows_tun::physical_egress_interface(&cfg.tun.name)?);
    }
    #[cfg(target_os = "macos")]
    {
        let output = crate::tun_dns::run("route", &["-n", "get", "default"])?;
        let name = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:"))
            .map(str::trim)
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 15
                    && *name != "lo0"
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            })
            .ok_or_else(|| invalid("no pre-capture egress interface for destination routing"))?;
        value["outbounds"][1]["bind_interface"] = json!(name);
    }
    let servers = crate::tun_dns::servers(cfg)?;
    if let Some(server) = servers.first() {
        value["dns"]["servers"][0]["server"] = json!(server);
    }
    log::info!(
        "[destination-routing] {}: matches {}, other traffic {}; captured TCP/UDP DNS through tunnel; {} rules",
        if !policy.active() {
            "DNS-only"
        } else if policy.mode == 1 {
            "Include"
        } else {
            "Exclude"
        },
        if policy.mode == 1 { "tunnel" } else { "DIRECT" },
        if policy.mode == 1 { "DIRECT" } else { "tunnel" },
        policy.rules.len()
    );
    Ok(value)
}

pub fn decode(text: Option<String>) -> Result<(Option<Policy>, Option<String>)> {
    let Some(text) = text else {
        return Ok((None, None));
    };
    let Some(document) = text.strip_prefix(ENVELOPE) else {
        return Ok((None, Some(text)));
    };
    if document.len() > 131072 {
        return Err(invalid("routing document is too large"));
    }
    let value: Value = serde_json::from_str(document)
        .map_err(|error| invalid(format!("routing document: {error}")))?;
    let policy = Policy::parse(&value["destinations"].to_string())?;
    let legacy = value["legacy"]
        .as_str()
        .ok_or_else(|| invalid("routing document has no legacy route string"))?
        .to_owned();
    Ok((policy.active().then_some(policy), Some(legacy)))
}

/// Conservative capability gate: the complete policy goes through one path.
/// App policies keep their existing ordered composition via the shared stage.
pub fn uses_native(cfg: &crate::config::SessionConfig) -> bool {
    use crate::config::TunEngine;
    let Some(policy) = cfg.destinations.as_ref() else {
        return false;
    };
    if !policy.active() || cfg.app_routing.is_some() {
        return false;
    }
    #[cfg(target_os = "macos")]
    if cfg.uses_macos_ne() {
        return false;
    }
    match cfg.tun.engine {
        TunEngine::SingBox => cfg!(any(
            windows,
            target_os = "linux",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        )),
        // Native domain sniffing/DNS semantics differ; retain the shared path.
        TunEngine::Mihomo => {
            cfg!(any(windows, target_os = "linux", target_os = "macos"))
                && policy.rules.iter().all(|rule| rule.kind != "domain")
        }
        _ => false,
    }
}

/// Native Mihomo delegates DNS to the shared stage so TCP-only exits can
/// answer UDP DNS too. Native sing-box handles its own DNS action directly.
pub fn uses_shared_stage(cfg: &crate::config::SessionConfig) -> bool {
    !uses_native(cfg) || cfg.tun.engine == crate::config::TunEngine::Mihomo
}

/// Install the same sing-box rule grammar directly in its selected TUN core.
pub fn apply_singbox(
    cfg: &crate::config::SessionConfig,
    value: &mut Value,
    socks: SocketAddr,
    udp: bool,
) -> Result<()> {
    if !uses_native(cfg) {
        return Ok(());
    }
    let Some(policy) = cfg.destinations.as_ref() else {
        return Ok(());
    };
    let compiled = session_config(policy, cfg, socks, 1, udp)?;
    // Keep the TUN platform/process guards, then evaluate destination policy.
    let installed = || value["route"]["rules"].as_array().into_iter().flatten();
    // The device's own range is refused before anything else, as it is
    // without a destination policy. The engine only guards that range itself
    // when it programs the routes, and here it does not: a flow addressed
    // there would otherwise be handed to whichever outbound the policy names.
    let refused: Vec<Value> = installed()
        .filter(|rule| rule["action"] == "reject")
        .cloned()
        .collect();
    let guards: Vec<Value> = installed()
        .filter(|rule| {
            rule.get("process_path").is_some() || rule.get("process_path_regex").is_some()
        })
        .cloned()
        .collect();
    let mut compiled_rules = compiled["route"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    // Captured DNS must precede process guards and destination matches.
    let matches = compiled_rules.split_off(DNS_RULES.min(compiled_rules.len()));
    let mut rules = refused;
    rules.extend(compiled_rules);
    rules.extend(guards);
    rules.extend(matches);
    value["outbounds"] = compiled["outbounds"].clone();
    value["dns"] = compiled["dns"].clone();
    value["route"]["default_domain_resolver"] =
        compiled["route"]["default_domain_resolver"].clone();
    value["route"]["rules"] = json!(rules);
    value["route"]["final"] = compiled["route"]["final"].clone();
    Ok(())
}

/// Mihomo IP/port rules only. OR port selections, AND the other fields;
/// reject VPN-required UDP explicitly before Mihomo can skip a TCP-only exit.
pub fn apply_mihomo(
    cfg: &crate::config::SessionConfig,
    value: &mut Value,
    udp: bool,
) -> Result<()> {
    if !uses_native(cfg) {
        return Ok(());
    }
    let Some(policy) = cfg.destinations.as_ref() else {
        return Ok(());
    };
    policy.validate()?;
    let guards: Vec<String> = value["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|rule| {
            rule.starts_with("PROCESS-PATH-REGEX,") && rule.ends_with(",fcae-tun-direct")
        })
        .map(str::to_owned)
        .collect();
    let mut rules = vec![
        "DST-PORT,53,fcae-tun-exit".to_owned(),
        // The DNS firewall drops this port anywhere but in the tunnel.
        "DST-PORT,853,fcae-tun-exit".to_owned(),
    ];
    rules.extend(guards);
    let mut push = |condition: String, exit: bool| {
        if exit && !udp {
            rules.push(if condition == "MATCH" {
                "NETWORK,udp,REJECT".into()
            } else {
                format!("AND,((NETWORK,udp),({condition})),REJECT")
            });
        }
        rules.push(format!(
            "{condition},{}",
            if exit {
                "fcae-tun-exit"
            } else {
                "fcae-tun-direct"
            }
        ));
    };
    for rule in &policy.rules {
        let mut conditions = Vec::new();
        if rule.kind == "ip" {
            for prefix in prefixes(&rule.target)? {
                conditions.push(format!(
                    "{},{}",
                    if prefix.contains(':') {
                        "IP-CIDR6"
                    } else {
                        "IP-CIDR"
                    },
                    prefix
                ));
            }
        }
        if rule.protocol != "both" {
            conditions.push(format!("NETWORK,{}", rule.protocol));
        }
        let (single, ranges) = ports(&rule.ports)?;
        let mut choices: Vec<String> = single
            .iter()
            .map(|port| format!("DST-PORT,{port}"))
            .collect();
        choices.extend(
            ranges
                .iter()
                .map(|range| format!("DST-PORT,{}", range.replace(':', "-"))),
        );
        if choices.len() == 1 {
            conditions.push(choices.remove(0));
        } else if !choices.is_empty() {
            conditions.push(format!(
                "OR,({})",
                choices
                    .iter()
                    .map(|c| format!("({c})"))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        let condition = if conditions.len() == 1 {
            conditions.remove(0)
        } else {
            format!(
                "AND,({})",
                conditions
                    .iter()
                    .map(|c| format!("({c})"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        push(condition, policy.mode == 1);
    }
    push("MATCH".into(), policy.mode != 1);
    value["rules"] = json!(rules);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SessionConfig, TunEngine};
    use crate::desktop_flow_routing::FlowPolicy;

    fn rule(kind: &str, target: &str, ports: &str) -> Rule {
        Rule {
            kind: kind.into(),
            target: target.into(),
            ports: ports.into(),
            protocol: "both".into(),
        }
    }

    fn policy(mode: u8) -> Policy {
        Policy {
            schema: 1,
            mode,
            rules: vec![
                rule("domain", "example.com", ""),
                rule("ip", "1.1.1.1", ""),
            ],
        }
    }

    fn socks() -> SocketAddr {
        "127.0.0.1:1080".parse().unwrap()
    }

    #[test]
    fn a_domain_rule_covers_the_name_and_every_name_under_it() {
        let compiled = rule("domain", "Example.com.", "").compile("fcae-exit").unwrap();
        assert_eq!(compiled["domain"], json!(["example.com"]));
        // With its dot: "www.example.com" yes, "notexample.com" no.
        assert_eq!(compiled["domain_suffix"], json!([".example.com"]));
        assert!(compiled.get("domain_regex").is_none());
        // A wildcard says what it covers itself and stays as written.
        let wildcard = rule("domain", "*.example.com", "").compile("fcae-exit").unwrap();
        assert!(wildcard["domain_regex"].is_array());
        assert!(wildcard.get("domain").is_none() && wildcard.get("domain_suffix").is_none());
    }

    #[test]
    fn dns_ports_stay_on_the_exit_before_any_destination_is_matched() {
        for mode in [1, 2] {
            let config = policy(mode).config(socks(), 1081, true).unwrap();
            let rules = config["route"]["rules"].as_array().unwrap();
            assert_eq!(rules[0]["port"], 53);
            assert_eq!(rules[0]["action"], "hijack-dns");
            // A resolver the policy would send DIRECT -- 1.1.1.1 is a rule
            // here, and Include mode's default is DIRECT -- keeps DNS over TLS
            // in the tunnel, the only place the DNS firewall lets it live.
            assert_eq!(rules[1]["port"], 853);
            assert_eq!(rules[1]["outbound"], "fcae-exit");
            let first_match = rules
                .iter()
                .position(|rule| rule.get("ip_cidr").is_some() || rule.get("domain").is_some())
                .unwrap();
            assert!(first_match >= DNS_RULES);
        }
    }

    #[test]
    fn a_native_policy_keeps_every_guard_of_the_device() {
        let mut cfg = SessionConfig::default();
        cfg.tun.engine = TunEngine::SingBox;
        for mode in [1, 2] {
            cfg.destinations = Some(policy(mode));
            assert!(uses_native(&cfg));
            let none = FlowPolicy {
                revision: 0,
                provider: "captured_flow".into(),
                mode: 0,
                paths: Default::default(),
            };
            let mut value = none.config(&cfg, socks(), "fcae0", true).unwrap();
            let before = value["route"]["rules"].as_array().unwrap().clone();
            apply_singbox(&cfg, &mut value, socks(), true).unwrap();
            let rules = value["route"]["rules"].as_array().unwrap();

            // The device's own range is still refused first.
            assert_eq!(rules[0], before[0]);
            assert_eq!(rules[0]["action"], "reject");
            assert_eq!(rules[0]["ip_cidr"][0], cfg.tun.ipv4);
            // Then DNS, then the app's own process, then the policy.
            assert_eq!(rules[1]["action"], "hijack-dns");
            assert_eq!(rules[2]["port"], 853);
            assert_eq!(rules[2]["outbound"], "fcae-exit");
            let own = rules
                .iter()
                .position(|rule| {
                    rule.get("process_path").is_some() || rule.get("process_path_regex").is_some()
                })
                .unwrap();
            let first_match = rules
                .iter()
                .position(|rule| rule.get("domain").is_some())
                .unwrap();
            assert_eq!(own, 3);
            assert_eq!(rules[own]["outbound"], "fcae-direct");
            assert!(own < first_match);
            assert_eq!(
                value["route"]["final"],
                if mode == 1 { "fcae-direct" } else { "fcae-exit" }
            );
            assert_eq!(
                rules[first_match]["outbound"],
                if mode == 1 { "fcae-exit" } else { "fcae-direct" }
            );
        }
    }

    #[test]
    fn a_native_mihomo_policy_keeps_both_dns_ports_on_the_exit() {
        let mut cfg = SessionConfig::default();
        cfg.tun.engine = TunEngine::Mihomo;
        cfg.destinations = Some(Policy {
            schema: 1,
            mode: 1,
            rules: vec![rule("ip", "1.1.1.1", ""), rule("port", "", "443")],
        });
        assert!(uses_native(&cfg));
        let mut value = json!({"rules": ["PROCESS-PATH-REGEX,^/opt/fcae$,fcae-tun-direct", "MATCH,fcae-tun-exit"]});
        apply_mihomo(&cfg, &mut value, true).unwrap();
        let rules: Vec<&str> = value["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(rules[0], "DST-PORT,53,fcae-tun-exit");
        assert_eq!(rules[1], "DST-PORT,853,fcae-tun-exit");
        assert_eq!(rules[2], "PROCESS-PATH-REGEX,^/opt/fcae$,fcae-tun-direct");
        assert_eq!(rules[3], "IP-CIDR,1.1.1.1/32,fcae-tun-exit");
        assert_eq!(rules[4], "DST-PORT,443,fcae-tun-exit");
        assert_eq!(*rules.last().unwrap(), "MATCH,fcae-tun-direct");
    }
}
