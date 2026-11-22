//! Destination policy shared by packet and flow platforms. Matching is done
//! before the configured final exit, never by changing the user's exit chain.
use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
pub const ENVELOPE: &str = "FCAE-DESTINATIONS/1\n";
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
                rule[if regex { "domain_regex" } else { "domain" }] = json!([value]);
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
        if self.mode == 1 && self.rules.is_empty() {
            return Err(invalid(
                "include mode requires at least one destination rule",
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
        self.mode != 0 && !(self.mode == 2 && self.rules.is_empty())
    }
    pub fn config(&self, socks: SocketAddr, listen: u16, udp: bool) -> Result<Value> {
        self.validate()?;
        if !socks.ip().is_loopback() || socks.port() == 0 || listen == 0 {
            return Err(invalid("destination routing requires loopback listeners"));
        }
        let mut rules = vec![json!({"port":[53,853],"action":"route","outbound":"fcae-exit"})];
        let domains = self.rules.iter().any(|rule| rule.kind == "domain");
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
            if domains {
                rules
                    .push(json!({"domain_regex":[".+"],"action":"route","outbound":"fcae-direct"}));
                "fcae-exit"
            } else {
                "fcae-direct"
            }
        } else {
            "fcae-exit"
        };
        let mut exit = json!({"type":"socks","tag":"fcae-exit","server":socks.ip().to_string(),"server_port":socks.port(),"version":"5","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1"});
        if !udp {
            exit["network"] = json!("tcp");
        }
        let direct = json!({"type":"direct","tag":"fcae-direct"});
        #[cfg(target_os = "macos")]
        let direct = {
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
                .ok_or_else(|| {
                    invalid("no pre-capture egress interface for destination routing")
                })?;
            let mut direct = direct;
            direct["bind_interface"] = json!(name);
            direct
        };
        Ok(
            json!({"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"fcae-destinations","listen":"127.0.0.1","listen_port":listen}],"dns":{"servers":[{"type":"local","tag":"fcae-system"}]},"outbounds":[exit,direct],"route":{"default_domain_resolver":"fcae-system","auto_detect_interface":cfg!(any(windows,target_os="linux",target_os="macos")),"rules":rules,"final":default}}),
        )
    }
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
