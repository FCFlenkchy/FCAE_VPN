//! Add the app's transport hop without flattening the native routing graph.
//! Only terminal network dialers receive the hop; existing detours, selectors,
//! routing, DNS and deliberate direct/block routes retain their meaning.
use serde_json::{json, Value};

const TAG: &str = "fcae-upstream";

pub fn attach(config: &mut Value, upstream: Value, xray: bool) -> Result<(), String> {
    // A reference to our not-yet-inserted tag is just as dangerous as a tag
    // collision: it could turn an existing chain into a cycle after insertion.
    fn reserved(value: &Value) -> bool {
        match value {
            Value::String(s) => s == TAG,
            Value::Array(a) => a.iter().any(reserved),
            Value::Object(o) => o.values().any(reserved),
            _ => false,
        }
    }
    if reserved(config) {
        return Err(format!("native config uses reserved chaining tag {TAG:?}; rename it before enabling the upstream proxy"));
    }
    let object = config
        .as_object_mut()
        .ok_or("native config must be an object")?;
    for section in ["outbounds", "endpoints"] {
        let Some(entries) = object.get_mut(section) else {
            continue;
        };
        let entries = entries
            .as_array_mut()
            .ok_or_else(|| format!("native {section} must be an array"))?;
        for entry in entries {
            let kind = entry
                .get(if xray { "protocol" } else { "type" })
                .and_then(Value::as_str)
                .ok_or("native chain entry needs a protocol/type")?
                .to_owned();
            if xray {
                match kind.as_str() {
                    "freedom" | "direct" | "blackhole" | "block" | "dns" | "loopback" => continue,
                    "http" | "socks" | "shadowsocks" | "trojan" | "vless" | "vmess" | "hysteria" | "masque" | "wireguard" => {},
                    _ => return Err(format!("native Xray {kind:?} cannot be safely chained by the app; disable the upstream proxy or use the core's own chain settings")),
                }
                // Legacy proxySettings already owns this outbound's next hop.
                if entry.get("proxySettings").is_some() {
                    continue;
                }
                let stream = entry
                    .as_object_mut()
                    .ok_or("outbound must be an object")?
                    .entry("streamSettings")
                    .or_insert_with(|| json!({}));
                let sockopt = stream
                    .as_object_mut()
                    .ok_or("streamSettings must be an object")?
                    .entry("sockopt")
                    .or_insert_with(|| json!({}));
                let sockopt = sockopt.as_object_mut().ok_or("sockopt must be an object")?;
                match sockopt.get("dialerProxy") {
                    Some(Value::String(s)) if !s.is_empty() => {}
                    None | Some(Value::String(_)) => {
                        sockopt.insert("dialerProxy".into(), json!(TAG));
                    }
                    _ => return Err("sockopt.dialerProxy must be a string".into()),
                }
            } else {
                match kind.as_str() {
                    // A bridge is an OS-local port, not a network dialer: it
                    // has no detour field, just like an intentional direct route.
                    "direct" | "block" | "dns" | "selector" | "urltest" | "bridge" => continue,
                    "socks" | "http" | "shadowsocks" | "vmess" | "trojan" | "wireguard" |
                    "hysteria" | "vless" | "shadowtls" | "tuic" | "hysteria2" | "anytls" |
                    "snell" | "ssh" | "naive" | "tor" | "tailcat" | "tailscale" |
                    "openconnect" | "openvpn-client" | "masque-client" => {},
                    _ => return Err(format!("native sing-box {kind:?} cannot be safely chained by the app; disable the upstream proxy or use the core's own detour settings")),
                }
                match entry.get("detour") {
                    Some(Value::String(s)) if !s.is_empty() => continue,
                    None | Some(Value::String(_)) => {}
                    _ => return Err("detour must be a string".into()),
                }
                // A listening endpoint and a proxied dialer are incompatible.
                if entry
                    .get("listen_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    != 0
                {
                    return Err(format!(
                        "native {kind} with listen_port cannot use the app's upstream proxy"
                    ));
                }
                entry
                    .as_object_mut()
                    .ok_or("outbound/endpoint must be an object")?
                    .insert("detour".into(), json!(TAG));
            }
        }
    }
    let outbounds = object.entry("outbounds").or_insert_with(|| json!([]));
    outbounds
        .as_array_mut()
        .ok_or("native outbounds must be an array")?
        .push(upstream);
    Ok(())
}
