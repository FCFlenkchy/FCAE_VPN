use std::env;

const USAGE: &str = "\
Usage: aether [OPTIONS]

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard        use classic WireGuard
  --gool, --wiw            use WARP-in-WARP (wireguard tunneled in wireguard)

Scan mode:
  --scan <mode>            turbo | balanced | thorough | stealth
  --turbo                  shortcut for --scan turbo
  --balanced               shortcut for --scan balanced
  --thorough               shortcut for --scan thorough
  --stealth                shortcut for --scan stealth

Validation (after scan finds candidates):
  --validate <mode>        handshake (default) | ironclad
  --ironclad               shortcut for --validate ironclad
                           (real tunnel + HTTP check on top candidates, not every IP)

Tunnel health (background monitoring while connected):
  --health-interval <n>    seconds between live probes (default 20)
  --health-max-fails <n>   consecutive failed probes before reconnect (default 2)
  --health-timeout <n>     seconds per health probe (default 5)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)

Obfuscation:
  --noize <profile>        obfuscation profile (off, light/firewall, balanced, gfw/aggressive, ...)

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --sni <hostname>         custom TLS Server Name (SNI) for MASQUE handshakes
                           (default consumer-masque.cloudflareclient.com)
  --ech <auto|base64>      enable Encrypted Client Hello
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan

Config files:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE

Advanced:
  --tls-groups <list>      TLS key share groups, e.g. \"P-256:X25519:P-384\"
  --verbose                detailed debug logs: tunnel stages, validation, reconnects, retries
                           (equivalent to RUST_LOG=info,aether=debug; RUST_LOG overrides this)

  -v, --version            show version and exit
  -h, --help               show this help and exit
";

pub fn parse_and_apply() -> crate::error::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        macro_rules! next_value {
            () => {{
                i += 1;
                args.get(i).ok_or_else(|| {
                    crate::error::AetherError::Other(format!("{arg} requires a value"))
                })?
            }};
        }

        match arg {
            "-v" | "--version" => {
                println!("aether {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }

            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--quick-reconnect" => set("AETHER_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("AETHER_QUICK_RECONNECT", "0"),

            "-4" => set("AETHER_IP", "v4"),
            "-6" => set("AETHER_IP", "v6"),
            "--dual" => set("AETHER_IP", "both"),
            "--ip" => set("AETHER_IP", next_value!()),

            "--peer" => set("AETHER_PEER", next_value!()),
            "--wg-peer" => set("AETHER_WG_PEER", next_value!()),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" => set("AETHER_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("AETHER_PROTOCOL", "gool"),
            "--protocol" => set("AETHER_PROTOCOL", next_value!()),

            "--scan" => set("AETHER_SCAN", next_value!()),
            "--turbo" => set("AETHER_SCAN", "turbo"),
            "--balanced" => set("AETHER_SCAN", "balanced"),
            "--thorough" => set("AETHER_SCAN", "thorough"),
            "--stealth" => set("AETHER_SCAN", "stealth"),
            // Legacy: --ironclad used to be a scan mode; now it's validation.
            "--ironclad" => set("AETHER_VALIDATE", "ironclad"),
            "--validate" => set("AETHER_VALIDATE", next_value!()),

            "--noize" => set("AETHER_NOIZE", next_value!()),

            "--h2" | "--http2" => set("AETHER_MASQUE_HTTP2", "1"),
            "--h2-peer" => set("AETHER_MASQUE_H2_PEER", next_value!()),
            "--sni" => set("AETHER_SNI", next_value!()),
            "--ech" => set("AETHER_ECH", next_value!()),
            "--no-data-check" => {
                set("AETHER_MASQUE_NO_DATA_CHECK", "1");
                set("AETHER_WG_NO_DATA_CHECK", "1");
                set("AETHER_NO_LIVE_CHECK", "1");
            }
            "--validate-secs" => set("AETHER_MASQUE_VALIDATE_SECS", next_value!()),
            "--reconnect-secs" => {
                let v = next_value!();
                set("AETHER_MASQUE_RECONNECT_SECS", v);
                set("AETHER_WG_RECONNECT_SECS", v);
            }
            "--health-interval" => set("AETHER_HEALTH_INTERVAL_SECS", next_value!()),
            "--health-max-fails" => set("AETHER_HEALTH_MAX_FAILS", next_value!()),
            "--health-timeout" => set("AETHER_HEALTH_TIMEOUT_SECS", next_value!()),
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("AETHER_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay" => set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!()),

            "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),

            "--config" => set("AETHER_CONFIG", next_value!()),
            "--wg-config" => set("AETHER_WG_CONFIG", next_value!()),
            "--masque-config" => set("AETHER_MASQUE_CONFIG", next_value!()),

            "--tls-groups" => set("AETHER_TLS_GROUPS", next_value!()),
            "--verbose" => set("AETHER_VERBOSE", "1"),

            other => {
                return Err(crate::error::AetherError::Other(format!(
                    "unknown option '{other}'\n\n{USAGE}"
                )));
            }
        }

        i += 1;
    }

    Ok(())
}

fn set(key: &str, value: &str) {
    std::env::set_var(key, value);
}
