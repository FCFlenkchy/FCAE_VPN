pub const API_URL: &str = "https://api.cloudflareclient.com";
pub const API_VERSION: &str = "v0a4471";

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

/// The SNI to present on MASQUE TLS handshakes.
///
/// Defaults to [`CONNECT_SNI`], overridden by `AETHER_SNI`. The name is a
/// censorship-relevant knob: it is the one field of the handshake a DPI box
/// reads in cleartext (when ECH is off), so a network that blocklists the
/// stock name can be worked around by presenting another. The endpoints are
/// verified by certificate pinning rather than hostname matching, so a
/// substituted name does not weaken the connection -- see the
/// `set_verify_hostname` call in `masque_h2`.
///
/// Callers must use this instead of reading `CONNECT_SNI` directly, or the
/// override applies to some handshakes and not others.
pub fn connect_sni() -> String {
    std::env::var("AETHER_SNI")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| CONNECT_SNI.to_string())
}
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

pub const ECH_PUBLIC_NAME: &str = "cloudflare-ech.com";

pub const DEFAULT_MODEL: &str = "PC";
pub const DEFAULT_LOCALE: &str = "en_US";

pub const KEY_TYPE_MASQUE: &str = "secp256r1";
pub const TUN_TYPE_MASQUE: &str = "masque";

pub const UA_REGISTER: &str = "WARP for Android";
pub const CF_CLIENT_VERSION: &str = "a-6.35-4471";

pub const ALPN_H3: &[u8] = b"h3";

pub const CF_CONNECT_PROTOCOL: &str = "cf-connect-ip";

pub const H3_DATAGRAM_00: u64 = 0x276;

pub const CONNECT_IP_CONTEXT_ID: u64 = 0;

pub const CDN_ANYCAST_POOL: &[&str] = &[
    "104.16.0.0",
    "104.17.0.0",
    "104.18.0.0",
    "104.19.0.0",
    "104.20.0.0",
    "104.21.0.0",
    "104.22.0.0",
    "104.24.0.0",
    "104.25.0.0",
    "104.26.0.0",
    "104.27.0.0",
    "104.28.0.0",
    "172.64.0.0",
    "172.65.0.0",
    "172.66.0.0",
    "172.67.0.0",
    "188.114.96.0",
    "188.114.97.0",
    "188.114.98.0",
    "188.114.99.0",
];

pub const QUIC_PORT: u16 = 443;

/// SHA-256 SPKI hashes of Cloudflare MASQUE edge certificates.
/// Used for certificate pinning to prevent MITM attacks while allowing
/// SslVerifyMode::NONE at the library level (required because Cloudflare
/// edges serve different certs per SNI and some are self-signed).
///
/// Format: raw 32-byte hex (no base64, no colons).
pub const MASQUE_PINS: &[&[u8]] = &[
    // masque.cloudflareclient.com — self-signed by Cloudflare (2024-02-27 Self-Signed Root)
    // Returned when SNI is empty or unrecognized
    b"\xeb\x59\x1b\x36\xab\x26\xba\x61\x7e\x98\x37\x19\x18\xc1\x0b\xcd\xea\xe3\x74\x2d\xb6\xe7\x65\x43\xf9\x4b\xe5\x24\xdc\xe1\xd5\x55",
    // cloudflareaccess.com — signed by Google Trust Services WE1
    // Returned when SNI=cloudflareaccess.com
    b"\x3f\xbb\x1d\x74\x52\xd3\x2b\x38\x81\xeb\x4b\x5d\x48\x42\x14\x45\xb6\xb9\xd8\xf5\x22\x59\x59\xf0\x33\x53\x2d\x50\x26\x37\xb0\x40",
];

#[cfg(test)]
mod tests {
    use super::*;

    // AETHER_SNI is process-global, so the cases share one test rather than
    // racing each other under the parallel runner.
    #[test]
    fn the_connect_sni_can_be_overridden() {
        std::env::remove_var("AETHER_SNI");
        assert_eq!(connect_sni(), CONNECT_SNI);

        std::env::set_var("AETHER_SNI", "example.invalid");
        assert_eq!(connect_sni(), "example.invalid");

        // Surrounding whitespace comes from a text field, not intent.
        std::env::set_var("AETHER_SNI", "  spaced.invalid  ");
        assert_eq!(connect_sni(), "spaced.invalid");

        // An empty or all-whitespace value means "unset", not "send an empty
        // SNI" -- an empty SNI is a distinct and very fingerprintable
        // handshake.
        std::env::set_var("AETHER_SNI", "   ");
        assert_eq!(connect_sni(), CONNECT_SNI);
        std::env::set_var("AETHER_SNI", "");
        assert_eq!(connect_sni(), CONNECT_SNI);

        std::env::remove_var("AETHER_SNI");
    }
}
