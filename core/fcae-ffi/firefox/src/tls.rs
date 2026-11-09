use boring::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslVerifyMode};
use boring::x509::{store::{X509Store, X509StoreBuilder}, X509};
#[cfg(target_os = "android")]
use std::path::Path;
use std::sync::OnceLock;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::dialer::Dialer;
use crate::error::{FirefoxError, Result};

pub const ALPN_H2: &[u8] = b"\x02h2";
pub const ALPN_H1: &[u8] = b"\x08http/1.1";
pub const ALPN_H2_H1: &[u8] = b"\x02h2\x08http/1.1";

const FIREFOX_TLS12_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const FIREFOX_TLS13_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";
const FIREFOX_GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";
const FIREFOX_KEY_SHARES: &str = "X25519MLKEM768:X25519:P-256";
const FIREFOX_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1";

fn fingerprint() -> aether_engine::tls::Fingerprint {
    aether_engine::tls::Fingerprint {
        ciphers: Some(FIREFOX_TLS12_CIPHERS.into()),
        tls13_ciphers: Some(FIREFOX_TLS13_CIPHERS.into()),
        groups: FIREFOX_GROUPS.into(),
        key_shares: Some(FIREFOX_KEY_SHARES.into()),
        grease: false,
        grease_sigalgs: false,
        sigalgs: Some(FIREFOX_SIGALGS.into()),
        cert_compression: Some("zlib:brotli:zstd".into()),
        alps: None,
        trust_anchors: None,
        server_padding: None,
        ech_grease: true,
        ocsp_stapling: true,
        sct: true,
        session_ticket: true,
        permute_extensions: false,
    }
}

fn is_fastly_proxy(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.ends_with(".m1.fastly-masque.net")
}

fn mozilla_roots() -> Result<&'static X509Store> {
    static ROOTS: OnceLock<std::result::Result<X509Store, String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut store = X509StoreBuilder::new().map_err(|error| error.to_string())?;
        for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            let cert = X509::from_der(der.as_ref()).map_err(|error| error.to_string())?;
            store.add_cert(cert).map_err(|error| error.to_string())?;
        }
        Ok(store.build())
    }).as_ref().map_err(|error| FirefoxError::Protocol(format!("loading Mozilla trust roots: {error}")))
}

#[cfg(target_os = "android")]
fn android_system_ca_directory() -> &'static Path {
    let apex = Path::new("/apex/com.android.conscrypt/cacerts");
    if std::fs::read_dir(apex).ok().is_some_and(|mut entries| entries.next().is_some()) {
        apex
    } else {
        Path::new("/system/etc/security/cacerts")
    }
}

fn configuration(alpn: &[u8], host: &str) -> Result<ConnectConfiguration> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|error| FirefoxError::Protocol(format!("creating TLS context: {error}")))?;
    let fingerprint = fingerprint();
    fingerprint
        .apply(&mut builder, alpn)
        .map_err(|error| FirefoxError::Protocol(format!("configuring Firefox TLS fingerprint: {error}")))?;
    if is_fastly_proxy(host) {
        // Mozilla's proxy certificates can use roots missing from older device stores.
        // Keep this store scoped to Fastly proxy names and update it with the app.
        builder.set_cert_store_ref(mozilla_roots()?);
    } else {
        #[cfg(target_os = "android")]
        builder
            .load_verify_locations(None, Some(android_system_ca_directory()))
            .map_err(|error| FirefoxError::Protocol(format!("loading Android system trust roots: {error}")))?;
        #[cfg(not(target_os = "android"))]
        builder
            .set_default_verify_paths()
            .map_err(|error| FirefoxError::Protocol(format!("loading system trust roots: {error}")))?;
    }
    builder.set_verify(SslVerifyMode::PEER);
    let mut configuration = builder
        .build()
        .configure()
        .map_err(|error| FirefoxError::Protocol(format!("creating TLS connection: {error}")))?;
    configuration.set_verify_hostname(true);
    configuration.set_use_server_name_indication(true);
    fingerprint
        .prepare(&mut configuration, alpn)
        .map_err(|error| FirefoxError::Protocol(format!("preparing Firefox TLS handshake: {error}")))?;
    Ok(configuration)
}

pub async fn connect(dialer: &Dialer, host: &str, port: u16, alpn: &[u8]) -> Result<SslStream<TcpStream>> {
    let tcp = dialer.connect_tcp(host, port).await?;
    connect_stream(tcp, host, alpn).await
}

pub(crate) async fn connect_stream<S>(stream: S, host: &str, alpn: &[u8]) -> Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let config = configuration(alpn, host)?;
    tokio_boring::connect(config, host, stream).await.map_err(|error| {
        if error.ssl().is_some_and(|ssl| ssl.verify_result().is_err()) {
            FirefoxError::TlsCertificate { host: host.into(), message: error.to_string() }
        } else {
            FirefoxError::Tls { host: host.into(), message: error.to_string() }
        }
    })
}

pub fn require_h2(stream: &SslStream<TcpStream>) -> Result<()> {
    if stream.ssl().selected_alpn_protocol() == Some(b"h2") {
        Ok(())
    } else {
        Err(FirefoxError::Protocol("Mozilla proxy did not negotiate HTTP/2".into()))
    }
}

pub fn firefox_user_agent() -> String {
    firefox_user_agent_for_major(159)
}

pub(crate) fn firefox_user_agent_for_major(major: u16) -> String {
    let platform = if cfg!(target_os = "windows") || cfg!(target_os = "android") {
        "Windows NT 10.0; Win64; x64"
    } else if cfg!(target_os = "macos") {
        "Macintosh; Intel Mac OS X 10.15"
    } else if cfg!(target_arch = "aarch64") {
        "X11; Linux aarch64"
    } else {
        "X11; Linux x86_64"
    };
    format!("Mozilla/5.0 ({platform}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn mozilla_store_contains_the_fastly_root() {
        let expected = "cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058";
        assert!(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter()
            .any(|cert| hex::encode(Sha256::digest(cert.as_ref())) == expected));
        assert!(mozilla_roots().is_ok());
    }

    #[test]
    fn mozilla_store_is_scoped_to_fastly_proxy_hosts() {
        assert!(is_fastly_proxy("muc139.m1.fastly-masque.net"));
        assert!(is_fastly_proxy("P.M1.FASTLY-MASQUE.NET."));
        assert!(!is_fastly_proxy("m1.fastly-masque.net"));
        assert!(!is_fastly_proxy("muc139.m1.fastly-masque.net.example.com"));
        assert!(!is_fastly_proxy("accounts.firefox.com"));
    }

    #[test]
    fn certificate_failures_are_not_retried_forever() {
        let error = FirefoxError::TlsCertificate { host: "example.com".into(), message: "untrusted".into() };
        assert!(!error.is_transient());
        assert_eq!(error.reason_code(), "tls_certificate");
    }
}
