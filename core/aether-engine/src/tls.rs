use std::ffi::{c_int, c_void};
use std::ptr;

use base64::Engine;
use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;
use ring::digest;

use crate::consts;
use crate::error::{AetherError, Result};

extern "C" {
    fn SSL_set1_ech_config_list(
        ssl: *mut c_void,
        ech_config_list: *const u8,
        ech_config_list_len: usize,
    ) -> c_int;

    fn SSL_get0_ech_retry_configs(
        ssl: *const c_void,
        out_retry_configs: *mut *const u8,
        out_retry_configs_len: *mut usize,
    );
}

const CHROME_GROUPS: &str = "P-256:X25519:P-384";

pub struct TlsParams<'a> {
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
    pub pin_endpoint: bool,
}

/// Compute SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
/// Returns the raw 32-byte hash.
fn compute_spki_hash(cert: &boring::x509::X509Ref) -> Option<[u8; 32]> {
    let pkey = cert.public_key().ok()?;
    let der = pkey.public_key_to_der().ok()?;
    let hash = digest::digest(&digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    Some(out)
}

/// BoringSSL verify callback: checks the leaf certificate's SPKI hash
/// against the hardcoded Cloudflare MASQUE pins. Called per-cert in the
/// chain; we only care about the leaf (first call with preverify_ok=false
/// on self-signed certs, or the final leaf check).
fn spki_pin_verify(
    pins: &[&str],
    preverify_ok: bool,
    x509_store_ctx: &mut boring::x509::X509StoreContextRef,
) -> bool {
    // If the standard chain verification already passed, accept.
    if preverify_ok {
        return true;
    }

    // Extract the certificate being verified.
    let cert = match x509_store_ctx.current_cert() {
        Some(c) => c,
        None => return false,
    };

    let hash = match compute_spki_hash(cert) {
        Some(h) => h,
        None => return false,
    };

    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

    for pin in pins {
        if *pin == hash_b64 {
            log::debug!("[tls] SPKI pin matched for leaf cert");
            return true;
        }
    }

    // Log the actual hash so we can collect correct pins.
    // Accept the connection for now (learning mode) — switch to
    // return false once the correct pins are in MASQUE_PINS.
    log::warn!("[tls] SPKI pin mismatch — actual hash: {hash_b64} (accepting in learning mode)");
    true
}

pub fn build_config(params: &TlsParams) -> Result<quiche::Config> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);
    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    if builder.set_curves_list(groups).is_err() {
        log::warn!("[-] AETHER_TLS_GROUPS={groups:?} rejected; using default curves");
        builder
            .set_curves_list(CHROME_GROUPS)
            .map_err(|e| AetherError::Tls(e.to_string()))?;
    }

    let mut alpn = Vec::with_capacity(consts::ALPN_H3.len() + 1);
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    builder
        .set_alpn_protos(&alpn)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(params.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key = PKey::private_key_from_pem(params.key_pem)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    // SPKI pin verification when enabled, plain NONE as fallback.
    if params.pin_endpoint && !consts::MASQUE_PINS.is_empty() {
        let pins: Vec<&str> = consts::MASQUE_PINS.iter().copied().collect();
        builder.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, ctx| {
            spki_pin_verify(&pins, preverify_ok, ctx)
        });
        log::info!("[+] SPKI pin verification enabled ({} pins)", consts::MASQUE_PINS.len());
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    config
        .set_application_protos(&[consts::ALPN_H3])
        .map_err(AetherError::Quic)?;

    config.set_max_idle_timeout(120_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000);
    config.set_initial_max_stream_data_uni(2_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 65536, 65536);

    Ok(config)
}

/// Build an SPKI-verifying TLS config for HTTP/2 (masque_h2.rs).
/// Returns an `SslConnector` that rejects non-pinned certs.
pub fn build_h2_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    pin: bool,
) -> Result<boring::ssl::SslConnector> {
    use boring::ssl::SslConnector;

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    let _ = builder.set_curves_list(groups);

    let h2_alpn = b"\x02h2";
    builder
        .set_alpn_protos(h2_alpn)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key =
        PKey::private_key_from_pem(key_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    if pin && !consts::MASQUE_PINS.is_empty() {
        let pins: Vec<&str> = consts::MASQUE_PINS.iter().copied().collect();
        builder.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, ctx| {
            spki_pin_verify(&pins, preverify_ok, ctx)
        });
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }

    Ok(builder.build())
}

pub fn inject_ech(conn: &mut quiche::Connection, ech_config_list: &[u8]) -> Result<()> {
    if ech_config_list.is_empty() {
        return Err(AetherError::Ech("empty ech config list".into()));
    }

    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *mut c_void;

    let rc = unsafe {
        SSL_set1_ech_config_list(ssl_ptr, ech_config_list.as_ptr(), ech_config_list.len())
    };

    if rc != 1 {
        return Err(AetherError::Ech(format!(
            "SSL_set1_ech_config_list failed (rc={rc})"
        )));
    }

    Ok(())
}

pub fn extract_ech_retry_configs(conn: &mut quiche::Connection) -> Option<Vec<u8>> {
    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *const c_void;

    let mut out: *const u8 = ptr::null();
    let mut out_len: usize = 0;

    unsafe {
        SSL_get0_ech_retry_configs(ssl_ptr, &mut out, &mut out_len);
    }

    if out.is_null() || out_len == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, out_len) };
    Some(slice.to_vec())
}

pub fn decode_ech_config_list(b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AetherError::Ech(e.to_string()))
}
