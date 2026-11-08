use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroize;

use crate::error::{FirefoxError, Result};

const PROTOCOL: &str = "identity.mozilla.com/picl/v1/";

pub fn normalize_email(email: &str) -> String {
    email.chars().filter(|c| !invisible(*c)).collect()
}

pub fn normalize_code(code: &str) -> String {
    code.chars().filter_map(|c| match c {
        '۰'..='۹' => Some(char::from_u32('0' as u32 + c as u32 - '۰' as u32).unwrap()),
        '٠'..='٩' => Some(char::from_u32('0' as u32 + c as u32 - '٠' as u32).unwrap()),
        _ if invisible(c) => None,
        _ => Some(c),
    }).collect()
}

fn invisible(c: char) -> bool {
    c.is_whitespace()
        || matches!(c as u32, 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff)
}

pub fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else { return false };
    !local.is_empty()
        && local.len() <= 64
        && email.len() <= 320
        && !local.chars().any(|c| c.is_control())
        && crate::types::valid_dns_name(domain)
}

pub fn derive_auth_pw(email: &str, password: &str) -> [u8; 32] {
    let salt = format!("{PROTOCOL}quickStretch:{email}");
    let mut stretched = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), 1000, &mut stretched);
    let hkdf = Hkdf::<Sha256>::new(Some(&[0]), &stretched);
    let mut output = [0u8; 32];
    hkdf.expand(format!("{PROTOCOL}authPW").as_bytes(), &mut output).expect("HKDF output length is valid");
    stretched.zeroize();
    output
}

pub fn derive_hawk(token_hex: &str, context: &str) -> Result<(String, [u8; 32])> {
    let mut token = hex::decode(token_hex).map_err(|_| FirefoxError::Protocol("invalid FxA session token".into()))?;
    if token.len() < 16 {
        token.zeroize();
        return Err(FirefoxError::Protocol("FxA session token is too short".into()));
    }
    let hkdf = Hkdf::<Sha256>::new(None, &token);
    token.zeroize();
    let mut output = [0u8; 96];
    hkdf.expand(format!("{PROTOCOL}{context}").as_bytes(), &mut output)
        .map_err(|_| FirefoxError::Internal("HKDF expansion failed".into()))?;
    let id = hex::encode(&output[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&output[32..64]);
    output.zeroize();
    Ok((id, key))
}

pub fn hawk_header(method: &str, raw_url: &str, id: &str, key: &[u8; 32], payload: Option<&[u8]>) -> Result<String> {
    let url = Url::parse(raw_url)?;
    let host = url.host_str().ok_or_else(|| FirefoxError::Protocol("HAWK URL has no host".into()))?;
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let mut nonce = [0u8; 6];
    OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let payload_hash = payload.filter(|body| !body.is_empty()).map(|body| {
        let mut hash = Sha256::new();
        hash.update(b"hawk.1.payload\napplication/json\n");
        hash.update(body);
        hash.update(b"\n");
        hex::encode(hash.finalize())
    });
    let normalized = format!(
        "hawk.1.header\n{timestamp}\n{nonce}\n{}\n{path}\n{host}\n{port}\n{}\n\n",
        method.to_ascii_uppercase(),
        payload_hash.as_deref().unwrap_or("")
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(normalized.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let mut header = format!("Hawk id=\"{id}\", ts=\"{timestamp}\", nonce=\"{nonce}\", mac=\"{signature}\"");
    if let Some(hash) = payload_hash {
        header.push_str(&format!(", hash=\"{hash}\""));
    }
    Ok(header)
}

pub fn random_urlsafe(size: usize) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
