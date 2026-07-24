use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use rand::{Rng, RngCore};
use regex::Regex;
use tokio::net::UdpSocket;

// Compiled once and reused — parse_cps() was previously recompiling this
// regex on every call (up to 5x per handshake/keepalive burst, once per
// i1..i5 signature), which is wasted CPU on a path that runs per-reconnect.
static TAG_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"<([a-z]+)\s*([^>]*)>").unwrap());

#[derive(Debug, Clone)]
pub struct AetherNoizeConfig {
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub jc: usize,
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jc_after_hs: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub junk_interval: Duration,
    pub handshake_delay: Duration,
    pub allow_zero_size: bool,
}

impl AetherNoizeConfig {
    pub fn off() -> Self {
        Self {
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            jc: 0,
            jc_before_hs: 0,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 0,
            jmax: 0,
            junk_interval: Duration::ZERO,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn light() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 20-32>".to_string()),
            i2: Some("<rc 24-48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 1,
            jc_after_hs: 1,
            jmin: 48,
            jmax: 190,
            junk_interval: Duration::from_millis(3),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    pub fn balanced() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 20-40>".to_string()),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>".to_string()),
            i3: Some("<r 30-50>".to_string()),
            i4: None,
            i5: None,
            jc: 6,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 1,
            jmin: 64,
            jmax: 256,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 40-64>".to_string()),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>".to_string()),
            i3: Some("<b 474554><rc 40-60>".to_string()),
            i4: Some("<r 60-100>".to_string()),
            i5: Some("<c><rd 20-40>".to_string()),
            jc: 10,
            jc_before_hs: 4,
            jc_after_i1: 3,
            jc_after_hs: 3,
            jmin: 80,
            jmax: 384,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(12),
            allow_zero_size: false,
        }
    }

    /// Mimic Chrome TLS fingerprint — blends with legitimate Chrome traffic
    pub fn chrome() -> Self {
        Self {
            // TLS ClientHello: record type 0x16, version TLS 1.2, 2-byte record length,
            // handshake type 0x01 (ClientHello), 3-byte handshake length,
            // client version TLS 1.2, 32-byte random.
            // Uses <r> (binary random) for length fields — NOT <rd> which generates ASCII digits.
            i1: Some("<b 16030300><r 2><b 010000><r 3><b 0303><r 32>".to_string()),
            // POST-like header after "handshake"
            i2: Some("<b 504f5354><rc 20-30><rd 10-20>".to_string()),
            // HTTP/2 SETTINGS frame mimicry
            i3: Some("<b 00000c040000000000000300006400040000ffff><r 8-16>".to_string()),
            i4: None,
            i5: None,
            jc: 6,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 1,
            jmin: 128,
            jmax: 512,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    /// GFW-specific — mimics the pattern that GFW's DPI expects to see
    /// before allowing the connection through
    pub fn gfw() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 24>".to_string()),
            // TLS ClientHello-like preamble with binary length fields
            i2: Some("<b 16030300><r 2><b 010000><r 3><b 0303><r 32>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 2,
            jc_after_hs: 0,
            jmin: 64,
            jmax: 256,
            junk_interval: Duration::from_millis(5),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    /// Firewall bypass — minimal obfuscation tuned for corporate/firewall DPI
    pub fn firewall() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 24>".to_string()),
            i2: Some("<r 48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 2,
            jc_after_hs: 0,
            jmin: 48,
            jmax: 190,
            junk_interval: Duration::from_millis(4),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    /// VoIP/Zoom-like traffic — fixed-size packets at regular 20ms intervals
    pub fn voice() -> Self {
        Self {
            // Fixed-size packets mimicking VoIP cadence (20ms interval is the key signal).
            // No fake RTP headers — a DPI system seeing RTP headers carrying WireGuard
            // packets would immediately flag this as obfuscated traffic.
            // Instead, use generic fixed-size payloads that match VoIP packet sizes.
            i1: Some("<r 160>".to_string()),
            i2: Some("<r 128>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 3,
            jc_before_hs: 1,
            jc_after_i1: 1,
            jc_after_hs: 1,
            jmin: 120,
            jmax: 180,
            junk_interval: Duration::from_millis(20),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    /// Streaming traffic — large bursts followed by idle periods
    pub fn streaming() -> Self {
        Self {
            // TLS ClientHello-like preamble with binary length fields
            i1: Some("<b 16030300><r 2><b 010000><r 3><b 0303><r 64-128>".to_string()),
            // HTTP/2 DATA frame-like
            i2: Some("<b 0000000000><r 256-512>".to_string()),
            i3: Some("<b 0000000000><r 512-1024>".to_string()),
            i4: Some("<r 256-512>".to_string()),
            i5: None,
            jc: 8,
            jc_before_hs: 2,
            jc_after_i1: 3,
            jc_after_hs: 3,
            jmin: 256,
            jmax: 1400,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(10),
            allow_zero_size: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> AetherNoizeConfig {
    match name {
        "off" | "none" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "aggressive" | "heavy" => AetherNoizeConfig::aggressive(),
        "chrome" => AetherNoizeConfig::chrome(),
        "voice" => AetherNoizeConfig::voice(),
        "streaming" => AetherNoizeConfig::streaming(),
        "gfw" => AetherNoizeConfig::gfw(),
        "firewall" => AetherNoizeConfig::firewall(),
        _ => AetherNoizeConfig::balanced(),
    }
}

fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max > min && min > 0 {
            return rand::thread_rng().gen_range(min..=max).min(2048);
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

pub fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();

    for cap in TAG_REGEX.captures_iter(spec) {
        let tag_type = cap.get(1).map_or("", |m| m.as_str());
        let tag_data = cap.get(2).map_or("", |m| m.as_str()).trim();

        match tag_type {
            "b" => {
                let hex_str: String = tag_data.chars().filter(|c| !c.is_whitespace()).collect();
                let clean = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(&hex_str);
                if let Ok(decoded) = hex::decode(clean) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            "c" => {
                let counter = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    % 0xFFFFFFFF) as u32;
                out.extend_from_slice(&counter.to_be_bytes());
            }
            "r" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let mut r = vec![0u8; len];
                    rand::thread_rng().fill_bytes(&mut r);
                    out.extend_from_slice(&r);
                }
            }
            "rc" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            "rd" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"0123456789";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            _ => {}
        }
    }

    out
}

fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return payload.to_vec();
    }

    let mut initiator_spi = [0u8; 8];
    let mut responder_spi = [0u8; 8];

    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        rand::thread_rng().fill_bytes(&mut initiator_spi);
    }
    rand::thread_rng().fill_bytes(&mut responder_spi);

    let total_length = 28u32 + 24 + payload.len() as u32;
    let sa_payload_length = 24u16 + payload.len() as u16;

    let mut header = Vec::with_capacity(total_length as usize);

    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.push(0x21);
    header.push(0x20);
    header.push(0x22);
    header.push(0x08);
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&total_length.to_be_bytes());

    header.push(0x00);
    header.push(0x00);
    header.extend_from_slice(&sa_payload_length.to_be_bytes());

    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);

    header.extend_from_slice(payload);
    header
}

fn generate_junk(cfg: &AetherNoizeConfig) -> Vec<u8> {
    let (min_size, max_size) = match (cfg.jmin, cfg.jmax) {
        (0, 0) if cfg.allow_zero_size => return vec![],
        (0, 0) => return vec![0x00],
        (min, 0) if !cfg.allow_zero_size => (min.max(1), min.max(1)),
        (min, max) if !cfg.allow_zero_size => (min.max(1), max.max(min)),
        (min, max) => (min, max.max(min)),
    };

    let size = if max_size == min_size {
        min_size
    } else {
        rand::thread_rng().gen_range(min_size..=max_size)
    };

    if size == 0 {
        return if cfg.allow_zero_size { vec![] } else { vec![0x00] };
    }

    let mut junk = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut junk);
    junk
}

async fn send_connected(sock: &UdpSocket, pkt: &[u8]) {
    let _ = sock.send(pkt).await;
}

pub async fn apply_obfuscation(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    if let Some(ref i1) = cfg.i1 {
        let payload = parse_cps(i1);
        if !payload.is_empty() {
            let framed = wrap_ikev2(&payload);
            send_connected(sock, &framed).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for _ in 0..cfg.jc_after_i1 {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for _ in 0..cfg.jc_before_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for sig in [&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5].iter() {
        if let Some(s) = sig {
            let pkt = parse_cps(s);
            if !pkt.is_empty() {
                send_connected(sock, &pkt).await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    if !cfg.handshake_delay.is_zero() {
        tokio::time::sleep(cfg.handshake_delay).await;
    }
}

pub async fn send_post_handshake_junk(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    for _ in 0..cfg.jc_after_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }
}

pub async fn send_keepalive_junk(sock: &UdpSocket, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    // Battery optimization: cap at 2 junk packets per keepalive tick
    // instead of base + random(0..=base) which could be 3-6 packets.
    // Two packets maintain the obfuscation pattern without excessive
    // radio wake-ups on mobile.
    let count = cfg.jc_before_hs.max(1).min(2);

    for _ in 0..count {
        let mut junk = generate_junk(cfg);
        if let Some(first) = junk.first_mut() {
            if *first >= 1 && *first <= 4 {
                *first = first.wrapping_add(0x40);
            }
        }
        send_connected(sock, &junk).await;

        let jitter = rand::thread_rng().gen_range(0..=8);
        let gap = cfg.junk_interval + Duration::from_millis(jitter);
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }
}
