use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/FCFlenkchy/FCAE_VPN/main/sponsors.json";
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_MEDIA_BYTES: usize = 2 * 1024 * 1024;
// One portable sponsor canvas keeps the manifest behavior identical on every
// platform and fits the Android card without requiring platform-specific assets.
const MAX_WIDTH: u32 = 800;
const MAX_HEIGHT: u32 = 450;
#[cfg(target_os = "android")]
const MAX_FRAMES: usize = 60;
#[cfg(not(target_os = "android"))]
const MAX_FRAMES: usize = 120;
#[cfg(target_os = "android")]
const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
#[cfg(target_os = "android")]
const MAX_TOTAL_DECODED_BYTES: usize = 24 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_TOTAL_DECODED_BYTES: usize = 96 * 1024 * 1024;
const ROTATE_EVERY: Duration = Duration::from_secs(5);
const MANIFEST_REFRESH_SECS: u64 = 12 * 60 * 60;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    #[serde(default)]
    sponsors: Vec<Campaign>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Campaign {
    id: String,
    title: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    media_url: Option<String>,
    destination_url: String,
    #[serde(default = "enabled")]
    enabled: bool,
    #[serde(default)]
    starts_at: Option<u64>,
    #[serde(default)]
    ends_at: Option<u64>,
}

fn enabled() -> bool { true }

#[derive(Clone)]
struct Frame {
    rgba: Arc<Vec<u8>>,
    delay: Duration,
}

#[derive(Clone)]
struct ReadyCampaign {
    campaign: Campaign,
    width: u32,
    height: u32,
    frames: Vec<Frame>,
}

#[derive(Clone)]
pub struct SponsorFrame {
    pub id: String,
    pub title: String,
    pub message: String,
    pub destination_url: String,
    pub width: u32,
    pub height: u32,
    pub campaign_count: u32,
    pub animated: bool,
    pub rgba: Arc<Vec<u8>>,
    pub generation: u64,
}

fn default_cache_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    if let Some(root) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(root).join("FCAE_VPN").join("sponsors");
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Caches/FCAE_VPN/sponsors");
    }
    if let Some(root) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(root).join("fcae-vpn/sponsors");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/fcae-vpn/sponsors");
    }
    std::env::temp_dir().join(format!("fcae-sponsor-cache-{}", std::process::id()))
}

struct State {
    campaigns: Vec<Campaign>,
    ready: Vec<ReadyCampaign>,
    cache_dir: PathBuf,
    rotation_started: Instant,
    current_campaign: usize,
    random_state: u64,
    manifest_checked_at: u64,
    last_error: String,
}

static STATE: Lazy<Mutex<State>> = Lazy::new(|| Mutex::new(State {
    campaigns: Vec::new(),
    ready: Vec::new(),
    cache_dir: default_cache_dir(),
    rotation_started: Instant::now(),
    current_campaign: 0,
    random_state: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64 ^ std::process::id() as u64,
    manifest_checked_at: 0,
    last_error: String::new(),
}));
static CONNECTED: AtomicBool = AtomicBool::new(false);
static SPONSOR_PROXY: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
static MANIFEST_BUSY: AtomicBool = AtomicBool::new(false);
static MEDIA_BUSY: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU64 = AtomicU64::new(1);

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn set_cache_dir(path: impl Into<PathBuf>) {
    STATE.lock().cache_dir = path.into();
    load_cached_manifest();
}

pub fn load_cached_manifest() {
    let cache_dir = STATE.lock().cache_dir.clone();
    let json = fs::read(cache_dir.join("manifest.json")).ok();
    let timestamp = fs::read_to_string(cache_dir.join("manifest.timestamp"))
        .ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(0);
    let checked_at = fs::read_to_string(cache_dir.join("manifest.check.timestamp"))
        .ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(timestamp);
    let now = unix_now();
    {
        let mut state = STATE.lock();
        state.manifest_checked_at = if checked_at <= now.saturating_add(300) { checked_at } else { 0 };
    }
    if let Some(json) = json {
        if let Ok(campaigns) = parse_manifest(&json) {
            apply_campaigns(campaigns);
        }
    }
}

pub fn set_proxy(proxy: Option<String>) {
    *SPONSOR_PROXY.write() = proxy;
}

pub fn set_connected(connected: bool) {
    let was = CONNECTED.swap(connected, Ordering::AcqRel);
    if connected && !was {
        if manifest_due() {
            refresh_manifest_async();
        } else {
            refresh_media_async();
        }
    }
}

pub fn manifest_refresh_remaining_secs() -> u64 {
    let checked_at = STATE.lock().manifest_checked_at;
    if checked_at == 0 { return 0; }
    let now = unix_now();
    if checked_at > now.saturating_add(300) { return 0; }
    MANIFEST_REFRESH_SECS.saturating_sub(now.saturating_sub(checked_at))
}

pub fn manifest_check_started() {
    if !CONNECTED.load(Ordering::Acquire) { return; }
    let now = unix_now();
    let cache_dir = {
        let mut state = STATE.lock();
        state.manifest_checked_at = now;
        state.cache_dir.clone()
    };
    let _ = fs::create_dir_all(&cache_dir);
    let _ = fs::write(cache_dir.join("manifest.check.timestamp"), now.to_string());
}

pub fn manifest_due() -> bool {
    manifest_refresh_remaining_secs() == 0
}

pub fn set_manifest_json(json: &[u8]) -> Result<(), String> {
    let campaigns = parse_manifest(json)?;
    let now = unix_now();
    apply_campaigns(campaigns);
    let cache_dir = {
        let mut state = STATE.lock();
        state.manifest_checked_at = now;
        state.cache_dir.clone()
    };
    let _ = fs::create_dir_all(&cache_dir);
    let manifest_tmp = cache_dir.join("manifest.json.tmp");
    if fs::write(&manifest_tmp, json).is_ok() {
        let manifest_path = cache_dir.join("manifest.json");
        let _ = fs::remove_file(&manifest_path);
        if fs::rename(manifest_tmp, manifest_path).is_ok() {
            let _ = fs::write(cache_dir.join("manifest.timestamp"), now.to_string());
            let _ = fs::write(cache_dir.join("manifest.check.timestamp"), now.to_string());
        }
    }
    if CONNECTED.load(Ordering::Acquire) { refresh_media_async(); }
    Ok(())
}

fn apply_campaigns(campaigns: Vec<Campaign>) {
    let mut state = STATE.lock();
    let previous = std::mem::take(&mut state.ready);
    let mut ready = Vec::with_capacity(campaigns.len());

    for campaign in &campaigns {
        if let Some(existing) = previous.iter().find(|candidate| {
            candidate.campaign.id == campaign.id
                && candidate.campaign.media_url == campaign.media_url
                && candidate.campaign.destination_url == campaign.destination_url
                && candidate.campaign.title == campaign.title
                && candidate.campaign.message == campaign.message
        }) {
            ready.push(existing.clone());
        } else {
            // Publish the text card immediately. Media decoding is asynchronous
            // and replaces this fallback when it succeeds.
            ready.push(ReadyCampaign {
                campaign: campaign.clone(),
                width: 0,
                height: 0,
                frames: Vec::new(),
            });
        }
    }

    let ready_count = ready.len();
    state.ready = ready;
    state.current_campaign = if ready_count == 0 {
        0
    } else {
        state.current_campaign % ready_count
    };
    prune_cache(&state.cache_dir, &campaigns);
    state.campaigns = campaigns;
    state.last_error.clear();
    state.rotation_started = Instant::now();
    drop(state);
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub fn refresh_manifest_async() {
    if !CONNECTED.load(Ordering::Acquire)
        || !manifest_due()
        || MANIFEST_BUSY.swap(true, Ordering::AcqRel)
    {
        return;
    }
    manifest_check_started();
    thread::spawn(|| {
        match fetch_manifest() {
            Ok(json) => {
                if let Err(error) = set_manifest_json(&json) {
                    STATE.lock().last_error = error;
                }
            }
            Err(error) => {
                STATE.lock().last_error = error;
                if CONNECTED.load(Ordering::Acquire) {
                    refresh_media_async();
                }
            }
        }
        MANIFEST_BUSY.store(false, Ordering::Release);
    });
}

pub fn refresh_media_async() {
    if !CONNECTED.load(Ordering::Acquire) || MEDIA_BUSY.swap(true, Ordering::AcqRel) { return; }
    let (campaigns, cache_dir) = {
        let state = STATE.lock();
        (state.campaigns.clone(), state.cache_dir.clone())
    };
    thread::spawn(move || {
        let ready = prepare_media(&campaigns, &cache_dir);
        if CONNECTED.load(Ordering::Acquire) {
            let mut state = STATE.lock();
            state.ready = ready;
            state.current_campaign = 0;
            state.rotation_started = Instant::now();
            GENERATION.fetch_add(1, Ordering::Relaxed);
        }
        MEDIA_BUSY.store(false, Ordering::Release);
    });
}

fn advance_campaign(state: &mut State) {
    let count = state.ready.len();
    if count <= 1 {
        state.current_campaign = 0;
        return;
    }
    state.current_campaign = if count == 2 {
        (state.current_campaign + 1) % 2
    } else {
        // Xorshift64 chooses among every campaign except the one on screen.
        let mut value = state.random_state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        state.random_state = value;
        let choice = value as usize % (count - 1);
        if choice >= state.current_campaign { choice + 1 } else { choice }
    };
    state.rotation_started = Instant::now();
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub fn next_campaign() {
    let mut state = STATE.lock();
    advance_campaign(&mut state);
}

pub fn current_frame() -> Option<SponsorFrame> {
    let mut state = STATE.lock();
    if state.ready.is_empty() { return None; }
    if state.ready.len() > 1 && state.rotation_started.elapsed() >= ROTATE_EVERY {
        advance_campaign(&mut state);
    }
    let ready_count = state.ready.len();
    state.current_campaign %= ready_count;
    let campaign_index = state.current_campaign;
    let ready = &state.ready[campaign_index];
    let within = state.rotation_started.elapsed();
    let mut frame_index = 0;
    if ready.frames.len() > 1 {
        let mut cursor = Duration::ZERO;
        let cycle = ready.frames.iter().fold(Duration::ZERO, |sum, frame| sum + frame.delay);
        let target = if cycle.is_zero() { Duration::ZERO } else {
            Duration::from_millis((within.as_millis() % cycle.as_millis()) as u64)
        };
        for (index, frame) in ready.frames.iter().enumerate() {
            cursor += frame.delay;
            frame_index = index;
            if target < cursor { break; }
        }
    }
    let rgba = ready.frames.get(frame_index)
        .map(|frame| frame.rgba.clone())
        .unwrap_or_default();
    let generation = (GENERATION.load(Ordering::Relaxed) << 32)
        ^ ((campaign_index as u64) << 16)
        ^ frame_index as u64;
    Some(SponsorFrame {
        id: ready.campaign.id.clone(),
        title: ready.campaign.title.clone(),
        message: ready.campaign.message.clone().unwrap_or_default(),
        destination_url: ready.campaign.destination_url.clone(),
        width: ready.width,
        height: ready.height,
        campaign_count: ready_count.try_into().unwrap_or(u32::MAX),
        animated: ready.frames.len() > 1,
        rgba,
        generation,
    })
}

pub fn last_error() -> String { STATE.lock().last_error.clone() }

fn fetch_manifest() -> Result<Vec<u8>, String> {
    let response = client()?.get(MANIFEST_URL).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() { return Err(format!("manifest HTTP {}", response.status())); }
    read_limited(response, MAX_MANIFEST_BYTES)
}

fn parse_manifest(body: &[u8]) -> Result<Vec<Campaign>, String> {
    if body.len() > MAX_MANIFEST_BYTES { return Err("manifest too large".into()); }
    let manifest: Manifest = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if manifest.schema_version != 1 { return Err("unsupported sponsor schema".into()); }
    if manifest.sponsors.len() > 32 { return Err("too many sponsor campaigns".into()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut ids = HashSet::new();
    let mut valid = Vec::new();
    for campaign in manifest.sponsors {
        validate_campaign(&campaign)?;
        if !ids.insert(campaign.id.clone()) { return Err("duplicate sponsor id".into()); }
        if campaign.enabled
            && campaign.starts_at.map_or(true, |start| now >= start)
            && campaign.ends_at.map_or(true, |end| now <= end)
        {
            valid.push(campaign);
        }
    }
    Ok(valid)
}

fn validate_campaign(c: &Campaign) -> Result<(), String> {
    if c.id.is_empty() || c.id.len() > 64 || !c.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("invalid sponsor id".into());
    }
    if c.title.is_empty() || c.title.len() > 96
        || !c.title.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
    {
        return Err("sponsor title must use printable ASCII".into());
    }
    if c.message.as_ref().is_some_and(|message| {
        message.is_empty() || message.len() > 256
            || !message.bytes().all(|byte| byte == b'\n' || matches!(byte, 0x20..=0x7e))
    }) {
        return Err("sponsor message must use printable ASCII and be at most 256 bytes".into());
    }
    if c.destination_url.len() > 511 || !c.destination_url.is_ascii()
        || !is_https(&c.destination_url)
    {
        return Err("invalid sponsor destination HTTPS URL".into());
    }
    if c.media_url.as_ref().is_some_and(|url| {
        url.is_empty() || url.len() > 2_048 || !url.is_ascii() || !is_https(url)
    }) {
        return Err("invalid sponsor media HTTPS URL".into());
    }
    if matches!((c.starts_at, c.ends_at), (Some(start), Some(end)) if start >= end) {
        return Err("invalid sponsor date range".into());
    }
    Ok(())
}

fn is_https(url: &str) -> bool {
    url.starts_with("https://") && !url.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
}

fn prune_cache(cache_dir: &Path, campaigns: &[Campaign]) {
    let _ = fs::create_dir_all(cache_dir);
    let keep: HashSet<String> = campaigns.iter()
        .filter(|campaign| campaign.media_url.is_some())
        .map(cache_name)
        .collect();
    if let Ok(entries) = fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".media") && !keep.contains(&name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn prepare_media(campaigns: &[Campaign], cache_dir: &Path) -> Vec<ReadyCampaign> {
    prune_cache(cache_dir, campaigns);
    let mut ready = Vec::new();
    let mut decoded_total = 0usize;
    for campaign in campaigns {
        let decoded = campaign.media_url.as_ref().and_then(|_| {
            let path = cache_dir.join(cache_name(campaign));
            let decoded = fs::read(&path).ok()
                .and_then(|bytes| decode(campaign.clone(), &bytes).ok())
                .or_else(|| {
                    let bytes = download_media(campaign).ok()?;
                    let decoded = decode(campaign.clone(), &bytes).ok()?;
                    let _ = fs::write(&path, &bytes);
                    Some(decoded)
                });
            if decoded.is_none() { let _ = fs::remove_file(path); }
            decoded
        });
        if let Some(decoded) = decoded {
            let decoded_bytes = decoded.frames.iter().map(|frame| frame.rgba.len()).sum::<usize>();
            if decoded_total.saturating_add(decoded_bytes) <= MAX_TOTAL_DECODED_BYTES {
                decoded_total += decoded_bytes;
                ready.push(decoded);
                continue;
            }
        }
        ready.push(ReadyCampaign {
            campaign: campaign.clone(),
            width: 0,
            height: 0,
            frames: Vec::new(),
        });
    }
    ready
}

fn cache_name(c: &Campaign) -> String {
    let mut hash = DefaultHasher::new();
    c.media_url.hash(&mut hash);
    format!("{}-{:016x}.media", c.id, hash.finish())
}

fn download_media(c: &Campaign) -> Result<Vec<u8>, String> {
    let url = c.media_url.as_deref().ok_or_else(|| "sponsor has no media URL".to_string())?;
    let response = client()?.get(url).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() { return Err(format!("media HTTP {}", response.status())); }
    read_limited(response, MAX_MEDIA_BYTES)
}

fn read_limited(mut response: reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|length| length > limit as u64) { return Err("response too large".into()); }
    let mut bytes = Vec::new();
    response.by_ref().take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > limit { return Err("response too large".into()); }
    Ok(bytes)
}

fn decode(campaign: Campaign, bytes: &[u8]) -> Result<ReadyCampaign, String> {
    let format = image::guess_format(bytes).map_err(|e| e.to_string())?;
    if format == ImageFormat::Gif {
        let decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
        let (width, height) = decoder.dimensions();
        validate_dimensions(width, height, 1)?;
        let frame_bytes = width as usize * height as usize * 4;
        let mut decoded = Vec::new();
        for frame in decoder.into_frames() {
            if decoded.len() >= MAX_FRAMES || (decoded.len() + 1) * frame_bytes > MAX_DECODED_BYTES {
                return Err("GIF exceeds decoded frame limits".into());
            }
            let frame = frame.map_err(|e| e.to_string())?;
            if frame.buffer().width() != width || frame.buffer().height() != height {
                return Err("inconsistent GIF frame dimensions".into());
            }
            decoded.push(frame);
        }
        if decoded.is_empty() { return Err("invalid GIF frame count".into()); }
        let frames = decoded.into_iter().map(|frame| {
            let (numer, denom) = frame.delay().numer_denom_ms();
            let millis = if denom == 0 { 100 } else { (numer / denom).clamp(20, 10_000) };
            Frame { rgba: Arc::new(frame.into_buffer().into_raw()), delay: Duration::from_millis(millis as u64) }
        }).collect();
        Ok(ReadyCampaign { campaign, width, height, frames })
    } else {
        if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP) {
            return Err("unsupported sponsor media".into());
        }
        let (width, height) = image::ImageReader::with_format(Cursor::new(bytes), format)
            .into_dimensions().map_err(|e| e.to_string())?;
        validate_dimensions(width, height, 1)?;
        let image: DynamicImage = image::load_from_memory_with_format(bytes, format).map_err(|e| e.to_string())?;
        let rgba = image.to_rgba8();
        validate_dimensions(rgba.width(), rgba.height(), 1)?;
        Ok(ReadyCampaign {
            campaign,
            width: rgba.width(),
            height: rgba.height(),
            frames: vec![Frame { rgba: Arc::new(rgba.into_raw()), delay: ROTATE_EVERY }],
        })
    }
}

fn validate_dimensions(width: u32, height: u32, frames: usize) -> Result<(), String> {
    if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
        return Err("sponsor media dimensions exceed limits".into());
    }
    let decoded = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_mul(frames))
        .ok_or_else(|| "sponsor media dimensions overflow".to_string())?;
    if decoded > MAX_DECODED_BYTES {
        return Err("sponsor media dimensions exceed limits".into());
    }
    Ok(())
}

fn client() -> Result<reqwest::blocking::Client, String> {
    let proxy = SPONSOR_PROXY
        .read()
        .clone()
        .ok_or_else(|| "sponsor network is unavailable without a connected tunnel".to_string())?;
    let proxy = reqwest::Proxy::all(&proxy).map_err(|e| format!("invalid sponsor tunnel proxy: {e}"))?;
    reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" {
                attempt.error("refusing non-HTTPS redirect")
            } else if attempt.previous().len() >= 3 {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .user_agent("FCAE-VPN sponsor client")
        .build()
        .map_err(|e| format!("cannot create sponsor tunnel client: {e}"))
}
