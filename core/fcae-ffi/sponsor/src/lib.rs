use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rodio::{Decoder as AudioDecoder, OutputStreamBuilder, Sink, Source};
use serde::Deserialize;
use yscv_video::Mp4VideoReader;
use std::{
    collections::HashSet,
    fs,
    io::{BufReader, Cursor, Read},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        Once,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/FCFlenkchy/FCAE_VPN/main/sponsors.json";
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
// Each foreground icon, optional background, or optional audio clip may use up
// to 15 MiB on disk. Decoded frame and aggregate budgets below still bound
// memory use.
const MAX_MEDIA_BYTES: usize = 15 * 1024 * 1024;
// One portable sponsor canvas keeps the manifest behavior identical on every
// platform and fits the Android card without requiring platform-specific assets.
const MAX_WIDTH: u32 = 800;
const MAX_HEIGHT: u32 = 450;
// MP4 frames may be larger than the portable sponsor canvas. Decode only a
// bounded source size, then downsample before retaining RGBA frames so a
// valid 16:9 960x540 campaign video is not rejected just because the card is
// capped at 800x450.
const MAX_VIDEO_SOURCE_WIDTH: u32 = 1920;
const MAX_VIDEO_SOURCE_HEIGHT: u32 = 1080;
const MAX_VIDEO_SOURCE_PIXELS: u64 =
    MAX_VIDEO_SOURCE_WIDTH as u64 * MAX_VIDEO_SOURCE_HEIGHT as u64;
// Video backgrounds are displayed in a 140-unit card. Retaining an 800x450
// frame for every animation step wastes memory and makes JNI/texture uploads
// expensive, especially on Android. Use a card-sized decode canvas while
// keeping the public background_scale for display composition.
#[cfg(target_os = "android")]
const VIDEO_MAX_WIDTH: u32 = 360;
#[cfg(target_os = "android")]
const VIDEO_MAX_HEIGHT: u32 = 202;
#[cfg(not(target_os = "android"))]
const VIDEO_MAX_WIDTH: u32 = 480;
#[cfg(not(target_os = "android"))]
const VIDEO_MAX_HEIGHT: u32 = 270;
// Decode enough source samples to cover normal short sponsor clips, but do not
// let a long or malicious MP4 turn startup into an unbounded decode.
const MAX_VIDEO_INPUT_FRAMES: usize = 300;
#[cfg(target_os = "android")]
const MAX_FRAMES: usize = 60;
#[cfg(not(target_os = "android"))]
const MAX_FRAMES: usize = 120;
#[cfg(target_os = "android")]
const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
// Allow both GIF demos to retain their background frames even when the same
// source asset is used by more than one campaign, while keeping a finite
// aggregate decoded-memory ceiling.
#[cfg(target_os = "android")]
const MAX_TOTAL_DECODED_BYTES: usize = 128 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_TOTAL_DECODED_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_TITLE_COLOR: u32 = 0xFFFFFFFF;
const DEFAULT_MESSAGE_COLOR: u32 = 0xFFD8E7FF;
const DEFAULT_CARD_COLOR: u32 = 0xFF142A44;
const DEFAULT_ICON_X: u8 = 50;
const DEFAULT_ICON_Y: u8 = 25;
const DEFAULT_TITLE_X: u8 = 50;
const DEFAULT_TITLE_Y: u8 = 50;
const DEFAULT_MESSAGE_X: u8 = 50;
const DEFAULT_MESSAGE_Y: u8 = 72;
const DEFAULT_ICON_SCALE: u32 = 100;
const DEFAULT_BACKGROUND_SCALE: u32 = 100;
const DEFAULT_DURATION_SECONDS: u32 = 10;
const MAX_DURATION_SECONDS: u32 = 3_600;
// Keep the current campaign visible for ten seconds before rotating.
const ROTATE_EVERY: Duration = Duration::from_secs(10);
// The manifest is checked at most once every twelve hours unless explicitly refreshed.
const MANIFEST_REFRESH_SECS: u64 = 12 * 60 * 60;

#[derive(Clone, Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    sponsors: Vec<Campaign>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct Campaign {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    icon_url: Option<String>,
    #[serde(default)]
    background_url: Option<String>,
    #[serde(default)]
    audio_url: Option<String>,
    #[serde(default)]
    title_color: Option<String>,
    #[serde(default)]
    message_color: Option<String>,
    #[serde(default)]
    background_color: Option<String>,
    #[serde(default)]
    title_x: Option<u32>,
    #[serde(default)]
    title_y: Option<u32>,
    #[serde(default)]
    message_x: Option<u32>,
    #[serde(default)]
    message_y: Option<u32>,
    #[serde(default)]
    image_fit: Option<String>,
    #[serde(default)]
    icon_scale: Option<u32>,
    #[serde(default)]
    background_scale: Option<u32>,
    #[serde(default)]
    icon_x: Option<u32>,
    #[serde(default)]
    icon_y: Option<u32>,
    #[serde(default)]
    duration_seconds: Option<u32>,
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
    background_frames: Vec<Frame>,
    background_width: u32,
    background_height: u32,
    background_rgba: Arc<Vec<u8>>,
    title_color: u32,
    message_color: u32,
    card_color: u32,
    icon_x: u8,
    icon_y: u8,
    duration_seconds: u32,
    title_x: u8,
    title_y: u8,
    message_x: u8,
    message_y: u8,
    image_fit: u8,
    icon_scale: u32,
    background_scale: u32,
}

struct MediaPayload {
    path: PathBuf,
    bytes: Vec<u8>,
    cached: bool,
    // If the current URL's cache entry is corrupt or a refresh fails, retain
    // the last valid entry for this campaign as a decoding fallback.
    fallback: Option<PathBuf>,
}

struct CampaignPayload {
    media: Option<MediaPayload>,
    background: Option<MediaPayload>,
    audio: Option<MediaPayload>,
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
    pub background_width: u32,
    pub background_height: u32,
    pub background_rgba: Arc<Vec<u8>>,
    pub title_color: u32,
    pub message_color: u32,
    pub card_color: u32,
    pub icon_x: u8,
    pub icon_y: u8,
    pub duration_seconds: u32,
    pub title_x: u8,
    pub title_y: u8,
    pub message_x: u8,
    pub message_y: u8,
    pub image_fit: u8,
    pub icon_scale: u32,
    pub background_scale: u32,
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
    // Prevent a failed media request from being retried once per UI poll;
    // successful publishing clears the backoff immediately.
    media_retry_after: Instant,
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
    media_retry_after: Instant::now(),
    last_error: String::new(),
}));
static CONNECTED: AtomicBool = AtomicBool::new(false);
static SPONSOR_PROXY: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
static CLIENT_CACHE: Lazy<Mutex<Option<(String, reqwest::blocking::Client)>>> =
    Lazy::new(|| Mutex::new(None));
static MANIFEST_BUSY: AtomicBool = AtomicBool::new(false);
static MANIFEST_FORCE_PENDING: AtomicBool = AtomicBool::new(false);
static MEDIA_BUSY: AtomicBool = AtomicBool::new(false);
// Sponsor audio is muted by default; the attached text control explicitly
// enables it and the setting lasts only for the running client process.
static AUDIO_ENABLED: AtomicBool = AtomicBool::new(false);
// Audio is allowed only while a client UI owns the sponsor card. Android
// toggles this from Activity onResume/onPause; desktop keeps it active while
// the ImGui window is rendering and clears it during shutdown.
static AUDIO_UI_ACTIVE: AtomicBool = AtomicBool::new(false);
static AUDIO_CONTROLLER: Lazy<Mutex<AudioController>> = Lazy::new(|| {
    Mutex::new(AudioController {
        sender: None,
        campaign_id: None,
    })
});
static GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "android")]
static ANDROID_CONTEXT_INIT: Once = Once::new();

/// CPAL's Android AAudio backend needs the JavaVM and a long-lived Android
/// Context when it is used from a JNI-loaded Rust static library. ndk-glue
/// normally fills this global, but this app owns its JVM entry point itself.
/// Keep the first application-context reference for the lifetime of the
/// process and make repeated Activity recreation calls harmless.
#[cfg(target_os = "android")]
pub fn initialize_android_context(
    java_vm: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
) -> bool {
    let mut initialized = false;
    ANDROID_CONTEXT_INIT.call_once(|| {
        // SAFETY: the JNI bridge passes a live JavaVM pointer and a global
        // reference to the application Context, both valid for this process.
        unsafe { ndk_context::initialize_android_context(java_vm, context); }
        initialized = true;
    });
    initialized
}

enum AudioCommand {
    Play { path: PathBuf },
    Stop,
}

// cpal's CoreAudio stream is intentionally kept on its owning thread: on
// macOS it contains a non-Send property-listener callback. The global state
// stores only an mpsc Sender, which is Send + Sync on every target.
struct AudioController {
    sender: Option<Sender<AudioCommand>>,
    campaign_id: Option<String>,
}

fn audio_requested() -> bool {
    AUDIO_ENABLED.load(Ordering::Acquire)
        && AUDIO_UI_ACTIVE.load(Ordering::Acquire)
}

fn audio_worker(receiver: Receiver<AudioCommand>) {
    // Open lazily on the first Play command. In particular, this happens
    // after the Android JNI bridge has initialized ndk-context, rather than
    // while the worker is being created during UI startup. The stream is
    // dropped on Stop so mute/backgrounding releases the output device too.
    let mut stream = None;
    let mut sink: Option<Sink> = None;
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(AudioCommand::Play { path }) => {
                // Muting or backgrounding can race a queued Play command.
                // Check before opening the file, then check again after the
                // potentially expensive decoder setup so muted audio is never
                // read/decoded or attached to an output sink.
                if !audio_requested() {
                    sink.take();
                    stream.take();
                    continue;
                }
                sink.take();
                let file = match fs::File::open(&path) {
                    Ok(file) => file,
                    Err(error) => {
                        log::warn!("[sponsor] audio cache open failed ({}): {error}", path.display());
                        continue;
                    }
                };
                let source = match AudioDecoder::try_from(BufReader::new(file)) {
                    Ok(source) => source,
                    Err(error) => {
                        log::warn!("[sponsor] audio decode failed ({}): {error}", path.display());
                        continue;
                    }
                };
                if !audio_requested() {
                    stream.take();
                    continue;
                }
                if stream.is_none() {
                    match OutputStreamBuilder::open_default_stream() {
                        Ok(output) => stream = Some(output),
                        Err(error) => {
                            log::warn!("[sponsor] audio output stream unavailable: {error}");
                            continue;
                        }
                    }
                }
                if !audio_requested() {
                    stream.take();
                    continue;
                }
                let Some(output) = stream.as_ref() else { continue; };
                let next_sink = Sink::connect_new(output.mixer());
                // A single source is attached once and repeats at the source
                // level, so it does not depend on UI polling cadence.
                next_sink.append(source.repeat_infinite());
                next_sink.play();
                sink = Some(next_sink);
                log::info!("[sponsor] playing looping cached audio {}", path.display());
            }
            Ok(AudioCommand::Stop) => {
                sink.take();
                // Release the platform output device as well. Mute therefore
                // leaves no decoder, sink, or audio device retained.
                stream.take();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn audio_sender(controller: &mut AudioController) -> Option<Sender<AudioCommand>> {
    if controller.sender.is_none() {
        let (sender, receiver) = mpsc::channel();
        if thread::Builder::new()
            .name("fcae-sponsor-audio".into())
            .spawn(move || audio_worker(receiver))
            .is_err()
        {
            return None;
        }
        controller.sender = Some(sender);
    }
    controller.sender.clone()
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn set_cache_dir(path: impl Into<PathBuf>) {
    let path = path.into();
    let _ = fs::create_dir_all(&path);
    STATE.lock().cache_dir = path;
    load_cached_manifest();
}

pub fn load_cached_manifest() {
    let cache_dir = STATE.lock().cache_dir.clone();
    let json = fs::read(cache_dir.join("manifest.json")).ok();
    let campaigns = json.as_deref().and_then(|body| parse_manifest(body).ok());
    let timestamp = fs::read_to_string(cache_dir.join("manifest.timestamp"))
        .ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(0);
    let checked_at = fs::read_to_string(cache_dir.join("manifest.check.timestamp"))
        .ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(timestamp);
    let now = unix_now();
    {
        let mut state = STATE.lock();
        state.manifest_checked_at = if campaigns.is_some()
            && checked_at <= now.saturating_add(300) {
            checked_at
        } else {
            0
        };
    }
    if let Some(campaigns) = campaigns {
        log::info!("[sponsor] loaded cached manifest ({} active campaigns)", campaigns.len());
        apply_campaigns(campaigns);
        // Rehydrate local media before publishing the first UI snapshot. This
        // never downloads, so a restart shows the cached GIF/image immediately
        // instead of briefly showing a text-only card.
        refresh_cached_media_sync();
    } else if json.is_some() {
        log::warn!("[sponsor] cached manifest is invalid; forcing a refresh");
    }
}

pub fn set_proxy(proxy: Option<String>) {
    *SPONSOR_PROXY.write() = proxy;
}

fn stop_audio() {
    let mut controller = AUDIO_CONTROLLER.lock();
    controller.campaign_id = None;
    if let Some(sender) = controller.sender.as_ref() {
        let _ = sender.send(AudioCommand::Stop);
    }
}

pub fn set_audio_enabled(enabled: bool) {
    AUDIO_ENABLED.store(enabled, Ordering::Release);
    if !enabled {
        stop_audio();
    } else if CONNECTED.load(Ordering::Acquire) {
        // Audio is deliberately lazy: enabling the card control is the first
        // point at which the current campaign's audio may be downloaded.
        refresh_media_async();
    } else {
        refresh_cached_media_async();
    }
}

pub fn audio_enabled() -> bool {
    AUDIO_ENABLED.load(Ordering::Acquire)
}

pub fn set_audio_ui_active(active: bool) {
    AUDIO_UI_ACTIVE.store(active, Ordering::Release);
    if !active {
        stop_audio();
    }
}

fn start_audio_for_campaign(campaign_id: &str) {
    if !audio_requested() {
        stop_audio();
        return;
    }
    let path = {
        let state = STATE.lock();
        let campaign = state.campaigns.iter().find(|campaign|
            campaign.id == campaign_id);
        campaign.and_then(|campaign| campaign.audio_url.as_ref().map(|_| {
            state.cache_dir.join(audio_cache_name(campaign))
        }))
    };
    let Some(path) = path.filter(|path| {
        path.is_file()
            && fs::metadata(path)
                .map(|metadata| metadata.len() <= MAX_MEDIA_BYTES as u64)
                .unwrap_or(false)
    }) else {
        stop_audio();
        return;
    };
    let mut controller = AUDIO_CONTROLLER.lock();
    // Start one looping sink per visible campaign. Do not replace it on every
    // polling tick; rotation or an explicit disable/re-enable starts it again.
    if controller.campaign_id.as_deref() == Some(campaign_id) {
        return;
    }
    let Some(sender) = audio_sender(&mut controller) else { return; };
    if sender.send(AudioCommand::Play { path }).is_err() {
        controller.sender = None;
        controller.campaign_id = None;
        return;
    }
    controller.campaign_id = Some(campaign_id.to_string());
}

pub fn set_connected(connected: bool) {
    let was = CONNECTED.swap(connected, Ordering::AcqRel);
    if !connected {
        // Disconnecting only disables network work. Keep the in-memory frame
        // and durable files; rehydrate local media if a refresh was in flight.
        if was { refresh_cached_media_async(); }
        return;
    }
    if !was {
        if manifest_due() {
            refresh_manifest_async();
        } else if media_needs_refresh() || audio_needs_refresh() {
            // A reconnect should not start another media pass when every
            // campaign already has the same usable decoded media. A pass is
            // still allowed when a URL changed or a campaign has no usable
            // cached frame/audio yet.
            refresh_media_async();
        }
    }
}

fn audio_needs_refresh() -> bool {
    if !audio_requested() { return false; }
    let state = STATE.lock();
    let Some(campaign) = state.campaigns.get(state.current_campaign) else {
        return false;
    };
    campaign.audio_url.is_some()
        && !cached_media_file_is_valid(&state.cache_dir.join(audio_cache_name(campaign)))
}

fn media_needs_refresh() -> bool {
    let state = STATE.lock();
    let Some(campaign) = state.campaigns.get(state.current_campaign) else {
        return false;
    };
    let Some(existing) = state.ready.iter().find(|ready|
        ready.campaign.id == campaign.id) else { return true; };
    (campaign.icon_url.is_some() && existing.frames.is_empty())
        || (campaign.background_url.is_some()
            && existing.background_frames.is_empty()
            && existing.background_rgba.is_empty())
}

pub fn manifest_refresh_remaining_secs() -> u64 {
    let checked_at = STATE.lock().manifest_checked_at;
    if checked_at == 0 { return 0; }
    let now = unix_now();
    if checked_at > now.saturating_add(300) { return 0; }
    MANIFEST_REFRESH_SECS.saturating_sub(now.saturating_sub(checked_at))
}

pub fn manifest_check_started() {
    let cache_dir = STATE.lock().cache_dir.clone();
    let _ = fs::create_dir_all(cache_dir);
}

pub fn manifest_due() -> bool {
    manifest_refresh_remaining_secs() == 0
}

pub fn set_manifest_json(json: &[u8]) -> Result<(), String> {
    let campaigns = parse_manifest(json)?;
    let active_count = campaigns.len();
    let now = unix_now();
    let selected_campaign_changed = apply_campaigns(campaigns);
    log::info!("[sponsor] accepted manifest ({} active campaigns)", active_count);
    let cache_dir = {
        let mut state = STATE.lock();
        state.manifest_checked_at = now;
        state.cache_dir.clone()
    };
    let _ = fs::create_dir_all(&cache_dir);
    let manifest_path = cache_dir.join("manifest.json");
    if write_atomic_preserving_old(&manifest_path, json) {
        let _ = fs::write(cache_dir.join("manifest.timestamp"), now.to_string());
        let _ = fs::write(cache_dir.join("manifest.check.timestamp"), now.to_string());
    }
    let media_needed = selected_campaign_changed
        || media_needs_refresh()
        || audio_needs_refresh();
    if media_needed && CONNECTED.load(Ordering::Acquire) {
        refresh_media_async();
    } else if media_needed {
        refresh_cached_media_async();
    }
    Ok(())
}

fn apply_campaigns(campaigns: Vec<Campaign>) -> bool {
    let mut state = STATE.lock();
    let previous_selected_id = state.campaigns.get(state.current_campaign)
        .map(|campaign| campaign.id.clone());
    let previous = std::mem::take(&mut state.ready);
    let mut ready = Vec::with_capacity(campaigns.len());

    for campaign in &campaigns {
        if let Some(existing) = previous.iter().find(|candidate| candidate.campaign.id == campaign.id) {
            // Keep the last usable foreground/background pixels for this
            // campaign while the new manifest version is being applied.
            ready.push(fallback_ready(existing, campaign));
        } else {
            // Stage a safe text fallback. Startup cache hydration replaces it
            // before the first snapshot; connected refreshes can replace it
            // asynchronously when a new asset is available.
            ready.push(empty_ready(campaign));
        }
    }

    let ready_count = ready.len();
    let cache_dir = state.cache_dir.clone();
    state.ready = ready;
    // A fresh cache load and every accepted manifest should start from a
    // random campaign. Media-only refreshes use publish_media() and preserve
    // the current campaign, so this does not cause animation jitter.
    state.current_campaign = if ready_count == 0 {
        0
    } else {
        (next_random(&mut state) as usize) % ready_count
    };
    let selected_campaign_id = campaigns.get(state.current_campaign)
        .map(|campaign| campaign.id.clone());
    let selected_campaign_changed = previous_selected_id != selected_campaign_id;
    state.campaigns = campaigns.clone();
    state.last_error.clear();
    state.media_retry_after = Instant::now();
    state.rotation_started = Instant::now();
    GENERATION.fetch_add(1, Ordering::Relaxed);
    drop(state);
    prune_cache(&cache_dir, &campaigns);
    selected_campaign_changed
}

pub fn refresh_manifest_async() {
    refresh_manifest_async_inner(false);
}

pub fn refresh_manifest_now_async() {
    refresh_manifest_async_inner(true);
}

fn refresh_manifest_async_inner(force: bool) {
    if !CONNECTED.load(Ordering::Acquire) || (!force && !manifest_due()) {
        return;
    }
    if MANIFEST_BUSY.swap(true, Ordering::AcqRel) {
        if force {
            MANIFEST_FORCE_PENDING.store(true, Ordering::Release);
            log::info!("[sponsor] queued explicit refresh behind the active fetch");
        }
        return;
    }
    thread::spawn(|| {
        match fetch_manifest() {
            Ok(json) => {
                log::info!("[sponsor] manifest response received ({} bytes)", json.len());
                if let Err(error) = set_manifest_json(&json) {
                    log::warn!("[sponsor] manifest rejected: {error}");
                    STATE.lock().last_error = error;
                }
            }
            Err(error) => {
                log::warn!("[sponsor] manifest fetch failed: {error}");
                STATE.lock().last_error = error;
                if CONNECTED.load(Ordering::Acquire) {
                    refresh_media_async();
                }
            }
        }
        MANIFEST_BUSY.store(false, Ordering::Release);
        if MANIFEST_FORCE_PENDING.swap(false, Ordering::AcqRel)
            && CONNECTED.load(Ordering::Acquire)
        {
            refresh_manifest_async_inner(true);
        }
    });
}

pub fn refresh_media_async() {
    refresh_media_async_inner(false);
}

fn merge_ready_media(previous: &[ReadyCampaign], ready: Vec<ReadyCampaign>) -> Vec<ReadyCampaign> {
    ready.into_iter().map(|mut candidate| {
        let Some(existing) = previous.iter().find(|ready| ready.campaign.id == candidate.campaign.id)
        else {
            return candidate;
        };
        // A prepared list may intentionally contain only the current target's
        // newly decoded planes. Retain the other campaign's last usable planes
        // at publication time as a second line of defense against a partial
        // refresh replacing the whole ready list with text-only cards.
        if candidate.campaign.icon_url.is_some()
            && candidate.frames.is_empty()
            && !existing.frames.is_empty()
        {
            candidate.width = existing.width;
            candidate.height = existing.height;
            candidate.frames = existing.frames.clone();
        }
        if candidate.campaign.background_url.is_some()
            && candidate.background_frames.is_empty()
            && candidate.background_rgba.is_empty()
            && (!existing.background_frames.is_empty() || !existing.background_rgba.is_empty())
        {
            candidate.background_width = existing.background_width;
            candidate.background_height = existing.background_height;
            candidate.background_frames = existing.background_frames.clone();
            candidate.background_rgba = existing.background_rgba.clone();
        }
        candidate
    }).collect()
}

fn publish_media(campaigns: &[Campaign], ready: Vec<ReadyCampaign>) -> bool {
    let mut state = STATE.lock();
    if state.campaigns.as_slice() != campaigns {
        return false;
    }
    let previous = state.ready.clone();
    state.ready = merge_ready_media(&previous, ready);
    let ready_count = state.ready.len();
    state.current_campaign = if ready_count == 0 {
        0
    } else {
        state.current_campaign % ready_count
    };
    let current_needs_media = state.ready.get(state.current_campaign)
        .map(|ready| ready_needs_media(ready, &state.cache_dir))
        .unwrap_or(false);
    if !current_needs_media {
        state.media_retry_after = Instant::now();
    }
    state.rotation_started = Instant::now();
    GENERATION.fetch_add(1, Ordering::Relaxed);
    true
}

fn refresh_cached_media_sync() {
    if MEDIA_BUSY.swap(true, Ordering::AcqRel) {
        return;
    }
    STATE.lock().media_retry_after = Instant::now() + Duration::from_secs(30);
    let (campaigns, cache_dir, previous, target_id) = {
        let state = STATE.lock();
        let target_id = state.campaigns.get(state.current_campaign)
            .map(|campaign| campaign.id.clone());
        (state.campaigns.clone(), state.cache_dir.clone(), state.ready.clone(), target_id)
    };
    let ready = prepare_media(
        &campaigns,
        &cache_dir,
        &previous,
        false,
        target_id.as_deref(),
    );
    let ready_count = ready.len();
    let applied = publish_media(&campaigns, ready);
    MEDIA_BUSY.store(false, Ordering::Release);
    if applied {
        log::info!("[sponsor] published synchronous cached media ({} active campaigns)", ready_count);
    }
}

fn refresh_cached_media_async() {
    refresh_media_async_inner(true);
}

fn refresh_media_async_inner(allow_disconnected: bool) {
    if (!allow_disconnected && !CONNECTED.load(Ordering::Acquire))
        || MEDIA_BUSY.swap(true, Ordering::AcqRel)
    {
        return;
    }
    STATE.lock().media_retry_after = Instant::now() + Duration::from_secs(30);
    let (campaigns, cache_dir, previous, target_id) = {
        let state = STATE.lock();
        let target_id = state.campaigns.get(state.current_campaign)
            .map(|campaign| campaign.id.clone());
        (state.campaigns.clone(), state.cache_dir.clone(), state.ready.clone(), target_id)
    };
    thread::spawn(move || {
        let ready = prepare_media(
            &campaigns,
            &cache_dir,
            &previous,
            !allow_disconnected,
            target_id.as_deref(),
        );
        let ready_count = ready.len();
        let connected = CONNECTED.load(Ordering::Acquire);
        let applied = if allow_disconnected || connected {
            publish_media(&campaigns, ready)
        } else {
            false
        };
        MEDIA_BUSY.store(false, Ordering::Release);
        if applied {
            log::info!("[sponsor] published media refresh ({} active campaigns)", ready_count);
            // If the offline pass finished after a reconnect, follow it with
            // one tunnel-backed pass so uncached media is downloaded too.
            if allow_disconnected && CONNECTED.load(Ordering::Acquire) {
                refresh_media_async();
            }
        } else if CONNECTED.load(Ordering::Acquire) {
            log::info!("[sponsor] discarded stale media refresh; scheduling another pass");
            refresh_media_async();
        } else if !allow_disconnected {
            // The tunnel may have closed while downloading. Rehydrate any
            // validated cache files without touching the network.
            refresh_cached_media_async();
        }
    });
}

fn next_random(state: &mut State) -> u64 {
    let mut value = state.random_state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    state.random_state = value;
    value
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
        let choice = next_random(state) as usize % (count - 1);
        if choice >= state.current_campaign { choice + 1 } else { choice }
    };
    state.rotation_started = Instant::now();
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub fn next_campaign() {
    let mut state = STATE.lock();
    advance_campaign(&mut state);
}

fn frame_index_at(frames: &[Frame], elapsed: Duration) -> usize {
    if frames.len() <= 1 { return 0; }
    // Use nanoseconds rather than truncating the cycle to milliseconds. The
    // modulo makes replay explicit and keeps short MP4/GIF delays from drifting
    // or getting stuck on the final frame after a long-running UI session.
    let cycle_nanos = frames.iter()
        .map(|frame| frame.delay.as_nanos())
        .fold(0u128, |sum, delay| sum.saturating_add(delay));
    if cycle_nanos == 0 { return 0; }
    let target = elapsed.as_nanos() % cycle_nanos;
    let mut cursor = 0u128;
    for (frame_index, frame) in frames.iter().enumerate() {
        cursor = cursor.saturating_add(frame.delay.as_nanos());
        if target < cursor { return frame_index; }
    }
    frames.len() - 1
}

fn cached_media_file_is_valid(path: &Path) -> bool {
    path.is_file()
        && fs::metadata(path)
            .map(|metadata| metadata.len() <= MAX_MEDIA_BYTES as u64)
            .unwrap_or(false)
}

fn ready_needs_media(ready: &ReadyCampaign, cache_dir: &Path) -> bool {
    (ready.campaign.icon_url.is_some() && ready.frames.is_empty())
        || (ready.campaign.background_url.is_some()
            && ready.background_frames.is_empty()
            && ready.background_rgba.is_empty())
        || (audio_requested()
            && ready.campaign.audio_url.is_some()
            && !cached_media_file_is_valid(&cache_dir.join(audio_cache_name(&ready.campaign))))
}

pub fn current_frame() -> Option<SponsorFrame> {
    let (frame, should_refresh) = {
        let mut state = STATE.lock();
        if state.ready.is_empty() {
            drop(state);
            stop_audio();
            return None;
        }
        let current_duration = state.ready.get(state.current_campaign)
            .map(|campaign| campaign.duration_seconds)
            .filter(|duration| *duration > 0)
            .unwrap_or(DEFAULT_DURATION_SECONDS);
        if state.ready.len() > 1
            && state.rotation_started.elapsed() >= Duration::from_secs(current_duration as u64)
        {
            advance_campaign(&mut state);
        }
        let ready_count = state.ready.len();
        state.current_campaign %= ready_count;
        let campaign_index = state.current_campaign;
        let within = state.rotation_started.elapsed();
        let needs_media = ready_needs_media(
            &state.ready[campaign_index],
            &state.cache_dir,
        );
        let should_refresh = needs_media && Instant::now() >= state.media_retry_after;
        if should_refresh {
            state.media_retry_after = Instant::now() + Duration::from_secs(30);
        }
        let ready = &state.ready[campaign_index];
        let frame_index = frame_index_at(&ready.frames, within);
        let background_frame_index = frame_index_at(&ready.background_frames, within);
        let rgba = ready.frames.get(frame_index)
            .map(|frame| frame.rgba.clone())
            .unwrap_or_default();
        let background_rgba = ready.background_frames.get(background_frame_index)
            .map(|frame| frame.rgba.clone())
            .unwrap_or_else(|| ready.background_rgba.clone());
        // Keep the animation planes independently identifiable across FFI:
        // published campaign metadata is above bit 24, foreground frame index
        // occupies bits 12..23, and background frame index occupies 0..11.
        // Android and desktop can therefore avoid copying an unchanged icon
        // while a video/GIF background advances.
        let generation = (GENERATION.load(Ordering::Relaxed) << 32)
            ^ ((campaign_index as u64) << 24)
            ^ ((frame_index as u64) << 12)
            ^ background_frame_index as u64;
        (SponsorFrame {
            id: ready.campaign.id.clone(),
            title: ready.campaign.title.clone(),
            message: ready.campaign.message.clone().unwrap_or_default(),
            destination_url: ready.campaign.destination_url.clone(),
            width: ready.width,
            height: ready.height,
            campaign_count: ready_count.try_into().unwrap_or(u32::MAX),
            animated: ready.frames.len() > 1 || ready.background_frames.len() > 1,
            rgba,
            background_width: ready.background_width,
            background_height: ready.background_height,
            background_rgba,
            title_color: ready.title_color,
            message_color: ready.message_color,
            card_color: ready.card_color,
            icon_x: ready.icon_x,
            icon_y: ready.icon_y,
            duration_seconds: ready.duration_seconds,
            title_x: ready.title_x,
            title_y: ready.title_y,
            message_x: ready.message_x,
            message_y: ready.message_y,
            image_fit: ready.image_fit,
            icon_scale: ready.icon_scale,
            background_scale: ready.background_scale,
            generation,
        }, should_refresh)
    };

    if should_refresh {
        if CONNECTED.load(Ordering::Acquire) {
            refresh_media_async();
        } else {
            refresh_cached_media_async();
        }
    }
    start_audio_for_campaign(&frame.id);
    Some(frame)
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
    if manifest.sponsors.len() > 32 { return Err("too many sponsor campaigns".into()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut ids = HashSet::with_capacity(manifest.sponsors.len());
    let mut valid = Vec::with_capacity(manifest.sponsors.len());
    for campaign in manifest.sponsors {
        validate_campaign(&campaign)?;
        if !ids.insert(campaign.id.clone()) { return Err("duplicate sponsor id".into()); }
        if campaign.enabled
            && campaign.starts_at.map_or(true, |start| now >= start)
            && campaign.ends_at.map_or(true, |end| now <= end)
        {
            let mut campaign = campaign;
            if campaign.message.as_ref().is_some_and(|message| !valid_message(message)) {
                log::warn!("[sponsor] campaign {} has invalid optional message; using title only", campaign.id);
                campaign.message = None;
            }
            if campaign.icon_url.as_ref().is_some_and(|url| !valid_icon_url(url)) {
                log::warn!("[sponsor] campaign {} has invalid optional icon URL; using text fallback", campaign.id);
                campaign.icon_url = None;
            }
            if campaign.background_url.as_ref().is_some_and(|url| !valid_icon_url(url)) {
                log::warn!("[sponsor] campaign {} has invalid optional background URL; using the card color", campaign.id);
                campaign.background_url = None;
            }
            if campaign.audio_url.as_ref().is_some_and(|url| !valid_audio_url(url)) {
                log::warn!("[sponsor] campaign {} has invalid optional audio URL; audio disabled", campaign.id);
                campaign.audio_url = None;
            }
            if campaign.title_color.as_ref().is_some_and(|color| !valid_color(color)) {
                log::warn!("[sponsor] campaign {} has invalid title color; using the default", campaign.id);
                campaign.title_color = None;
            }
            if campaign.message_color.as_ref().is_some_and(|color| !valid_color(color)) {
                log::warn!("[sponsor] campaign {} has invalid message color; using the default", campaign.id);
                campaign.message_color = None;
            }
            if campaign.background_color.as_ref().is_some_and(|color| !valid_color(color)) {
                log::warn!("[sponsor] campaign {} has invalid background color; using the default", campaign.id);
                campaign.background_color = None;
            }
            for (name, position) in [
                ("title X", &mut campaign.title_x),
                ("title Y", &mut campaign.title_y),
                ("message X", &mut campaign.message_x),
                ("message Y", &mut campaign.message_y),
                ("icon X", &mut campaign.icon_x),
                ("icon Y", &mut campaign.icon_y),
            ] {
                if position.as_ref().is_some_and(|value| *value > 100) {
                    log::warn!("[sponsor] campaign {} has invalid {name} position; using the default", campaign.id);
                    *position = None;
                }
            }
            if campaign.image_fit.as_ref().is_some_and(|fit| !valid_image_fit(fit)) {
                log::warn!("[sponsor] campaign {} has invalid image fit; using contain", campaign.id);
                campaign.image_fit = None;
            }
            if campaign.icon_scale.is_some_and(|scale| !(50..=160).contains(&scale)) {
                log::warn!("[sponsor] campaign {} has invalid icon scale; using 100 percent", campaign.id);
                campaign.icon_scale = None;
            }
            if campaign.background_scale.is_some_and(|scale| !(50..=160).contains(&scale)) {
                log::warn!("[sponsor] campaign {} has invalid background scale; using 100 percent", campaign.id);
                campaign.background_scale = None;
            }
            if campaign.duration_seconds.is_some_and(|duration|
                !(1..=MAX_DURATION_SECONDS).contains(&duration))
            {
                log::warn!("[sponsor] campaign {} has invalid duration; using 10 seconds", campaign.id);
                campaign.duration_seconds = None;
            }
            valid.push(campaign);
        }
    }
    Ok(valid)
}

fn validate_campaign(c: &Campaign) -> Result<(), String> {
    if c.id.is_empty() || c.id.len() > 64 || !c.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("invalid sponsor id".into());
    }
    // A campaign may be media-only. An omitted or empty title is valid as
    // long as a supplied title remains within the printable-text limit.
    if c.title.len() > 96
        || !c.title.chars().all(|character| !character.is_control())
    {
        return Err("sponsor title must use printable text".into());
    }
    if c.destination_url.len() > 511 || !c.destination_url.is_ascii()
        || !is_https(&c.destination_url)
    {
        return Err("invalid sponsor destination HTTPS URL".into());
    }
    if matches!((c.starts_at, c.ends_at), (Some(start), Some(end)) if start >= end) {
        return Err("invalid sponsor date range".into());
    }
    Ok(())
}

fn valid_message(message: &str) -> bool {
    message.len() <= 256
        && message.chars().all(|character| character == '\n' || !character.is_control())
}

fn valid_icon_url(url: &str) -> bool {
    !url.is_empty() && url.len() <= 2_048 && url.is_ascii() && is_https(url)
}

fn valid_audio_url(url: &str) -> bool {
    !url.is_empty() && url.len() <= 2_048 && url.is_ascii() && is_https(url)
}

fn valid_color(color: &str) -> bool {
    (color.len() == 7 || color.len() == 9)
        && color.as_bytes().first() == Some(&b'#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn color_value(color: Option<&str>, default: u32) -> u32 {
    let Some(color) = color.filter(|color| valid_color(color)) else { return default; };
    let value = u32::from_str_radix(&color[1..], 16).unwrap_or(0);
    if color.len() == 7 { 0xFF00_0000 | value } else { value }
}

fn position_value(value: Option<u32>, default: u8) -> u8 {
    value.filter(|position| *position <= 100).unwrap_or(default as u32) as u8
}

fn image_fit_value(value: Option<&str>) -> u8 {
    if value == Some("cover") { 1 } else { 0 }
}

fn media_scale_value(value: Option<u32>, default: u32) -> u32 {
    value.filter(|scale| (50..=160).contains(scale)).unwrap_or(default)
}

fn valid_image_fit(value: &str) -> bool {
    matches!(value, "contain" | "cover")
}

fn is_https(url: &str) -> bool {
    url.starts_with("https://") && !url.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0'))
}

fn empty_ready(campaign: &Campaign) -> ReadyCampaign {
    ReadyCampaign {
        campaign: campaign.clone(),
        width: 0,
        height: 0,
        frames: Vec::new(),
        background_frames: Vec::new(),
        background_width: 0,
        background_height: 0,
        background_rgba: Arc::new(Vec::new()),
        title_color: color_value(campaign.title_color.as_deref(), DEFAULT_TITLE_COLOR),
        message_color: color_value(campaign.message_color.as_deref(), DEFAULT_MESSAGE_COLOR),
        card_color: color_value(campaign.background_color.as_deref(), DEFAULT_CARD_COLOR),
        icon_x: position_value(campaign.icon_x, DEFAULT_ICON_X),
        icon_y: position_value(campaign.icon_y, DEFAULT_ICON_Y),
        duration_seconds: campaign.duration_seconds
            .filter(|duration| (1..=MAX_DURATION_SECONDS).contains(duration))
            .unwrap_or(DEFAULT_DURATION_SECONDS),
        title_x: position_value(campaign.title_x, DEFAULT_TITLE_X),
        title_y: position_value(campaign.title_y, DEFAULT_TITLE_Y),
        message_x: position_value(campaign.message_x, DEFAULT_MESSAGE_X),
        message_y: position_value(campaign.message_y, DEFAULT_MESSAGE_Y),
        image_fit: image_fit_value(campaign.image_fit.as_deref()),
        icon_scale: media_scale_value(campaign.icon_scale, DEFAULT_ICON_SCALE),
        background_scale: media_scale_value(campaign.background_scale, DEFAULT_BACKGROUND_SCALE),
    }
}

fn fallback_ready(previous: &ReadyCampaign, campaign: &Campaign) -> ReadyCampaign {
    let mut fallback = empty_ready(campaign);
    if campaign.icon_url.is_some() && !previous.frames.is_empty() {
        fallback.width = previous.width;
        fallback.height = previous.height;
        fallback.frames = previous.frames.clone();
    }
    if campaign.background_url.is_some()
        && (!previous.background_frames.is_empty() || !previous.background_rgba.is_empty())
    {
        fallback.background_width = previous.background_width;
        fallback.background_height = previous.background_height;
        fallback.background_frames = previous.background_frames.clone();
        fallback.background_rgba = previous.background_rgba.clone();
        if fallback.background_frames.is_empty() && !fallback.background_rgba.is_empty() {
            fallback.background_frames.push(Frame {
                rgba: fallback.background_rgba.clone(),
                delay: ROTATE_EVERY,
            });
        }
    }
    fallback
}

fn prune_cache(cache_dir: &Path, campaigns: &[Campaign]) {
    let _ = fs::create_dir_all(cache_dir);
    // Keep the current URL and one previous version for each active campaign.
    // A changed URL gets a new entry while the old entry remains available as
    // a bounded fallback if the new download fails.
    let active_prefixes: Vec<String> = campaigns.iter()
        .map(|campaign| format!("{}-", campaign.id))
        .collect();
    if let Ok(entries) = fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let media_cache = name.ends_with(".media")
                || name.ends_with(".background")
                || name.ends_with(".audio")
                || name.ends_with(".decoded");
            let belongs_to_active_campaign = active_prefixes.iter()
                .any(|prefix| name.starts_with(prefix));
            if media_cache && !belongs_to_active_campaign {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    for campaign in campaigns {
        for (suffix, current_name) in [
            ("media", campaign.icon_url.as_ref().map(|_| cache_name(campaign))),
            ("background", campaign.background_url.as_ref().map(|_| background_cache_name(campaign))),
            ("audio", campaign.audio_url.as_ref().map(|_| audio_cache_name(campaign))),
        ] {
            let prefix = format!("{}-", campaign.id);
            let mut candidates = Vec::new();
            if let Ok(entries) = fs::read_dir(cache_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with(&prefix) && name.ends_with(&format!(".{suffix}")) {
                        candidates.push(path);
                    }
                }
            }
            candidates.sort_by_key(|path| {
                fs::metadata(path).and_then(|metadata| metadata.modified())
                    .unwrap_or(UNIX_EPOCH)
            });
            candidates.reverse();
            let mut kept_fallback = false;
            for path in candidates {
                let is_current = current_name.as_ref().map_or(false, |name|
                    path.file_name().and_then(|value| value.to_str()) == Some(name.as_str()));
                if is_current {
                    continue;
                }
                if current_name.is_some() && !kept_fallback {
                    kept_fallback = true;
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}

fn prepare_media(
    campaigns: &[Campaign],
    cache_dir: &Path,
    previous: &[ReadyCampaign],
    allow_network: bool,
    target_id: Option<&str>,
) -> Vec<ReadyCampaign> {
    let network_client = (allow_network
        && CONNECTED.load(Ordering::Acquire)
        && campaigns.iter().any(|campaign| {
        campaign.icon_url.is_some()
            || campaign.background_url.is_some()
            || (audio_requested() && campaign.audio_url.is_some())
    })).then(|| client().ok()).flatten();

    // Decode and cache only the campaign that is currently visible. Inactive
    // campaigns stay lightweight until rotation reaches them; this prevents a
    // manifest refresh from blocking the first useful frame on unrelated
    // downloads while preserving every existing encoded/decoded cache entry.
    let mut ready = Vec::with_capacity(campaigns.len());
    let mut decoded_total = 0usize;
    for campaign in campaigns {
        let is_target = target_id == Some(campaign.id.as_str());
        let previous = previous.iter().find(|existing|
            existing.campaign.id == campaign.id);
        // Preserve every previously decoded campaign while refreshing one
        // target. A manifest refresh must not turn the other cards into
        // text-only placeholders just because their duplicate/shared asset
        // URLs were not decoded in this pass; the old pixels remain a valid
        // fallback until that campaign is visited and its new media is ready.
        let mut candidate = previous
            .map_or_else(|| empty_ready(campaign), |existing| fallback_ready(existing, campaign));

        if is_target {
            let payload = load_campaign_payload(
                campaign,
                cache_dir,
                false,
                false,
                audio_requested(),
                network_client.as_ref(),
            );
            let (media, background, _audio) = match payload {
                Some(payload) => (
                    payload.media.and_then(|payload| {
                        let url = campaign.icon_url.as_deref()?;
                        decode_media(campaign, url, payload, network_client.as_ref())
                    }),
                    payload.background.and_then(|payload| {
                        let url = campaign.background_url.as_deref()?;
                        decode_background(campaign, url, payload, network_client.as_ref())
                    }),
                    payload.audio,
                ),
                None => (None, None, None),
            };
            let media_loaded = media.is_some();
            let background_loaded = background.is_some();
            if campaign.icon_url.is_some() && !media_loaded && candidate.frames.is_empty() {
                log::warn!("[sponsor] campaign {} icon unavailable; using fallback", campaign.id);
            }
            if campaign.background_url.is_some() && !background_loaded
                    && candidate.background_frames.is_empty()
                    && candidate.background_rgba.is_empty() {
                log::warn!("[sponsor] campaign {} background unavailable; using card color", campaign.id);
            }
            if media_loaded || background_loaded {
                log::info!("[sponsor] campaign {} media ready (decoded on demand)", campaign.id);
            }
            if let Some(media) = media {
                candidate.width = media.width;
                candidate.height = media.height;
                candidate.frames = media.frames;
            }
            if let Some(background) = background {
                candidate.background_width = background.width;
                candidate.background_height = background.height;
                candidate.background_frames = background.frames;
                candidate.background_rgba = candidate.background_frames.first()
                    .map(|frame| frame.rgba.clone())
                    .unwrap_or_default();
            }
        }

        let media_bytes = candidate.frames.iter().map(|frame| frame.rgba.len()).sum::<usize>();
        let background_bytes = candidate.background_frames.iter()
            .map(|frame| frame.rgba.len()).sum::<usize>();
        if decoded_total.saturating_add(media_bytes).saturating_add(background_bytes)
            > MAX_TOTAL_DECODED_BYTES
        {
            if background_bytes != 0 {
                log::warn!("[sponsor] campaign {} background exceeds the decoded-size budget; using card color", campaign.id);
                candidate.background_frames.clear();
                candidate.background_width = 0;
                candidate.background_height = 0;
                candidate.background_rgba = Arc::new(Vec::new());
            }
        }
        let retained_bytes = candidate.frames.iter().map(|frame| frame.rgba.len()).sum::<usize>()
            + candidate.background_frames.iter().map(|frame| frame.rgba.len()).sum::<usize>();
        if decoded_total.saturating_add(retained_bytes) <= MAX_TOTAL_DECODED_BYTES {
            decoded_total += retained_bytes;
            ready.push(candidate);
        } else {
            log::warn!("[sponsor] campaign {} media exceeds the decoded-size budget; using text fallback", campaign.id);
            ready.push(empty_ready(campaign));
        }
    }
    ready
}

fn load_campaign_payload(
    campaign: &Campaign,
    cache_dir: &Path,
    reuse_media: bool,
    reuse_background: bool,
    load_audio: bool,
    client: Option<&reqwest::blocking::Client>,
) -> Option<CampaignPayload> {
    let media = (!reuse_media).then(|| load_payload(
        campaign.icon_url.as_deref(),
        cache_dir.join(cache_name(campaign)),
        cache_dir,
        &campaign.id,
        "media",
        client,
    )).flatten();
    let background = (!reuse_background).then(|| load_payload(
        campaign.background_url.as_deref(),
        cache_dir.join(background_cache_name(campaign)),
        cache_dir,
        &campaign.id,
        "background",
        client,
    )).flatten();
    let audio = (load_audio && audio_requested()).then(|| load_payload(
        campaign.audio_url.as_deref(),
        cache_dir.join(audio_cache_name(campaign)),
        cache_dir,
        &campaign.id,
        "audio",
        client,
    )).flatten();
    if media.is_none() && background.is_none() && audio.is_none() {
        None
    } else {
        Some(CampaignPayload { media, background, audio })
    }
}

fn find_cached_payload(
    cache_dir: &Path,
    campaign_id: &str,
    suffix: &str,
    exclude: &Path,
) -> Option<PathBuf> {
    let prefix = format!("{}-", campaign_id);
    fs::read_dir(cache_dir).ok()?.flatten().find_map(|entry| {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.as_path() == exclude
            || !name.starts_with(&prefix)
            || !name.ends_with(&format!(".{suffix}"))
        {
            return None;
        }
        Some(path)
    })
}

fn write_atomic_preserving_old(path: &Path, bytes: &[u8]) -> bool {
    let Some(parent) = path.parent() else { return false; };
    if fs::create_dir_all(parent).is_err() { return false; }
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("media");
    let tmp = parent.join(format!(".{filename}.download.tmp"));
    if fs::write(&tmp, bytes).is_err() { return false; }
    if fs::rename(&tmp, path).is_ok() { return true; }

    // Windows cannot rename over an existing file. Move the old valid entry
    // aside only after the new bytes are safely on disk, and restore it if the
    // replacement fails. The temporary names include the complete cache
    // filename so concurrent media/decoded writes cannot collide.
    let backup = parent.join(format!(".{filename}.previous.tmp"));
    let had_old = path.exists() && fs::rename(path, &backup).is_ok();
    let replaced = fs::rename(&tmp, path).is_ok();
    if replaced {
        if had_old { let _ = fs::remove_file(backup); }
        true
    } else {
        if had_old { let _ = fs::rename(backup, path); }
        let _ = fs::remove_file(&tmp);
        false
    }
}

fn load_payload(
    url: Option<&str>,
    path: PathBuf,
    cache_dir: &Path,
    campaign_id: &str,
    suffix: &str,
    client: Option<&reqwest::blocking::Client>,
) -> Option<MediaPayload> {
    let url = url?;
    let _ = fs::create_dir_all(cache_dir);
    let fallback = find_cached_payload(cache_dir, campaign_id, suffix, &path);
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() <= MAX_MEDIA_BYTES {
            return Some(MediaPayload { path, bytes, cached: true, fallback });
        }
        log::warn!("[sponsor] ignoring oversized cached {} media: {} bytes", suffix, bytes.len());
        let _ = fs::remove_file(&path);
    }
    if CONNECTED.load(Ordering::Acquire) {
        if let Some(client) = client {
            if let Ok(bytes) = download_media(client, url) {
                // Persist the original bytes before decoding. A disconnect or
                // process exit during GIF frame expansion must not lose a valid
                // download; decode_payload removes it later only if invalid.
                let cached = write_atomic_preserving_old(&path, &bytes);
                return Some(MediaPayload { path, bytes, cached, fallback });
            }
        }
    }
    fallback.and_then(|path| {
        let bytes = fs::read(&path).ok()?;
        if bytes.len() > MAX_MEDIA_BYTES {
            log::warn!("[sponsor] ignoring oversized fallback {} media: {} bytes", suffix, bytes.len());
            return None;
        }
        Some(MediaPayload {
            path,
            bytes,
            cached: true,
            fallback: None,
        })
    })
}

fn decoded_cache_path(path: &Path) -> PathBuf {
    path.with_extension("decoded")
}

fn decoded_ready_from_cache(campaign: &Campaign, path: &Path) -> Option<ReadyCampaign> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() > MAX_DECODED_BYTES.saturating_add(MAX_FRAMES * 8 + 32)
        || bytes.len() < 16
        // FDV2 invalidates the old 800x450 video cache after the bounded
        // video decode canvas changed; stale large frames would defeat the
        // rendering-performance fix.
        || &bytes[0..4] != b"FDV2"
    {
        let _ = fs::remove_file(path);
        return None;
    }
    let mut cursor = Cursor::new(&bytes[4..]);
    let width = read_u32(&mut cursor)?;
    let height = read_u32(&mut cursor)?;
    let frame_count = read_u32(&mut cursor)? as usize;
    if frame_count == 0 || frame_count > MAX_FRAMES
        || validate_dimensions(width, height, frame_count).is_err()
    {
        let _ = fs::remove_file(path);
        return None;
    }
    let frame_bytes = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
    let mut frames = Vec::with_capacity(frame_count);
    let mut decoded_total = 0usize;
    for _ in 0..frame_count {
        let delay = read_u32(&mut cursor)?.clamp(20, 10_000);
        let size = read_u32(&mut cursor)? as usize;
        if size != frame_bytes || decoded_total.checked_add(size)? > MAX_DECODED_BYTES {
            let _ = fs::remove_file(path);
            return None;
        }
        let mut rgba = vec![0u8; size];
        cursor.read_exact(&mut rgba).ok()?;
        decoded_total += size;
        frames.push(Frame { rgba: Arc::new(rgba), delay: Duration::from_millis(delay as u64) });
    }
    Some(ReadyCampaign {
        campaign: campaign.clone(),
        width,
        height,
        frames,
        background_frames: Vec::new(),
        background_width: 0,
        background_height: 0,
        background_rgba: Arc::new(Vec::new()),
        title_color: DEFAULT_TITLE_COLOR,
        message_color: DEFAULT_MESSAGE_COLOR,
        card_color: DEFAULT_CARD_COLOR,
        icon_x: DEFAULT_ICON_X,
        icon_y: DEFAULT_ICON_Y,
        duration_seconds: DEFAULT_DURATION_SECONDS,
        title_x: DEFAULT_TITLE_X,
        title_y: DEFAULT_TITLE_Y,
        message_x: DEFAULT_MESSAGE_X,
        message_y: DEFAULT_MESSAGE_Y,
        image_fit: 0,
        icon_scale: DEFAULT_ICON_SCALE,
        background_scale: DEFAULT_BACKGROUND_SCALE,
    })
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn write_decoded_cache(path: &Path, decoded: &ReadyCampaign) {
    let frame_bytes = decoded.frames.iter()
        .map(|frame| frame.rgba.len())
        .sum::<usize>();
    if decoded.frames.is_empty() || decoded.frames.len() > MAX_FRAMES
        || frame_bytes > MAX_DECODED_BYTES
    {
        return;
    }
    let mut bytes = Vec::with_capacity(16 + frame_bytes + decoded.frames.len() * 8);
    bytes.extend_from_slice(b"FDV2");
    bytes.extend_from_slice(&decoded.width.to_le_bytes());
    bytes.extend_from_slice(&decoded.height.to_le_bytes());
    bytes.extend_from_slice(&(decoded.frames.len() as u32).to_le_bytes());
    for frame in &decoded.frames {
        bytes.extend_from_slice(&(frame.delay.as_millis() as u32).clamp(20, 10_000).to_le_bytes());
        bytes.extend_from_slice(&(frame.rgba.len() as u32).to_le_bytes());
        bytes.extend_from_slice(frame.rgba.as_slice());
    }
    let _ = write_atomic_preserving_old(path, &bytes);
}

fn decode_payload(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
) -> Option<ReadyCampaign> {
    let MediaPayload { path, mut bytes, mut cached, fallback } = payload;
    let decoded_path = decoded_cache_path(&path);
    if let Some(decoded) = decoded_ready_from_cache(campaign, &decoded_path) {
        return Some(decoded);
    }
    let mut decoded = decode(campaign.clone(), &bytes).ok();
    if decoded.is_none() {
        if let Some(fallback_path) = fallback {
            if let Ok(fallback_bytes) = fs::read(&fallback_path) {
                if let Some(fallback_decoded) = decode(campaign.clone(), &fallback_bytes).ok() {
                    if cached { let _ = fs::remove_file(&path); }
                    return Some(fallback_decoded);
                }
            }
            // Preserve the previous encoded entry even when this refresh
            // cannot decode it; it is still the campaign's last fallback.
        }
        if cached {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&decoded_path);
        }
        if !CONNECTED.load(Ordering::Acquire) { return None; }
        let client = client?;
        bytes = download_media(client, url).ok()?;
        cached = false;
        decoded = decode(campaign.clone(), &bytes).ok();
    }
    if let Some(decoded) = decoded {
        if !cached { let _ = write_atomic_preserving_old(&path, &bytes); }
        write_decoded_cache(&decoded_path, &decoded);
        Some(decoded)
    } else {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(decoded_path);
        None
    }
}

fn decode_media(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
) -> Option<ReadyCampaign> {
    if image::guess_format(&payload.bytes).is_ok() {
        decode_payload(campaign, url, payload, client)
    } else {
        decode_video_payload(campaign, url, payload, client)
    }
}

fn decode_video_payload(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
) -> Option<ReadyCampaign> {
    let MediaPayload { path, bytes, cached, fallback } = payload;
    let decoded_path = decoded_cache_path(&path);
    if let Some(decoded) = decoded_ready_from_cache(campaign, &decoded_path) {
        return Some(decoded);
    }

    // Video readers operate on a bounded file path. The encoded cache is
    // written before this function in the normal path; retry the write when a
    // platform could not atomically install a newly downloaded file.
    if !path.exists() && !write_atomic_preserving_old(&path, &bytes) {
        return None;
    }
    let mut decoded = match decode_video_file(campaign.clone(), &path) {
        Ok(decoded) => Some(decoded),
        Err(error) => {
            log::warn!("[sponsor] video decode failed ({}): {error}", path.display());
            None
        }
    };
    if decoded.is_none() {
        if let Some(fallback_path) = fallback {
            decoded = match decode_video_file(campaign.clone(), &fallback_path) {
                Ok(decoded) => Some(decoded),
                Err(error) => {
                    log::warn!(
                        "[sponsor] cached video fallback decode failed ({}): {error}",
                        fallback_path.display()
                    );
                    None
                }
            };
            if decoded.is_some() {
                return decoded;
            }
            // Preserve the previous encoded entry even when this refresh
            // cannot decode it; it is still the campaign's last fallback.
        }
        if cached {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&decoded_path);
        }
        if !CONNECTED.load(Ordering::Acquire) {
            return None;
        }
        let client = client?;
        let fresh = download_media(client, url).ok()?;
        if !write_atomic_preserving_old(&path, &fresh) {
            return None;
        }
        decoded = match decode_video_file(campaign.clone(), &path) {
            Ok(decoded) => Some(decoded),
            Err(error) => {
                log::warn!("[sponsor] refreshed video decode failed ({}): {error}", path.display());
                None
            }
        };
    }
    if let Some(decoded) = decoded {
        write_decoded_cache(&decoded_path, &decoded);
        Some(decoded)
    } else {
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&decoded_path);
        None
    }
}

fn validate_video_source_dimensions(width: u32, height: u32) -> Result<(), String> {
    if width == 0 || height == 0
        || width > MAX_VIDEO_SOURCE_WIDTH
        || height > MAX_VIDEO_SOURCE_HEIGHT
        || (width as u64).saturating_mul(height as u64) > MAX_VIDEO_SOURCE_PIXELS
    {
        return Err("video source dimensions exceed limits".into());
    }
    Ok(())
}

fn bounded_video_rgb(
    width: u32,
    height: u32,
    rgb: Vec<u8>,
) -> Result<(u32, u32, Vec<u8>), String> {
    validate_video_source_dimensions(width, height)?;
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or_else(|| "video frame dimensions overflow".to_string())?;
    if rgb.len() != expected {
        return Err("unexpected video RGB frame size".into());
    }

    let scale = (VIDEO_MAX_WIDTH as f64 / width as f64)
        .min(VIDEO_MAX_HEIGHT as f64 / height as f64)
        .min(1.0);
    let target_width = ((width as f64 * scale).round() as u32).max(1);
    let target_height = ((height as f64 * scale).round() as u32).max(1);
    if target_width == width && target_height == height {
        return Ok((width, height, rgb));
    }

    let image = image::RgbImage::from_raw(width, height, rgb)
        .ok_or_else(|| "video RGB frame could not be constructed".to_string())?;
    let resized = image::imageops::resize(
        &image,
        target_width,
        target_height,
        image::imageops::FilterType::Triangle,
    );
    Ok((target_width, target_height, resized.into_raw()))
}

fn compact_video_frames(frames: &mut Vec<Frame>, total_bytes: &mut usize) {
    if frames.len() < 2 {
        return;
    }
    // Move the vector out before iterating so the iterator does not retain a
    // Drain borrow while the compacted vector is installed back into `frames`.
    let old_frames = std::mem::take(frames);
    let mut compacted = Vec::with_capacity((old_frames.len() + 1) / 2);
    let mut iter = old_frames.into_iter();
    while let Some(mut kept) = iter.next() {
        if let Some(dropped) = iter.next() {
            // Keeping the first frame of each pair and adding the dropped
            // frame's display time preserves the original video duration.
            kept.delay = kept.delay.saturating_add(dropped.delay);
        }
        compacted.push(kept);
    }
    *total_bytes = compacted.iter().map(|frame| frame.rgba.len()).sum();
    *frames = compacted;
}

fn decode_video_file(campaign: Campaign, path: &Path) -> Result<ReadyCampaign, String> {
    // MP4 is the portable sponsor-video format. The reader is pure Rust and
    // does not require FFmpeg or a platform media framework.
    let mut reader = Mp4VideoReader::open(path).map_err(|error| error.to_string())?;
    let mut frames = Vec::new();
    let mut total_bytes = 0usize;
    let mut previous_timestamp = None;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut source_frames = 0usize;

    while source_frames < MAX_VIDEO_INPUT_FRAMES {
        let frame = match reader.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) if !frames.is_empty() => {
                // A damaged trailing sample must not discard already decoded
                // frames. Keep the usable prefix and let the card animate it;
                // the encoded entry remains cached for a later retry.
                log::warn!(
                    "[sponsor] video decode stopped after {} frames ({}): {}",
                    frames.len(),
                    path.display(),
                    error,
                );
                break;
            }
            Err(error) => return Err(error.to_string()),
        };
        source_frames += 1;
        let frame_width = u32::try_from(frame.width)
            .map_err(|_| "video frame width exceeds limits".to_string())?;
        let frame_height = u32::try_from(frame.height)
            .map_err(|_| "video frame height exceeds limits".to_string())?;
        let (rgb_width, rgb_height, rgb) = bounded_video_rgb(
            frame_width,
            frame_height,
            frame.rgb8_data,
        )?;
        if frames.is_empty() {
            width = rgb_width;
            height = rgb_height;
        } else if rgb_width != width || rgb_height != height {
            return Err("inconsistent video frame dimensions".into());
        }
        let rgb_bytes = rgb.len();
        let rgba_size = rgb_bytes / 3 * 4;
        // Keep decoding the source after the retention budget is reached.
        // Compacting pairs of retained frames preserves the complete clip
        // timeline instead of looping only over its first few frames.
        while (frames.len() >= MAX_FRAMES
            || total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES)
            && frames.len() > 1
        {
            compact_video_frames(&mut frames, &mut total_bytes);
        }
        if total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES {
            break;
        }
        let mut rgba = Vec::with_capacity(rgba_size);
        for pixel in rgb.chunks_exact(3) {
            rgba.extend_from_slice(pixel);
            rgba.push(0xFF);
        }
        let delay_us = previous_timestamp
            .and_then(|previous| frame.timestamp_us.checked_sub(previous))
            .unwrap_or(100_000)
            .clamp(20_000, 10_000_000);
        previous_timestamp = Some(frame.timestamp_us);
        frames.push(Frame {
            rgba: Arc::new(rgba),
            delay: Duration::from_micros(delay_us),
        });
        total_bytes += rgba_size;
    }
    if frames.is_empty() {
        return Err("video contained no usable frames".into());
    }
    Ok(ReadyCampaign {
        campaign,
        width,
        height,
        frames,
        background_frames: Vec::new(),
        background_width: 0,
        background_height: 0,
        background_rgba: Arc::new(Vec::new()),
        title_color: DEFAULT_TITLE_COLOR,
        message_color: DEFAULT_MESSAGE_COLOR,
        card_color: DEFAULT_CARD_COLOR,
        icon_x: DEFAULT_ICON_X,
        icon_y: DEFAULT_ICON_Y,
        duration_seconds: DEFAULT_DURATION_SECONDS,
        title_x: DEFAULT_TITLE_X,
        title_y: DEFAULT_TITLE_Y,
        message_x: DEFAULT_MESSAGE_X,
        message_y: DEFAULT_MESSAGE_Y,
        image_fit: 0,
        icon_scale: DEFAULT_ICON_SCALE,
        background_scale: DEFAULT_BACKGROUND_SCALE,
    })
}

fn decode_background(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
) -> Option<BackgroundImage> {
    let decoded = decode_media(campaign, url, payload, client)?;
    if decoded.frames.is_empty() { return None; }
    Some(BackgroundImage {
        width: decoded.width,
        height: decoded.height,
        frames: decoded.frames,
    })
}

struct BackgroundImage {
    width: u32,
    height: u32,
    frames: Vec<Frame>,
}

fn cache_name_for(campaign: &Campaign, url: Option<&str>, suffix: &str) -> String {
    // Use a stable hash so cache filenames remain identical across process
    // restarts and unchanged campaign URLs can be reused.
    let mut hash = 14695981039346656037u64;
    for byte in url.unwrap_or_default().as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211u64);
    }
    format!("{}-{:016x}.{}", campaign.id, hash, suffix)
}

fn cache_name(campaign: &Campaign) -> String {
    cache_name_for(campaign, campaign.icon_url.as_deref(), "media")
}

fn background_cache_name(campaign: &Campaign) -> String {
    cache_name_for(campaign, campaign.background_url.as_deref(), "background")
}

fn audio_cache_name(campaign: &Campaign) -> String {
    cache_name_for(campaign, campaign.audio_url.as_deref(), "audio")
}

fn download_media(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>, String> {
    let response = client.get(url).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() { return Err(format!("media HTTP {}", response.status())); }
    read_limited(response, MAX_MEDIA_BYTES)
}

fn read_limited(mut response: reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>, String> {
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > limit as u64) { return Err("response too large".into()); }
    let reserve = content_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(limit);
    let mut bytes = Vec::with_capacity(reserve);
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
        let mut frames = Vec::new();
        let mut total_bytes = 0usize;
        for (source_index, frame) in decoder.into_frames().enumerate() {
            if source_index >= MAX_VIDEO_INPUT_FRAMES { break; }
            let frame = frame.map_err(|e| e.to_string())?;
            if frame.buffer().width() != width || frame.buffer().height() != height {
                return Err("inconsistent GIF frame dimensions".into());
            }
            let (numer, denom) = frame.delay().numer_denom_ms();
            let millis = if denom == 0 { 100 } else { (numer / denom).clamp(20, 10_000) };
            let rgba = frame.into_buffer().into_raw();
            // Retain the complete bounded GIF timeline. When the retention
            // budget is reached, merge adjacent frames and add their delays
            // instead of silently replaying only the prefix.
            while (frames.len() >= MAX_FRAMES
                || total_bytes.saturating_add(frame_bytes) > MAX_DECODED_BYTES)
                && frames.len() > 1
            {
                compact_video_frames(&mut frames, &mut total_bytes);
            }
            if total_bytes.saturating_add(rgba.len()) > MAX_DECODED_BYTES {
                break;
            }
            total_bytes += rgba.len();
            frames.push(Frame {
                rgba: Arc::new(rgba),
                delay: Duration::from_millis(millis as u64),
            });
        }
        if frames.is_empty() { return Err("invalid GIF frame count".into()); }
        Ok(ReadyCampaign {
            campaign,
            width,
            height,
            frames,
            background_frames: Vec::new(),
            background_width: 0,
            background_height: 0,
            background_rgba: Arc::new(Vec::new()),
            title_color: DEFAULT_TITLE_COLOR,
            message_color: DEFAULT_MESSAGE_COLOR,
            card_color: DEFAULT_CARD_COLOR,
            icon_x: DEFAULT_ICON_X,
            icon_y: DEFAULT_ICON_Y,
            duration_seconds: DEFAULT_DURATION_SECONDS,
            title_x: DEFAULT_TITLE_X,
            title_y: DEFAULT_TITLE_Y,
            message_x: DEFAULT_MESSAGE_X,
            message_y: DEFAULT_MESSAGE_Y,
            image_fit: 0,
            icon_scale: DEFAULT_ICON_SCALE,
            background_scale: DEFAULT_BACKGROUND_SCALE,
        })
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
            background_frames: Vec::new(),
            background_width: 0,
            background_height: 0,
            background_rgba: Arc::new(Vec::new()),
            title_color: DEFAULT_TITLE_COLOR,
            message_color: DEFAULT_MESSAGE_COLOR,
            card_color: DEFAULT_CARD_COLOR,
            icon_x: DEFAULT_ICON_X,
            icon_y: DEFAULT_ICON_Y,
            duration_seconds: DEFAULT_DURATION_SECONDS,
            title_x: DEFAULT_TITLE_X,
            title_y: DEFAULT_TITLE_Y,
            message_x: DEFAULT_MESSAGE_X,
            message_y: DEFAULT_MESSAGE_Y,
            image_fit: 0,
            icon_scale: DEFAULT_ICON_SCALE,
            background_scale: DEFAULT_BACKGROUND_SCALE,
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
    let proxy_url = SPONSOR_PROXY
        .read()
        .clone()
        .ok_or_else(|| "sponsor network is unavailable without a connected tunnel".to_string())?;
    let mut cached = CLIENT_CACHE.lock();
    if let Some((cached_proxy, client)) = cached.as_ref() {
        if cached_proxy == &proxy_url {
            return Ok(client.clone());
        }
    }
    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("invalid sponsor tunnel proxy: {e}"))?;
    let client = reqwest::blocking::Client::builder()
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
        .map_err(|e| format!("cannot create sponsor tunnel client: {e}"))?;
    *cached = Some((proxy_url, client.clone()));
    Ok(client)
}
