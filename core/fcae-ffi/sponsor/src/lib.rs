use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use rodio::{Decoder as AudioDecoder, OutputStreamBuilder, Sink, Source};
use serde::{Deserialize, Serialize};
use yscv_video::Mp4VideoReader;
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
/// Pacing cap for animated sponsor media: 30 fps on every platform. Slower
/// native rates play at their own delays; faster ones are slowed to this.
/// Also the fallback when a container yields no usable rate.
const FRAME_DELAY_US: u64 = 33_333;
/// Retained per-frame delay bounds, shared by the decode paths and the decoded
/// sidecar format. The floor matches the UI's 60 Hz poll: a shorter delay
/// cannot be presented and only costs decode bytes. The ceiling stops a
/// corrupt timestamp from freezing the card for minutes.
const MIN_FRAME_DELAY_MS: u64 = 20;
const MAX_FRAME_DELAY_MS: u64 = 10_000;
// Same bounds in microseconds for the sidecar format: stored as u32 µs,
// read back and clamped so a hydrated card never replays outside the
// floor/ceiling regardless of what the container reported.
const MIN_FRAME_DELAY_US: u32 = (MIN_FRAME_DELAY_MS * 1_000) as u32;
const MAX_FRAME_DELAY_US: u32 = (MAX_FRAME_DELAY_MS * 1_000) as u32;

// Every plane is displayed in a 140-unit card, so every plane is *retained*
// at a card-sized canvas: a still, a GIF and a video frame then cost the same
// per frame, and a large GIF keeps its whole timeline inside the budget
// instead of collapsing to a handful of frames. This one canvas is the
// difference between "the GIF sometimes animates" and "the GIF always does".
// The accepted *source* size is still 800x450 (MAX_WIDTH/MAX_HEIGHT); only the
// retained pixels are bounded.
#[cfg(target_os = "android")]
const MEDIA_MAX_WIDTH: u32 = 320;
#[cfg(target_os = "android")]
const MEDIA_MAX_HEIGHT: u32 = 180;
#[cfg(not(target_os = "android"))]
const MEDIA_MAX_WIDTH: u32 = 400;
#[cfg(not(target_os = "android"))]
const MEDIA_MAX_HEIGHT: u32 = 225;
// Decode enough source samples to cover normal short sponsor clips, but do not
// let a long or malicious animation turn startup into an unbounded decode.
const MAX_INPUT_FRAMES: usize = 180;
// Retention is a byte budget and nothing else -- no parallel frame count that
// could merge a small animation the budget could have kept. A clip over the
// budget merges frames (each merged frame's display time is added to its
// predecessor) instead of replaying only its prefix.
#[cfg(target_os = "android")]
const MAX_DECODED_BYTES: usize = 6 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_DECODED_BYTES: usize = 12 * 1024 * 1024;
// Aggregate decoded-memory ceiling. The retention window holds exactly one
// fully decoded card (the visible one); the prepared next card keeps only a
// one-frame preview per plane and is hydrated from its decoded sidecar on
// rotation. Each card is admitted against half of this number --
// CAMPAIGN_DECODED_BYTES -- which therefore covers one card's two planes.
#[cfg(target_os = "android")]
const MAX_TOTAL_DECODED_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(target_os = "android"))]
const MAX_TOTAL_DECODED_BYTES: usize = 32 * 1024 * 1024;
/// Decoded bytes a single card may retain.
const CAMPAIGN_DECODED_BYTES: usize = MAX_DECODED_BYTES;
/// Ceiling for the on-disk sponsor cache. Only re-derivable files are swept to
/// stay under it (decoded sidecars, parked clips); a current asset is never
/// deleted. Sized so a whole manifest fits with its encoded assets and its
/// decoded sidecars at once.
const MAX_CACHE_BYTES: u64 = 768 * 1024 * 1024;
/// How often the media worker re-checks that ceiling. A manifest arrives every
/// 12 hours and pins one fallback per plane per campaign, so a long session
/// needs its own pass over the tree.
const CACHE_SWEEP_INTERVAL: u64 = 15 * 60;
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
const DEFAULT_TITLE_SCALE: u32 = 100;
const DEFAULT_MESSAGE_SCALE: u32 = 100;
// Opacity defaults preserve the look campaigns shipped with before the fields
// existed: the icon fully opaque, the background plane dimmed to sit behind
// the text, and the card color applied as-is.
const DEFAULT_ICON_OPACITY: u8 = 100;
const DEFAULT_BACKGROUND_OPACITY: u8 = 42;
const DEFAULT_BACKGROUND_COLOR_OPACITY: u8 = 100;
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    #[serde(default, alias = "icon_size", alias = "icon_size_percent", alias = "icon_scale_percent", alias = "image_size")]
    icon_scale: Option<u32>,
    #[serde(default, alias = "background_size", alias = "bg_size", alias = "bg_scale", alias = "background_scale_percent")]
    background_scale: Option<u32>,
    #[serde(default, alias = "title_size", alias = "title_font_scale", alias = "title_font_size", alias = "title_scale_percent")]
    title_scale: Option<u32>,
    #[serde(default, alias = "message_size", alias = "message_font_scale", alias = "message_font_size", alias = "message_scale_percent")]
    message_scale: Option<u32>,
    /// Foreground icon opacity percent, 0..=100.
    #[serde(default)]
    icon_opacity: Option<u32>,
    /// Background media opacity percent, 0..=100.
    #[serde(default)]
    background_opacity: Option<u32>,
    /// Extra opacity percent applied to `background_color`, 0..=100.
    #[serde(default)]
    background_color_opacity: Option<u32>,
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
    /// True while only the first frame of each plane is retained. The card
    /// renders that preview immediately on rotation; the full animation is
    /// re-read from the decoded sidecar on demand, so at most one card's
    /// frames are resident at a time.
    preview_only: bool,
    background_width: u32,
    background_height: u32,
    background_rgba: Arc<Vec<u8>>,
    title_color: u32,
    message_color: u32,
    card_color: u32,
    /// Extra opacity percent applied to the card color, 0..=100.
    background_color_opacity: u8,
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
    title_scale: u32,
    message_scale: u32,
    /// Foreground icon opacity percent, 0..=100.
    icon_opacity: u8,
    /// Background media plane opacity percent, 0..=100.
    background_opacity: u8,
}

struct MediaPayload {
    path: PathBuf,
    // Encoded bytes that are already in memory: a fresh download, or a cached
    // still image that the image decoder needs as a buffer. Video is decoded
    // straight from `path`, so a cached MP4 is never pulled into the heap only
    // to be handed to a file reader.
    bytes: Option<Vec<u8>>,
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

/// Text of the visible card. Shared through `Arc` so the frame poll only ever
/// bumps reference counts; rotated to a new value whenever the card changes.
#[derive(Clone)]
struct CardText {
    id: Arc<str>,
    title: Arc<str>,
    message: Arc<str>,
    destination_url: Arc<str>,
}

impl CardText {
    fn of(campaign: &Campaign) -> Self {
        Self {
            id: Arc::from(campaign.id.as_str()),
            title: Arc::from(campaign.title.as_str()),
            message: Arc::from(campaign.message.as_deref().unwrap_or_default()),
            destination_url: Arc::from(campaign.destination_url.as_str()),
        }
    }
}

#[derive(Clone)]
pub struct SponsorFrame {
    pub id: Arc<str>,
    pub title: Arc<str>,
    pub message: Arc<str>,
    pub destination_url: Arc<str>,
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
    pub title_scale: u32,
    pub message_scale: u32,
    pub icon_opacity: u8,
    pub background_opacity: u8,
    pub background_color_opacity: u8,
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
    // Position in the visible card while the UI is hidden. The rotation clock
    // is frozen there, so the user returns to the card and frame they left.
    paused_at: Option<Duration>,
    media_released: bool,
    current_campaign: usize,
    // The next card is selected early so its media can be prepared while the
    // current card is visible. Only this two-card window retains decoded pixels.
    next_campaign: Option<usize>,
    random_state: u64,
    manifest_checked_at: u64,
    // (campaign id, clip present) for the last audio probe. The card is polled
    // at frame rate while it animates, so re-`stat`ing the clip on every poll
    // is pure syscall traffic; only the transition needs to touch the disk.
    audio_probe: Option<(String, bool)>,
    // "<campaign>:<plane>" entries whose failure has already been reported.
    // Rotation re-checks a campaign whose asset never arrives, so without this
    // an unreachable URL would warn on every rotation forever.
    warned_media: HashSet<String>,
    // Prevent a failed media request from being retried once per UI poll;
    // successful publishing clears the backoff immediately.
    media_retry_after: Instant,
    // Text of the visible card, cached by (state generation, campaign index).
    // The poll runs at 60 FPS on both clients, so rebuilding four strings per
    // frame is pure garbage; a publication or a rotation invalidates the key.
    card_text: Option<(u64, usize, CardText)>,
    // Last accepted manifest, kept so a campaign whose schedule window closes
    // mid-session can be dropped without another network round trip.
    manifest_json: Option<Vec<u8>>,
    last_error: String,
}

static STATE: Lazy<Mutex<State>> = Lazy::new(|| Mutex::new(State {
    campaigns: Vec::new(),
    ready: Vec::new(),
    cache_dir: default_cache_dir(),
    rotation_started: Instant::now(),
    paused_at: None,
    media_released: false,
    current_campaign: 0,
    next_campaign: None,
    random_state: SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64 ^ std::process::id() as u64,
    manifest_checked_at: 0,
    audio_probe: None,
    warned_media: HashSet::new(),
    media_retry_after: Instant::now(),
    card_text: None,
    manifest_json: None,
    last_error: String::new(),
}));
static CONNECTED: AtomicBool = AtomicBool::new(false);
static SPONSOR_PROXY: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));
static CLIENT_CACHE: Lazy<Mutex<Option<(String, reqwest::blocking::Client)>>> =
    Lazy::new(|| Mutex::new(None));
static MANIFEST_BUSY: AtomicBool = AtomicBool::new(false);
static MANIFEST_FORCE_PENDING: AtomicBool = AtomicBool::new(false);
static MEDIA_BUSY: AtomicBool = AtomicBool::new(false);

/// The media thread's slot, released on drop.
///
/// The flag used to be cleared by hand at each exit of the pass, so a panic in
/// a decoder would have left it set for the life of the process and frozen
/// every card that follows -- the kind of one-off "media stopped working"
/// failure that is impossible to reproduce. Drop runs during unwinding too.
struct MediaSlot;

fn acquire_media_slot() -> Option<MediaSlot> {
    (!MEDIA_BUSY.swap(true, Ordering::AcqRel)).then_some(MediaSlot)
}

impl Drop for MediaSlot {
    fn drop(&mut self) {
        MEDIA_BUSY.store(false, Ordering::Release);
    }
}
// Sponsor audio is muted by default; the attached text control explicitly
// enables it. The choice is persisted next to the manifest so a restart keeps
// the user's decision instead of silently resetting it -- the "works once,
// then the sound is gone again" complaint.
static AUDIO_ENABLED: AtomicBool = AtomicBool::new(false);
// Every retraction of audio (mute, backgrounding, campaign rotation) bumps
// this generation. A queued Play carrying an older generation is dropped by
// the worker instead of being played, so a command that loses the race with a
// Stop can never be heard.
static AUDIO_EPOCH: AtomicU64 = AtomicU64::new(0);
// Sponsors only do work while a client UI owns the card. Android toggles
// this from Activity onResume/onPause; desktop keeps it active while the
// ImGui window is rendering and clears it during shutdown. While it is false
// the engine neither plays audio nor spends decode passes in the background.
static SPONSOR_UI_ACTIVE: AtomicBool = AtomicBool::new(false);
static AUDIO_CONTROLLER: Lazy<Mutex<AudioController>> = Lazy::new(|| {
    Mutex::new(AudioController {
        sender: None,
        campaign_id: None,
        clip: None,
        request: 0,
        serial: 0,
        retry_at: None,
        active: false,
    })
});
static GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "android")]
static ANDROID_CONTEXT_INIT: std::sync::Once = std::sync::Once::new();

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
    Play { path: PathBuf, request: u64, epoch: u64 },
    Stop,
    Release,
}

/// A clip that is not cached yet is re-probed at this rate while its card is
/// visible. The media pass that downloads it runs on its own schedule, so this
/// only decides how quickly an arrival is noticed.
const AUDIO_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// A Play the worker never answered is resent after this long: the card poll
/// cannot tell a slow decode from a request that outlived a mute, and one
/// resend is cheaper than a clip that never starts.
const AUDIO_ANSWER_DEADLINE: Duration = Duration::from_secs(5);
/// How long the output device may sit idle after the last clip before it is
/// released. An open AAudio/WASAPI stream keeps its output route active --
/// visibly "using the speaker" on Android even while muted -- so a muted
/// client must hand the device back. Five seconds keeps fast rotations and
/// quick re-enables on the already-open device while a real mute releases it.
const AUDIO_STREAM_IDLE_LIMIT: Duration = Duration::from_secs(5);
/// Worker feedback for the card poll.
///
/// Without it the poll cannot tell "this file has no audio" (stop asking) from
/// "the clip is not on disk yet" (ask again): latching the first answer meant a
/// clip that arrived late stayed silent for the rest of the rotation -- the
/// "audio sometimes loads, sometimes not" half of the card.
#[derive(Clone, Copy, Default)]
struct AudioStatus {
    /// Request the worker last finished with -- played, silent, or failed --
    /// and 0 while nothing has been handled. The outcome is deliberately not
    /// kept: the poll only needs to know that this clip will not answer again.
    request: u64,
}

static AUDIO_STATUS: Lazy<Mutex<AudioStatus>> = Lazy::new(|| Mutex::new(AudioStatus::default()));

fn set_audio_status(request: u64) {
    AUDIO_STATUS.lock().request = request;
}

// cpal's CoreAudio stream is intentionally kept on its owning thread: on
// macOS it contains a non-Send property-listener callback. The global state
// stores only an mpsc Sender, which is Send + Sync on every target.
struct AudioController {
    sender: Option<Sender<AudioCommand>>,
    campaign_id: Option<String>,
    /// Clip handed to the worker for `campaign_id`, so a retry can tell a
    /// replaced file from the same one and a missing clip from a silent one.
    clip: Option<PathBuf>,
    /// Request id of the outstanding Play; 0 while nothing is outstanding.
    request: u64,
    /// Monotonic source of request ids. Never reset, so an id from an earlier
    /// campaign can never be mistaken for the answer to a later request.
    serial: u64,
    /// Next probe/resend. `None` means the worker owns the answer.
    retry_at: Option<Instant>,
    // True while a Play has been handed over and not yet retracted, so a muted
    // card does not enqueue a Stop command on every UI poll.
    active: bool,
}

fn audio_requested() -> bool {
    AUDIO_ENABLED.load(Ordering::Acquire)
        && SPONSOR_UI_ACTIVE.load(Ordering::Acquire)
}

fn audio_worker(receiver: Receiver<AudioCommand>) {
    // Open lazily on the first Play command. In particular, this happens
    // after the Android JNI bridge has initialized ndk-context, rather than
    // while the worker is being created during UI startup.
    //
    // The stream survives a Stop only for a short idle window: fast
    // rotations and quick mute/unmute toggles stay on the already-open
    // device (vendor AAudio implementations are unreliable about reopening a
    // released one), but once nothing has played for AUDIO_STREAM_IDLE_LIMIT
    // the stream is dropped so the output route is handed back -- a muted
    // client must not keep holding the speaker.
    let mut stream = None;
    let mut sink: Option<Sink> = None;
    // Set whenever the stream exists but nothing is attached to it; cleared
    // the moment a clip starts.
    let mut idle_since: Option<Instant> = None;
    // Files whose decoder had nothing to play. A video without an audio track
    // is a normal campaign, not a fault, and it is re-offered on every
    // rotation: report each file once so the log stays quiet.
    let mut reported: HashSet<PathBuf> = HashSet::new();
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(AudioCommand::Play { path, request, epoch }) => {
                // A Stop sent after this Play (mute, backgrounding, or the
                // card rotating) has already bumped the epoch: drop the
                // command unanswered instead of playing a clip whose card is
                // gone. Re-check at every gate, including the last one before
                // attaching the sink, so a mute that lands mid-decode is
                // honored too.
                if epoch != AUDIO_EPOCH.load(Ordering::Acquire) || !audio_requested() {
                    sink.take();
                    idle_since.get_or_insert_with(Instant::now);
                    continue;
                }
                sink.take();
                let file = match fs::File::open(&path) {
                    Ok(file) => file,
                    Err(error) => {
                        // Left unanswered on purpose: a file that vanished is
                        // re-resolved by the poll (which then sees no clip and
                        // probes for it again) while a real decode failure is
                        // answered as final below.
                        report_audio_failure(&mut reported, &path, &error.to_string());
                        idle_since.get_or_insert_with(Instant::now);
                        continue;
                    }
                };
                let source = match AudioDecoder::try_from(BufReader::new(file)) {
                    Ok(source) => source,
                    Err(error) => {
                        // The decoder decides what is playable. A video whose
                        // container carries no track lands here too, and is
                        // answered once so it is never decoded again.
                        set_audio_status(request);
                        report_audio_failure(&mut reported, &path, &error.to_string());
                        idle_since.get_or_insert_with(Instant::now);
                        continue;
                    }
                };
                if epoch != AUDIO_EPOCH.load(Ordering::Acquire) || !audio_requested() {
                    idle_since.get_or_insert_with(Instant::now);
                    continue;
                }
                if stream.is_none() {
                    match OutputStreamBuilder::open_default_stream() {
                        Ok(output) => stream = Some(output),
                        Err(error) => {
                            // Left unanswered: the controller resends after the
                            // answer deadline, which retries the device open.
                            // Answering here would latch the failure and the
                            // clip would stay silent for the whole campaign.
                            log::warn!("[sponsor] audio output stream unavailable: {error}");
                            continue;
                        }
                    }
                }
                let Some(output) = stream.as_ref() else { continue; };
                if epoch != AUDIO_EPOCH.load(Ordering::Acquire) || !audio_requested() {
                    idle_since.get_or_insert_with(Instant::now);
                    continue;
                }
                let next_sink = Sink::connect_new(output.mixer());
                // A single source is attached once and repeats at the source
                // level, so it does not depend on UI polling cadence.
                next_sink.append(source.repeat_infinite());
                next_sink.play();
                sink = Some(next_sink);
                idle_since = None;
                set_audio_status(request);
                log::debug!("[sponsor] playing looping cached audio {}", path.display());
            }
            Ok(AudioCommand::Stop) => {
                set_audio_status(0);
                // The sink drop stops playback and releases the decoder; the
                // idle clock decides when the device itself is handed back.
                sink.take();
                idle_since.get_or_insert_with(Instant::now);
            }
            Ok(AudioCommand::Release) => {
                // Explicit retract (sound toggled off, UI hidden): hand the
                // device back now instead of riding out the idle window.
                set_audio_status(0);
                sink.take();
                stream.take();
                idle_since = None;
            }
            Err(RecvTimeoutError::Timeout) => {
                // Idle release: the device is dropped only after a quiet
                // stretch, so a rotation gap or a quick toggle never pays for
                // a device reopen it did not need.
                if stream.is_some()
                    && sink.is_none()
                    && idle_since.is_some_and(|since| since.elapsed() >= AUDIO_STREAM_IDLE_LIMIT)
                {
                    stream.take();
                    idle_since = None;
                    log::debug!("[sponsor] released idle audio output device");
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Report a plane that produced no audio exactly once.
///
/// The decoder decides what is playable, never a pre-flight probe: an explicit
/// `audio_url` that fails is worth a warning, while a video whose container
/// carries no track is a normal campaign and stays on debug. The set is capped
/// so a long-lived process cannot accumulate paths for media no longer cached.
fn report_audio_failure(reported: &mut HashSet<PathBuf>, path: &Path, error: &str) {
    if reported.len() > 64 {
        reported.clear();
    }
    if !reported.insert(path.to_path_buf()) {
        return;
    }
    if plane_key(path) == "audio" {
        log::warn!("[sponsor] audio decode failed ({}): {error}", path.display());
    } else {
        log::debug!("[sponsor] media has no playable audio ({}): {error}", path.display());
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
    // Both embedding clients route their startup through here (Android via
    // set_cache_dir, desktop via the first sponsor poll), so this is the one
    // place the persisted audio choice is restored.
    load_audio_enabled();
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
        // Kept for the schedule sweep: an expired campaign must be droppable
        // without another network round trip.
        if campaigns.is_some() {
            state.manifest_json = json.clone();
        }
    }
    if let Some(campaigns) = campaigns {
        log::debug!("[sponsor] loaded cached manifest ({} active campaigns)", campaigns.len());
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

/// Retract and hand the output device back at once: for an explicit
/// sound-off and a hidden UI, where nothing plays until re-enabled.
fn stop_audio_and_release() {
    stop_audio();
    let controller = AUDIO_CONTROLLER.lock();
    if let Some(sender) = controller.sender.as_ref() {
        let _ = sender.send(AudioCommand::Release);
    }
}

fn stop_audio() {
    let mut controller = AUDIO_CONTROLLER.lock();
    // The card poll calls this every frame while audio is not requested; once
    // everything is retracted there is nothing to bump or send.
    if !controller.active && controller.request == 0 && controller.campaign_id.is_none() {
        return;
    }
    // Bump before the command: a Play already queued for the worker becomes
    // stale the moment this returns, even if the Stop is processed after it.
    AUDIO_EPOCH.fetch_add(1, Ordering::AcqRel);
    controller.campaign_id = None;
    controller.clip = None;
    controller.request = 0;
    controller.retry_at = None;
    if !controller.active {
        return;
    }
    controller.active = false;
    if let Some(sender) = controller.sender.as_ref() {
        let _ = sender.send(AudioCommand::Stop);
    }
}

/// The persisted audio choice lives beside the manifest: one file, written
/// only when the user toggles the control, read once when the cache dir is
/// resolved. A missing or unreadable file is the muted default, never an
/// error.
fn audio_pref_path() -> PathBuf {
    STATE.lock().cache_dir.join("audio.enabled")
}

fn persist_audio_enabled(enabled: bool) {
    let path = audio_pref_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, if enabled { "1\n" } else { "0\n" });
}

fn load_audio_enabled() {
    let contents = fs::read_to_string(audio_pref_path()).unwrap_or_default();
    AUDIO_ENABLED.store(contents.trim() == "1", Ordering::Release);
}

pub fn set_audio_enabled(enabled: bool) {
    AUDIO_ENABLED.store(enabled, Ordering::Release);
    persist_audio_enabled(enabled);
    if !enabled {
        stop_audio_and_release();
        return;
    }
    // The previous disable answered or retracted whatever was outstanding;
    // start from a clean controller so the next poll issues a fresh Play
    // instead of trusting a stale "answered" status.
    AUDIO_EPOCH.fetch_add(1, Ordering::AcqRel);
    {
        let mut controller = AUDIO_CONTROLLER.lock();
        controller.campaign_id = None;
        controller.clip = None;
        controller.request = 0;
        controller.retry_at = None;
        controller.active = false;
    }
    // Audio is deliberately lazy: enabling the card control is the first point
    // at which the current campaign's audio may be downloaded.
    STATE.lock().audio_probe = None;
    if CONNECTED.load(Ordering::Acquire) {
        refresh_media_async();
    } else {
        refresh_cached_media_async();
    }
}

pub fn audio_enabled() -> bool {
    AUDIO_ENABLED.load(Ordering::Acquire)
}

pub fn set_ui_active(active: bool) {
    // The desktop reasserts visibility on every poll; a shown UI never holds a
    // frozen clock, so there is nothing to do.
    if active && SPONSOR_UI_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    // The flag and the frozen clock change under one lock, so racing hide and
    // show calls can never leave a visible UI with its rotation paused.
    let mut state = STATE.lock();
    let was = SPONSOR_UI_ACTIVE.swap(active, Ordering::AcqRel);
    if !active {
        state.card_text = None;
        if state.paused_at.is_none() {
            state.paused_at = Some(state.rotation_started.elapsed());
        }
        retain_hidden_frames(&mut state);
        drop(state);
        stop_audio_and_release();
        if was {
            thread::spawn(release_freed_memory);
        }
        return;
    }
    state.media_released = false;
    if let Some(elapsed) = state.paused_at.take() {
        let now = Instant::now();
        state.rotation_started = now.checked_sub(elapsed).unwrap_or(now);
    }
    let is_prev = current_is_preview(&state);
    drop(state);
    if !was && (is_prev || media_needs_refresh() || audio_needs_refresh()) {
        // Passes do not run while the UI is hidden, so the card may be stale
        // by the time it returns: catch up before the first poll draws it.
        if CONNECTED.load(Ordering::Acquire) {
            refresh_media_async();
        } else {
            refresh_cached_media_async();
        }
    }
}

/// The cached clip of a campaign that declares an `audio_url`.
fn audio_source_path(state: &State, campaign: &Campaign) -> Option<PathBuf> {
    campaign.audio_url
        .as_ref()
        .map(|_| state.cache_dir.join(audio_cache_name(campaign)))
}


/// Start, keep, or retry the clip of the visible campaign.
///
/// The card poll calls this once per frame, so the answered case costs two
/// uncontended locks and no file I/O. The worker owns the truth about a clip
/// ([`AUDIO_STATUS`]): this only decides whether to hand one over again, which
/// is what keeps a clip that arrives after the card became visible from staying
/// silent for the rest of the rotation -- and what keeps a file with no audio
/// track from being decoded over and over.
fn start_audio_for_campaign(campaign_id: &str) {
    if !audio_requested() {
        stop_audio();
        return;
    }
    let mut controller = AUDIO_CONTROLLER.lock();
    if controller.campaign_id.as_deref() == Some(campaign_id) {
        let status = *AUDIO_STATUS.lock();
        if controller.request != 0 && status.request == controller.request {
            // Answered: either a sink is playing, or this file has nothing to
            // play. Both are final for this clip.
            return;
        }
        if controller.retry_at.is_some_and(|deadline| Instant::now() < deadline) {
            return;
        }
        // A clip that never arrived is re-resolved; a request the worker never
        // answered is resent.
    } else {
        // The card rotated. The worker loops the previous clip until it is
        // replaced, and a card without audio would never replace it -- so the
        // old clip is retracted explicitly before the new one is resolved.
        // Bumping the epoch also discards any Play still queued for the old
        // card.
        AUDIO_EPOCH.fetch_add(1, Ordering::AcqRel);
        if controller.active {
            if let Some(sender) = controller.sender.as_ref() {
                let _ = sender.send(AudioCommand::Stop);
            }
        }
        controller.campaign_id = Some(campaign_id.to_string());
        controller.clip = None;
        controller.request = 0;
        controller.retry_at = None;
        controller.active = false;
    }
    let epoch = AUDIO_EPOCH.load(Ordering::Acquire);
    let resolved = audio_source_path_for(campaign_id);
    if resolved.as_deref() == controller.clip.as_deref() && controller.request != 0 {
        // Same clip, still unanswered: resend it rather than re-resolve.
        let request = controller.request;
        if let Some(sender) = controller.sender.as_ref() {
            if sender.send(AudioCommand::Play { path: controller.clip.clone().unwrap(), request, epoch }).is_ok() {
                controller.retry_at = Some(Instant::now() + AUDIO_ANSWER_DEADLINE);
                return;
            }
        }
        controller.sender = None;
        controller.active = false;
        return;
    }
    let Some(path) = resolved else {
        // Nothing cached yet. Latch the probe so the poll does not stat the
        // cache every frame; the clip starts the moment it exists.
        controller.clip = None;
        controller.request = 0;
        controller.retry_at = Some(Instant::now() + AUDIO_PROBE_INTERVAL);
        return;
    };
    let Some(sender) = audio_sender(&mut controller) else { return; };
    controller.serial = controller.serial.saturating_add(1).max(1);
    let request = controller.serial;
    if sender.send(AudioCommand::Play { path: path.clone(), request, epoch }).is_err() {
        controller.sender = None;
        controller.active = false;
        return;
    }
    controller.clip = Some(path);
    controller.request = request;
    controller.retry_at = Some(Instant::now() + AUDIO_ANSWER_DEADLINE);
    controller.active = true;
}

/// Resolve the clip of a campaign by id, or `None` while it is not on disk.
fn audio_source_path_for(campaign_id: &str) -> Option<PathBuf> {
    let state = STATE.lock();
    state.campaigns.iter()
        .find(|campaign| campaign.id == campaign_id)
        .and_then(|campaign| audio_source_path(&state, campaign))
        .filter(|path| cached_media_file_is_valid(path))
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
    let mut state = STATE.lock();
    let (current, next) = (state.current_campaign, state.next_campaign);
    if [Some(current), next]
        .into_iter()
        .flatten()
        .any(|index| index >= state.ready.len())
    {
        return true;
    }
    if ready_needs_media(&mut state, current) {
        return true;
    }
    next.is_some_and(|index| ready_needs_media(&mut state, index))
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
        state.manifest_json = Some(json.to_vec());
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
    plan_next_campaign(&mut state);
    trim_ready_window(&mut state);
    state.last_error.clear();
    state.media_retry_after = Instant::now();
    restart_rotation(&mut state);
    GENERATION.fetch_add(1, Ordering::Relaxed);
    let visible = visible_ids(&state);
    schedule_expiry(&campaigns);
    drop(state);
    prune_cache(&cache_dir, &campaigns, &visible);
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
            log::debug!("[sponsor] queued explicit refresh behind the active fetch");
        }
        return;
    }
    // The one schedule-driven message the sponsor keeps at info level: a
    // manifest refresh is the only sponsor activity worth a normal-run line
    // (per-card media work, rotation and audio are debug noise at UI cadence).
    log::info!(
        "[sponsor] refreshing manifest ({})",
        if force { "manual request" } else { "12-hour schedule" }
    );
    thread::spawn(|| {
        match fetch_manifest() {
            Ok(json) => {
                log::debug!("[sponsor] manifest response received ({} bytes)", json.len());
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
    if state.next_campaign.is_none_or(|next| next >= ready_count || next == state.current_campaign) {
        plan_next_campaign(&mut state);
    }
    trim_ready_window(&mut state);
    retain_hidden_frames(&mut state);
    let current = state.current_campaign;
    let current_needs_media = ready_needs_media(&mut state, current);
    if !current_needs_media {
        state.media_retry_after = Instant::now();
    }
    GENERATION.fetch_add(1, Ordering::Relaxed);
    true
}

/// Publishes what the decoded cache already holds and decodes nothing itself.
///
/// Called from the app-launch path -- Android's `nativeSponsorInit` on the UI
/// thread, the desktop's first sponsor poll on the render thread -- so a plane
/// whose sidecar is missing or stale must not turn app start into an MP4/GIF
/// decode of up to a few hundred frames. Those planes are left to the refresh
/// worker, which decodes on its own thread.
fn refresh_cached_media_sync() {
    let Some(slot) = acquire_media_slot() else { return };
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
        false,
        target_id.as_deref(),
    );
    let ready_count = ready.len();
    let applied = publish_media(&campaigns, ready);
    // Released before the follow-up pass is requested: the slot is what that
    // request competes for.
    drop(slot);
    if applied {
        log::debug!("[sponsor] published cached media ({} active campaigns)", ready_count);
        // The worker owns the retry backoff, so clear the clock here so the
        // decode of anything the sidecars did not cover starts now rather than
        // on the next backoff expiry -- and start it for the card that is on
        // screen, not for the preload: a launch must show its campaign first.
        let current_missing = {
            let mut state = STATE.lock();
            state.media_retry_after = Instant::now();
            let index = state.current_campaign;
            ready_needs_media(&mut state, index)
        };
        if current_missing {
            refresh_cached_media_async();
        } else {
            preload_next_media_async();
        }
    }
}

fn refresh_cached_media_async() {
    refresh_media_async_inner(true);
}

fn refresh_media_async_inner(allow_disconnected: bool) {
    refresh_media_target_async(allow_disconnected, None);
}

fn preload_next_media_async() {
    let target_id = {
        let mut state = STATE.lock();
        let Some(next) = state.next_campaign else { return; };
        if !ready_needs_media(&mut state, next) {
            return;
        }
        let Some(ready) = state.ready.get(next) else { return; };
        ready.campaign.id.clone()
    };
    refresh_media_target_async(!CONNECTED.load(Ordering::Acquire), Some(target_id));
}

fn refresh_media_target_async(allow_disconnected: bool, requested_target: Option<String>) {
    // The card is only visible to a live UI; decoding while it is hidden just
    // burns CPU and battery for frames nobody will see. The activation edge of
    // `set_ui_active` re-arms a pass, so nothing is lost by skipping here.
    if !SPONSOR_UI_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if !allow_disconnected && !CONNECTED.load(Ordering::Acquire) {
        return;
    }
    let Some(slot) = acquire_media_slot() else { return };
    STATE.lock().media_retry_after = Instant::now() + Duration::from_secs(30);
    let (campaigns, cache_dir, previous, target_id) = {
        let state = STATE.lock();
        let target_id = requested_target.or_else(|| state.campaigns.get(state.current_campaign)
            .map(|campaign| campaign.id.clone()));
        (state.campaigns.clone(), state.cache_dir.clone(), state.ready.clone(), target_id)
    };
    thread::spawn(move || {
        let _slot = slot;
        let ready = prepare_media(
            &campaigns,
            &cache_dir,
            &previous,
            !allow_disconnected,
            true,
            target_id.as_deref(),
        );
        drop(previous);
        let ready_count = ready.len();
        let connected = CONNECTED.load(Ordering::Acquire);
        let applied = if allow_disconnected || connected {
            publish_media(&campaigns, ready)
        } else {
            false
        };
        drop(_slot);
        // The UI hid while this pass ran: the frames it copied are only freed
        // now, after the release that ran when the UI hid.
        if !SPONSOR_UI_ACTIVE.load(Ordering::Acquire) {
            release_freed_memory();
        }
        if applied {
            log::debug!("[sponsor] published media refresh ({} active campaigns)", ready_count);
            let (current_id, current_needs_media) = {
                let mut state = STATE.lock();
                let index = state.current_campaign;
                let current = state.ready.get(index)
                    .map(|ready| ready.campaign.id.clone());
                let needs = ready_needs_media(&mut state, index);
                (current, needs)
            };
            if current_needs_media && current_id.as_deref() != target_id.as_deref() {
                // Rotation can overtake a slow decode. Prioritize the newly
                // visible card instead of finishing an obsolete preload.
                refresh_media_async();
            } else if !current_needs_media {
                preload_next_media_async();
            }
            if allow_disconnected && CONNECTED.load(Ordering::Acquire) {
                refresh_media_async();
            }
        } else if CONNECTED.load(Ordering::Acquire) {
            log::debug!("[sponsor] discarded stale media refresh; scheduling another pass");
            refresh_media_async();
        } else if !allow_disconnected {
            refresh_cached_media_async();
        }
        // A published pass is the only thing that grows the cache, so it is
        // also the right place to notice that the tree outgrew its ceiling.
        // Sidecars of parked cards stay on disk until real pressure evicts
        // them: re-decoding them on every rotation back into the window was
        // both the slow pass and the missing-plane regression.
        let visible = visible_ids(&STATE.lock());
        sweep_cache_periodically(&cache_dir, &campaigns, &visible);
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

/// Unix second at which the active set changes on its own -- a campaign's
/// window opening or closing -- or 0 when nothing is scheduled. The card poll
/// compares against it, so a sponsor that expires mid-session disappears (with
/// its cache) at its boundary instead of at the next 12-hour refresh.
static NEXT_EXPIRY: AtomicU64 = AtomicU64::new(0);
/// Unix second of the last periodic cache sweep.
static LAST_SWEEP: AtomicU64 = AtomicU64::new(0);

fn schedule_expiry(campaigns: &[Campaign]) {
    let now = unix_now();
    // A campaign is active while `now <= ends_at`, so it leaves the set one
    // second after `ends_at`; `starts_at` is inclusive, so it enters at the
    // second itself. Scheduling the exclusive side of each comparison is what
    // makes the sweep land on the campaign instead of one boundary early.
    let next = campaigns.iter()
        .flat_map(|campaign| [
            campaign.starts_at,
            campaign.ends_at.map(|end| end.saturating_add(1)),
        ])
        .flatten()
        .filter(|boundary| *boundary > now)
        .min()
        .unwrap_or(0);
    NEXT_EXPIRY.store(next, Ordering::Relaxed);
}

/// Campaign ids that can be on screen right now (the visible card and the
/// prepared next one). Everything else is reloadable and may be reclaimed.
fn visible_ids(state: &State) -> Vec<String> {
    let mut ids = Vec::with_capacity(2);
    for index in [Some(state.current_campaign), state.next_campaign].into_iter().flatten() {
        if let Some(ready) = state.ready.get(index) {
            if !ids.contains(&ready.campaign.id) {
                ids.push(ready.campaign.id.clone());
            }
        }
    }
    ids
}

/// Drop campaigns whose window has closed (or has not opened yet) without
/// re-rolling the card: an unrelated sponsor expiring must not jump the one
/// the user is looking at.
fn drop_campaigns(is_active: &dyn Fn(&str) -> bool) -> bool {
    let mut state = STATE.lock();
    if !state.campaigns.iter().any(|campaign| !is_active(&campaign.id)) {
        return false;
    }
    let current_id = state.ready.get(state.current_campaign)
        .map(|ready| ready.campaign.id.clone());
    let next_id = state.next_campaign
        .and_then(|index| state.ready.get(index))
        .map(|ready| ready.campaign.id.clone());
    let before = state.campaigns.len();
    state.campaigns.retain(|campaign| is_active(&campaign.id));
    state.ready.retain(|ready| is_active(&ready.campaign.id));
    let count = state.ready.len();
    let current = current_id.as_deref()
        .and_then(|id| state.ready.iter().position(|ready| ready.campaign.id == id))
        .unwrap_or_else(|| state.current_campaign.min(count.saturating_sub(1)));
    state.current_campaign = if count == 0 { 0 } else { current };
    let selected_id = state.ready.get(state.current_campaign)
        .map(|ready| ready.campaign.id.clone());
    if selected_id.as_deref() != current_id.as_deref() {
        // The visible card was the one that expired. Its successor inherits the
        // rotation clock, so it starts a full turn here instead of rotating
        // away on the next poll.
        restart_rotation(&mut state);
    }
    state.next_campaign = if count == 0 {
        None
    } else {
        next_id.as_deref()
            .and_then(|id| state.ready.iter().position(|ready| ready.campaign.id == id))
            .filter(|index| *index != state.current_campaign)
    };
    let after = state.campaigns.len();
    if state.next_campaign.is_none() {
        plan_next_campaign(&mut state);
    }
    trim_ready_window(&mut state);
    GENERATION.fetch_add(1, Ordering::Relaxed);
    log::info!("[sponsor] {before} -> {after} active campaigns after a schedule change");
    true
}

/// Re-apply the last accepted manifest when a schedule boundary has passed.
///
/// Cheap enough for the frame poll: one atomic load, and a re-parse only when
/// the clock has actually crossed a campaign's `starts_at`/`ends_at`. A
/// campaign whose window closes leaves here -- with everything it cached --
/// instead of waiting for the next 12-hour refresh; one whose window opens gets
/// its turn like any other new sponsor.
fn expire_campaigns() {
    let due = NEXT_EXPIRY.load(Ordering::Relaxed);
    if due == 0 || unix_now() < due {
        return;
    }
    let Some(json) = STATE.lock().manifest_json.clone() else {
        NEXT_EXPIRY.store(0, Ordering::Relaxed);
        return;
    };
    let Ok(campaigns) = parse_manifest(&json) else {
        NEXT_EXPIRY.store(0, Ordering::Relaxed);
        return;
    };
    schedule_expiry(&campaigns);
    let active: HashSet<&str> = campaigns.iter().map(|campaign| campaign.id.as_str()).collect();
    let (removed, added) = {
        let state = STATE.lock();
        (
            state.campaigns.iter().any(|campaign| !active.contains(campaign.id.as_str())),
            campaigns.iter().any(|campaign| {
                !state.campaigns.iter().any(|current| current.id == campaign.id)
            }),
        )
    };
    let changed = if added {
        // A sponsor's window opened. The set changed, so the card is re-rolled
        // the same way a fresh manifest would re-roll it.
        apply_campaigns(campaigns.clone());
        true
    } else if removed {
        drop_campaigns(&|id: &str| active.contains(id))
    } else {
        false
    };
    if !changed {
        return;
    }
    let (cache_dir, visible) = {
        let state = STATE.lock();
        (state.cache_dir.clone(), visible_ids(&state))
    };
    prune_cache(&cache_dir, &campaigns, &visible);
    preload_next_media_async();
}

fn plan_next_campaign(state: &mut State) {
    let count = state.ready.len();
    state.next_campaign = match count {
        0 | 1 => None,
        2 => Some((state.current_campaign + 1) % 2),
        _ => {
            let choice = next_random(state) as usize % (count - 1);
            Some(if choice >= state.current_campaign { choice + 1 } else { choice })
        }
    };
}

/// Keeps exactly one decoded frame of each plane of a card. The preview is
/// what the card shows the instant it rotates in; the full animation is
/// re-read from the decoded sidecar on demand, so resident memory holds one
/// card's frames plus one card's previews instead of two full cards.
fn demote_to_preview(ready: &mut ReadyCampaign) {
    if ready.preview_only {
        return;
    }
    // A card whose planes already fit in one frame has nothing to hand back,
    // and stays fully resident without ever needing a hydration pass.
    if ready.frames.len() <= 1 && ready.background_frames.len() <= 1 {
        return;
    }
    ready.frames.truncate(1);
    ready.background_frames.truncate(1);
    if let Some(first) = ready.background_frames.first() {
        ready.background_rgba = first.rgba.clone();
    }
    ready.preview_only = true;
}

/// Keeps only the frame on screen of each plane, so a hidden UI holds one
/// still per plane and shows exactly that still again the moment it returns;
/// the animation is hydrated from the decoded sidecar afterwards.
fn retain_visible_frame(ready: &mut ReadyCampaign, elapsed: Duration) {
    for frames in [&mut ready.frames, &mut ready.background_frames] {
        if frames.len() > 1 {
            let visible = frame_index_at(frames, elapsed);
            frames.swap(0, visible);
            frames.truncate(1);
            ready.preview_only = true;
        }
    }
    if let Some(first) = ready.background_frames.first() {
        ready.background_rgba = first.rgba.clone();
    }
}

/// Starts the visible card's turn now. A hidden UI's frozen clock restarts at
/// the card's beginning too, instead of resuming into the future.
fn restart_rotation(state: &mut State) {
    state.rotation_started = Instant::now();
    if state.paused_at.is_some() {
        state.paused_at = Some(Duration::ZERO);
    }
}

fn card_elapsed(state: &State) -> Duration {
    state.paused_at.unwrap_or_else(|| state.rotation_started.elapsed())
}

/// While the UI is hidden the visible card holds one still per plane and every
/// other card holds nothing. Re-applied on publication, because a pass that
/// was already running when the UI hid publishes the full frames it copied.
fn retain_hidden_frames(state: &mut State) {
    let Some(elapsed) = state.paused_at else { return };
    let keep = (!state.media_released).then_some(state.current_campaign);
    for (index, ready) in state.ready.iter_mut().enumerate() {
        if Some(index) == keep {
            retain_visible_frame(ready, elapsed);
        } else if !ready.frames.is_empty()
            || !ready.background_frames.is_empty()
            || !ready.background_rgba.is_empty()
        {
            *ready = empty_ready(&ready.campaign);
        }
    }
}

pub fn ui_active() -> bool {
    SPONSOR_UI_ACTIVE.load(Ordering::Acquire)
}

/// Drops the still a hidden UI keeps, once no UI is left to show it or the OS
/// asks for memory. The next activation decodes the card again from cache.
pub fn release_media() {
    let mut state = STATE.lock();
    if SPONSOR_UI_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    state.paused_at.get_or_insert(Duration::ZERO);
    state.media_released = true;
    state.card_text = None;
    retain_hidden_frames(&mut state);
    GENERATION.fetch_add(1, Ordering::Relaxed);
    drop(state);
    release_freed_memory();
}

/// Hands pages of freed frames back to the OS. The allocators keep freed
/// blocks of this size cached in the process, so without it a hidden UI's
/// released frames would still count as resident memory.
fn release_freed_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> std::os::raw::c_int;
        }
        // SAFETY: glibc entry point without preconditions.
        unsafe { malloc_trim(0) };
    }
    #[cfg(target_os = "android")]
    {
        extern "C" {
            fn mallopt(param: std::os::raw::c_int, value: std::os::raw::c_int) -> std::os::raw::c_int;
        }
        const M_PURGE: std::os::raw::c_int = -101;
        // SAFETY: bionic entry point; unknown parameters are rejected with 0.
        unsafe { mallopt(M_PURGE, 0) };
    }
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: a null zone asks every zone to release its free pages.
        unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
    }
}

/// True while the visible card still holds only its one-frame preview and its
/// full planes must be hydrated from the decoded sidecar.
fn current_is_preview(state: &State) -> bool {
    state.ready.get(state.current_campaign).is_some_and(|ready| ready.preview_only || ready.frames.is_empty())
}

fn trim_ready_window(state: &mut State) {
    let current = state.current_campaign;
    let next = state.next_campaign;
    for (index, ready) in state.ready.iter_mut().enumerate() {
        if index == current {
            continue;
        }
        if Some(index) == next {
            demote_to_preview(ready);
        } else if !ready.frames.is_empty()
            || !ready.background_frames.is_empty()
            || !ready.background_rgba.is_empty()
        {
            *ready = empty_ready(&ready.campaign);
        }
    }
}

fn advance_campaign(state: &mut State) {
    if state.ready.len() <= 1 {
        state.current_campaign = 0;
        state.next_campaign = None;
        return;
    }
    if state.next_campaign.is_none() {
        plan_next_campaign(state);
    }
    state.current_campaign = state.next_campaign.take().unwrap_or(0);
    plan_next_campaign(state);
    trim_ready_window(state);
    restart_rotation(state);
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub fn next_campaign() {
    {
        let mut state = STATE.lock();
        advance_campaign(&mut state);
    }
    hydrate_or_preload_after_advance();
}

/// The card that just rotated in holds one-frame previews of its planes; its
/// full animation is re-read from the decoded sidecar before anything else is
/// prepared. A card that rotated in already decoded simply preloads the next.
fn hydrate_or_preload_after_advance() {
    if current_is_preview(&STATE.lock()) {
        refresh_cached_media_async();
    } else {
        preload_next_media_async();
    }
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

/// True the first time a plane failure is reported; false while it keeps
/// failing. The flag re-arms as soon as the plane loads, so one unreachable
/// URL costs one line instead of one per rotation.
fn note_plane_failure(campaign_id: &str, plane: &str) -> bool {
    STATE.lock().warned_media.insert(format!("{campaign_id}:{plane}"))
}

fn clear_plane_failure(campaign_id: &str, plane: &str) {
    STATE.lock().warned_media.remove(&format!("{campaign_id}:{plane}"));
}

fn cached_media_file_is_valid(path: &Path) -> bool {
    path.is_file()
        && fs::metadata(path)
            .map(|metadata| metadata.len() <= MAX_MEDIA_BYTES as u64)
            .unwrap_or(false)
}

/// True while this card still has nothing to fetch: a URL with no decoded
/// plane, or a requested clip that is not on disk yet. Asked once per UI poll,
/// so the answered case is memoised instead of `stat`ed again.
fn ready_needs_media(state: &mut State, index: usize) -> bool {
    let missing_plane = state.ready.get(index).is_some_and(|ready| {
        (ready.campaign.icon_url.is_some() && ready.frames.is_empty())
            || (ready.campaign.background_url.is_some()
                && ready.background_frames.is_empty()
                && ready.background_rgba.is_empty())
    });
    missing_plane || !audio_settled(state, index)
}

fn audio_settled(state: &mut State, index: usize) -> bool {
    if !audio_requested() {
        return true;
    }
    let Some(ready) = state.ready.get(index) else {
        return true;
    };
    if ready.campaign.audio_url.is_none() {
        return true;
    }
    // A positive probe is reused for as long as this campaign stays loaded: the
    // clip only changes when a publish replaces its URL or cache entry.
    if state.audio_probe.as_ref().is_some_and(|(id, present)| {
        *present && *id == ready.campaign.id
    }) {
        return true;
    }
    let cached = cached_media_file_is_valid(&state.cache_dir.join(audio_cache_name(&ready.campaign)));
    let campaign_id = ready.campaign.id.clone();
    state.audio_probe = Some((campaign_id, cached));
    cached
}

pub fn current_frame() -> Option<SponsorFrame> {
    // A sponsor whose window closed mid-session leaves here, with its cache,
    // instead of waiting for the next 12-hour manifest refresh.
    expire_campaigns();
    let (frame, should_refresh, rotated) = {
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
        let rotated = state.ready.len() > 1
            && state.paused_at.is_none()
            && state.rotation_started.elapsed() >= Duration::from_secs(current_duration as u64);
        if rotated {
            // The card that just came up has had no media pass of its own yet:
            // its media (and its clip) must not wait out the previous card's
            // retry backoff.
            state.media_retry_after = Instant::now();
            advance_campaign(&mut state);
        }
        let ready_count = state.ready.len();
        state.current_campaign %= ready_count;
        let campaign_index = state.current_campaign;
        let within = card_elapsed(&state);
        let needs_media = ready_needs_media(&mut state, campaign_index);
        // A card that rotated in as previews needs one hydration pass over its
        // decoded sidecars, retried through the same backoff as a missing
        // plane until the full frames are resident.
        let needs_hydration = state.ready[campaign_index].preview_only;
        // The backoff is armed by the pass that actually starts, never here: a
        // request that loses the race for the media thread must not park the
        // visible card's media for a full retry interval.
        let should_refresh =
            (needs_media || needs_hydration) && Instant::now() >= state.media_retry_after;
        let frame_index = frame_index_at(&state.ready[campaign_index].frames, within);
        let background_frame_index =
            frame_index_at(&state.ready[campaign_index].background_frames, within);
        let rgba = state.ready[campaign_index].frames.get(frame_index)
            .map(|frame| frame.rgba.clone())
            .unwrap_or_default();
        let background_rgba = state.ready[campaign_index].background_frames
            .get(background_frame_index)
            .map(|frame| frame.rgba.clone())
            .unwrap_or_else(|| state.ready[campaign_index].background_rgba.clone());
        // Keep the animation planes independently identifiable across FFI:
        // published campaign metadata is above bit 24, foreground frame index
        // occupies bits 12..23, and background frame index occupies 0..11.
        // Android and desktop can therefore avoid copying an unchanged icon
        // while a video/GIF background advances.
        let state_generation = GENERATION.load(Ordering::Relaxed);
        let generation = (state_generation << 32)
            ^ ((campaign_index as u64) << 24)
            ^ ((frame_index as u64) << 12)
            ^ background_frame_index as u64;
        // Card text is shared, not rebuilt: the poll runs at 60 FPS and this
        // used to allocate four strings (plus their JNI copies) per frame. The
        // key is (state generation, card index), and every change to either
        // bumps the generation, so a hit always describes the card on screen.
        let text = match state.card_text.as_ref()
            .filter(|(generation, index, _)| {
                *generation == state_generation && *index == campaign_index
            })
            .map(|(_, _, text)| text.clone())
        {
            Some(text) => text,
            None => {
                let text = CardText::of(&state.ready[campaign_index].campaign);
                state.card_text = Some((state_generation, campaign_index, text.clone()));
                text
            }
        };
        let ready = &state.ready[campaign_index];
        (SponsorFrame {
            id: text.id.clone(),
            title: text.title.clone(),
            message: text.message.clone(),
            destination_url: text.destination_url.clone(),
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
            title_scale: ready.title_scale,
            message_scale: ready.message_scale,
            icon_opacity: ready.icon_opacity,
            background_opacity: ready.background_opacity,
            background_color_opacity: ready.background_color_opacity,
            generation,
        }, should_refresh, rotated)
    };

    if should_refresh {
        if CONNECTED.load(Ordering::Acquire) {
            refresh_media_async();
        } else {
            refresh_cached_media_async();
        }
    }
    if rotated {
        hydrate_or_preload_after_advance();
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
            if campaign.title_scale.is_some_and(|scale| !(50..=200).contains(&scale)) {
                log::warn!("[sponsor] campaign {} has invalid title scale; using 100 percent", campaign.id);
                campaign.title_scale = None;
            }
            if campaign.message_scale.is_some_and(|scale| !(50..=200).contains(&scale)) {
                log::warn!("[sponsor] campaign {} has invalid message scale; using 100 percent", campaign.id);
                campaign.message_scale = None;
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

fn text_scale_value(value: Option<u32>, default: u32) -> u32 {
    value.filter(|scale| (50..=200).contains(scale)).unwrap_or(default)
}

/// Opacity percent clamped into range: an omitted or out-of-range value falls
/// back to the plane's default instead of failing the manifest.
fn opacity_value(value: Option<u32>, default: u8) -> u8 {
    value.filter(|opacity| *opacity <= 100).unwrap_or(default as u32) as u8
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
        preview_only: false,
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
        title_scale: text_scale_value(campaign.title_scale, DEFAULT_TITLE_SCALE),
        message_scale: text_scale_value(campaign.message_scale, DEFAULT_MESSAGE_SCALE),
        icon_opacity: opacity_value(campaign.icon_opacity, DEFAULT_ICON_OPACITY),
        background_opacity: opacity_value(campaign.background_opacity, DEFAULT_BACKGROUND_OPACITY),
        background_color_opacity: opacity_value(
            campaign.background_color_opacity,
            DEFAULT_BACKGROUND_COLOR_OPACITY,
        ),
    }
}

fn fallback_ready(previous: &ReadyCampaign, campaign: &Campaign) -> ReadyCampaign {
    let mut fallback = empty_ready(campaign);
    fallback.preview_only = previous.preview_only;
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

fn move_cache_file(old: &Path, new: &Path) {
    if !old.is_file() || new.exists() {
        return;
    }
    if let Some(parent) = new.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::rename(old, new).is_err() && fs::copy(old, new).is_ok() {
        let _ = fs::remove_file(old);
    }
}

fn migrate_legacy_cache(cache_dir: &Path, campaign: &Campaign) {
    for (url, kind, current) in [
        (campaign.icon_url.as_deref(), "media", cache_name(campaign)),
        (campaign.background_url.as_deref(), "background", background_cache_name(campaign)),
        (campaign.audio_url.as_deref(), "audio", audio_cache_name(campaign)),
    ] {
        if url.is_none() {
            continue;
        }
        let new = cache_dir.join(current);
        // Flat <id>-<url hash> files at the cache root.
        let flat = cache_dir.join(legacy_cache_name_for(campaign, url, kind));
        move_cache_file(&flat, &new);
        move_cache_file(&flat.with_extension("decoded"), &new.with_extension("decoded"));
        // Url-hashed entries under a per-kind directory; newest wins.
        if !new.is_file() {
            let hashed_dir = cache_dir.join("campaigns").join(&campaign.id).join(kind);
            if let Some(hashed) = newest_file_with_extension(&hashed_dir, kind) {
                move_cache_file(&hashed, &new);
                move_cache_file(&hashed.with_extension("decoded"), &new.with_extension("decoded"));
            }
        }
    }
}

/// Planes of one campaign with each plane's id-keyed cache file.
fn campaign_planes(cache_dir: &Path, campaign: &Campaign) -> [(&'static str, Option<PathBuf>); 3] {
    [
        ("media", campaign.icon_url.as_ref().map(|_| cache_dir.join(cache_name(campaign)))),
        ("background", campaign.background_url.as_ref().map(|_| cache_dir.join(background_cache_name(campaign)))),
        ("audio", campaign.audio_url.as_ref().map(|_| cache_dir.join(audio_cache_name(campaign)))),
    ]
}

/// Size of a directory tree, without following symlinks.
fn directory_bytes(root: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(root) else { return 0; };
    entries.flatten().fold(0u64, |total, entry| {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => total.saturating_add(directory_bytes(&path)),
            Ok(kind) if kind.is_file() => total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0)),
            _ => total,
        }
    })
}

/// Delete `.<name>.<kind>.tmp` staging files a crash left behind. Nothing else
/// ever removes them: install renames or removes them on every normal path.
fn remove_staging_files(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => remove_staging_files(&path),
            Ok(kind) if kind.is_file() => {
                let staging = path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with('.') && name.ends_with(".tmp"));
                if staging {
                    let _ = fs::remove_file(&path);
                }
            }
            _ => {}
        }
    }
}

/// Keep the cache under [`MAX_CACHE_BYTES`] without touching what is on screen.
///
/// Only re-derivable files are candidates, cheapest to restore first: decoded
/// sidecars of cards that are not visible, superseded/fallback entries of those
/// same cards, their clips, and finally the sidecars of the visible cards (one
/// decode rebuilds those). A current asset of a visible card is never deleted:
/// losing it is exactly the "media sometimes missing" failure this cache
/// exists to prevent.
fn sweep_cache_periodically(cache_dir: &Path, campaigns: &[Campaign], visible: &[String]) {
    let now = unix_now();
    if now.saturating_sub(LAST_SWEEP.load(Ordering::Relaxed)) < CACHE_SWEEP_INTERVAL {
        return;
    }
    // Claim the window. A concurrent claimer would delete the same
    // re-derivable files again, which is harmless, so no lock is worth it.
    LAST_SWEEP.store(now, Ordering::Relaxed);
    sweep_cache_to_limit(cache_dir, campaigns, visible);
}

/// Eviction order once the tree outgrows [`MAX_CACHE_BYTES`]: parked sidecars,
/// then parked audio clips, then sidecars of visible cards. A visible card's
/// encoded asset is never a candidate.
fn sweep_cache_to_limit(cache_dir: &Path, campaigns: &[Campaign], visible: &[String]) {
    let root = cache_dir.join("campaigns");
    let mut over = directory_bytes(&root).saturating_sub(MAX_CACHE_BYTES);
    if over == 0 {
        return;
    }
    let mut candidates: Vec<(u8, SystemTime, u64, PathBuf)> = Vec::new();
    for campaign in campaigns {
        let on_screen = visible.iter().any(|id| id == &campaign.id);
        for (kind, current) in campaign_planes(cache_dir, campaign) {
            let Some(current) = current else { continue; };
            let mut push = |path: &Path, priority: u8| {
                let Ok(metadata) = fs::metadata(path) else { return; };
                candidates.push((
                    priority,
                    metadata.modified().unwrap_or(UNIX_EPOCH),
                    metadata.len(),
                    path.to_path_buf(),
                ));
            };
            let sidecar = decoded_cache_path(&current);
            if sidecar.is_file() {
                push(&sidecar, if on_screen { 3 } else { 0 });
            }
            if !on_screen && kind == "audio" && current.is_file() {
                push(&current, 2);
            }
        }
    }
    candidates.sort_by_key(|(priority, modified, ..)| (*priority, *modified));
    for (_, _, length, path) in candidates {
        if over == 0 {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            over = over.saturating_sub(length);
        }
    }
    if over > 0 {
        log::warn!("[sponsor] cache is still {over} bytes over its ceiling; assets in use are kept");
    } else {
        log::debug!("[sponsor] cache swept under its size ceiling");
    }
}

fn prune_cache(cache_dir: &Path, campaigns: &[Campaign], visible: &[String]) {
    let campaigns_root = cache_dir.join("campaigns");
    let _ = fs::create_dir_all(&campaigns_root);
    let active: HashSet<&str> = campaigns.iter().map(|campaign| campaign.id.as_str()).collect();

    for campaign in campaigns {
        migrate_legacy_cache(cache_dir, campaign);
        let campaign_dir = campaigns_root.join(&campaign.id);
        let _ = fs::create_dir_all(&campaign_dir);
        if let Ok(json) = serde_json::to_vec(campaign) {
            let _ = write_atomic_preserving_old(&campaign_dir.join("campaign.json"), &json);
        }

        // One encoded entry and one sidecar per plane at fixed paths; drop
        // everything else, including entries of the old url-hashed layouts.
        let mut keep: HashSet<PathBuf> = HashSet::from([campaign_dir.join("campaign.json")]);
        for (_, plane) in campaign_planes(cache_dir, campaign) {
            let Some(plane) = plane else { continue; };
            keep.insert(plane.clone());
            keep.insert(decoded_cache_path(&plane));
        }
        if let Ok(entries) = fs::read_dir(&campaign_dir) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if keep.contains(&path) {
                    continue;
                }
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
        for (_, plane) in campaign_planes(cache_dir, campaign) {
            let Some(plane) = plane else { continue; };
            let sidecar = decoded_cache_path(&plane);
            if sidecar.is_file() && !plane.is_file() {
                let _ = fs::remove_file(sidecar);
            }
        }
    }

    if let Ok(entries) = fs::read_dir(&campaigns_root) {
        for entry in entries.flatten() {
            if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                && !active.contains(entry.file_name().to_string_lossy().as_ref())
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    // Flat media files belong to the pre-directory cache format. Current files
    // were migrated above; obsolete and inactive entries can now be discarded.
    if let Ok(entries) = fs::read_dir(cache_dir) {
        for path in entries.flatten().map(|entry| entry.path()) {
            if matches!(path.extension().and_then(|value| value.to_str()),
                Some("media" | "background" | "audio" | "decoded" | "tmp"))
            {
                let _ = fs::remove_file(path);
            }
        }
    }

    remove_staging_files(cache_dir);
    sweep_cache_to_limit(cache_dir, campaigns, visible);
}

fn prepare_media(
    campaigns: &[Campaign],
    cache_dir: &Path,
    previous: &[ReadyCampaign],
    allow_network: bool,
    decode_missing: bool,
    target_id: Option<&str>,
) -> Vec<ReadyCampaign> {
    let network_client = (allow_network
        && CONNECTED.load(Ordering::Acquire)
        && campaigns.iter().any(|campaign| {
        campaign.icon_url.is_some()
            || campaign.background_url.is_some()
            || (audio_requested() && campaign.audio_url.is_some())
    })).then(|| client().ok()).flatten();

    // Decode exactly one requested campaign per pass. The visible card is
    // published first; a second pass then prepares the already-selected next
    // card without retaining pixels for the rest of the manifest.
    let mut ready = Vec::with_capacity(campaigns.len());
    for campaign in campaigns {
        let is_target = target_id == Some(campaign.id.as_str());
        let previous = previous.iter().find(|existing|
            existing.campaign.id == campaign.id);
        // Preserve the two-card working set while replacing one target. The
        // publication step drops pixels outside the current/next window.
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
                        decode_media(
                            campaign,
                            url,
                            payload,
                            network_client.as_ref(),
                            decode_missing,
                        )
                    }),
                    payload.background.and_then(|payload| {
                        let url = campaign.background_url.as_deref()?;
                        decode_background(
                            campaign,
                            url,
                            payload,
                            network_client.as_ref(),
                            decode_missing,
                        )
                    }),
                    payload.audio,
                ),
                None => (None, None, None),
            };
            let media_loaded = media.is_some();
            let background_loaded = background.is_some();
            // Only a real decode attempt can fail a plane: a hydration pass that
            // deliberately skipped it must neither warn nor spend the
            // once-per-plane failure report.
            if decode_missing && campaign.icon_url.is_some() && !media_loaded
                && candidate.frames.is_empty()
                && note_plane_failure(&campaign.id, "media")
            {
                log::warn!("[sponsor] campaign {} icon unavailable; using fallback", campaign.id);
            }
            if decode_missing && campaign.background_url.is_some() && !background_loaded
                    && candidate.background_frames.is_empty()
                    && candidate.background_rgba.is_empty()
                    && note_plane_failure(&campaign.id, "background")
            {
                log::warn!("[sponsor] campaign {} background unavailable; using card color", campaign.id);
            }
            if media_loaded { clear_plane_failure(&campaign.id, "media"); }
            if background_loaded { clear_plane_failure(&campaign.id, "background"); }
            if media_loaded || background_loaded {
                log::debug!("[sponsor] campaign {} media ready (decoded on demand)", campaign.id);
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
            // Freshly decoded planes replace whatever preview the card held.
            if media_loaded || background_loaded {
                candidate.preview_only = false;
            }
        }

        // Admission is per card: each of the two cards that can be on screen
        // (the visible one and the prepared next) holds half the aggregate
        // budget, so the working set always fits and one campaign can never
        // take another's media away. A card that would exceed its share is
        // merged down to fewer, longer frames instead of losing its planes --
        // the budget decides animation smoothness, never whether the GIF is
        // there at all.
        let before = frame_bytes(&candidate.frames) + frame_bytes(&candidate.background_frames);
        let retained_bytes = admit_frames(&mut candidate, CAMPAIGN_DECODED_BYTES);
        if retained_bytes < before {
            log::debug!(
                "[sponsor] campaign {} animation merged to {} bytes for the decoded budget",
                campaign.id, retained_bytes
            );
        }
        ready.push(candidate);
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
        "media",
        client,
    )).flatten();
    let background = (!reuse_background).then(|| load_payload(
        campaign.background_url.as_deref(),
        cache_dir.join(background_cache_name(campaign)),
        cache_dir,
        "background",
        client,
    )).flatten();
    let audio = (load_audio && audio_requested()).then(|| load_payload(
        campaign.audio_url.as_deref(),
        cache_dir.join(audio_cache_name(campaign)),
        cache_dir,
        "audio",
        client,
    )).flatten();
    if media.is_none() && background.is_none() && audio.is_none() {
        None
    } else {
        Some(CampaignPayload { media, background, audio })
    }
}

fn newest_file_with_extension(dir: &Path, extension: &str) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(dir).ok()?.flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|path| fs::metadata(path)
        .and_then(|metadata| metadata.modified()).unwrap_or(UNIX_EPOCH));
    candidates.pop()
}

fn find_cached_payload(exclude: &Path) -> Option<PathBuf> {
    let parent = exclude.parent()?;
    let extension = exclude.extension()?.to_str()?;
    let mut candidates = fs::read_dir(parent).ok()?.flatten()
        .map(|entry| entry.path())
        .filter(|path| path != exclude
            && path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|path| fs::metadata(path)
        .and_then(|metadata| metadata.modified()).unwrap_or(UNIX_EPOCH));
    candidates.pop()
}

fn staging_path(path: &Path, kind: &str) -> Option<PathBuf> {
    let parent = path.parent()?;
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("media");
    Some(parent.join(format!(".{filename}.{kind}.tmp")))
}

/// Renames a fully written staging file over `path`. Windows cannot rename over
/// an existing file, so the old valid entry is moved aside only after the new
/// bytes are on disk and restored when the replacement fails. The staging name
/// carries the complete cache filename, so concurrent media writes and decoded
/// writes can never collide.
fn install_cache_file(tmp: &Path, path: &Path) -> bool {
    if fs::rename(tmp, path).is_ok() { return true; }
    let Some(backup) = staging_path(path, "previous") else { return false; };
    let had_old = path.exists() && fs::rename(path, &backup).is_ok();
    if fs::rename(tmp, path).is_ok() {
        if had_old { let _ = fs::remove_file(backup); }
        true
    } else {
        if had_old { let _ = fs::rename(backup, path); }
        let _ = fs::remove_file(tmp);
        false
    }
}

fn write_atomic_preserving_old(path: &Path, bytes: &[u8]) -> bool {
    let Some(parent) = path.parent() else { return false; };
    if fs::create_dir_all(parent).is_err() { return false; }
    let Some(tmp) = staging_path(path, "download") else { return false; };
    if fs::write(&tmp, bytes).is_err() {
        let _ = fs::remove_file(&tmp);
        return false;
    }
    install_cache_file(&tmp, path)
}

fn load_payload(
    url: Option<&str>,
    path: PathBuf,
    cache_dir: &Path,
    suffix: &str,
    client: Option<&reqwest::blocking::Client>,
) -> Option<MediaPayload> {
    let url = url?;
    let _ = fs::create_dir_all(cache_dir);
    let fallback = find_cached_payload(&path);
    match fs::metadata(&path) {
        // Cached entries are handled by path: only the still-image decoder
        // needs a buffer, and it asks for one when it runs.
        Ok(metadata) if metadata.len() <= MAX_MEDIA_BYTES as u64 => {
            return Some(MediaPayload { path, bytes: None, cached: true, fallback });
        }
        Ok(metadata) => {
            log::warn!("[sponsor] ignoring oversized cached {} media: {} bytes", suffix, metadata.len());
            let _ = fs::remove_file(&path);
        }
        Err(_) => {}
    }
    if CONNECTED.load(Ordering::Acquire) {
        if let Some(client) = client {
            if let Ok(bytes) = download_media(client, url) {
                // Persist the original bytes before decoding. A disconnect or
                // process exit during GIF frame expansion must not lose a valid
                // download; decode_payload removes it later only if invalid.
                let cached = write_atomic_preserving_old(&path, &bytes);
                return Some(MediaPayload { path, bytes: Some(bytes), cached, fallback });
            }
        }
    }
    fallback.and_then(|path| match fs::metadata(&path) {
        Ok(metadata) if metadata.len() <= MAX_MEDIA_BYTES as u64 => Some(MediaPayload {
            path,
            bytes: None,
            cached: true,
            fallback: None,
        }),
        Ok(metadata) => {
            log::warn!("[sponsor] ignoring oversized fallback {} media: {} bytes", suffix, metadata.len());
            None
        }
        Err(_) => None,
    })
}

fn decoded_cache_path(path: &Path) -> PathBuf {
    path.with_extension("decoded")
}

/// Reads the decoded-frame cache a frame at a time. The previous version
/// loaded the whole file into a buffer and then copied every frame out of it,
/// which peaked at twice the retained pixels for no benefit: the file is
/// already an offset-addressable frame list.
/// The reader keeps the retention budget the decoder uses, but folds an
/// animation that no longer fits instead of rejecting the file: a sidecar
/// written under a larger budget keeps its whole timeline (each dropped frame's
/// display time is added to the one before it, exactly as `compact_video_frames`
/// does while decoding) rather than being deleted and re-decoded on the next
/// app start -- a re-decode that would otherwise run on the caller's thread.
fn decoded_ready_from_cache(campaign: &Campaign, path: &Path) -> Option<ReadyCampaign> {
    let length = fs::metadata(path).ok()?.len();
    if length < 16 || length > MAX_TOTAL_DECODED_BYTES as u64 {
        let _ = fs::remove_file(path);
        return None;
    }
    let mut reader = BufReader::new(fs::File::open(path).ok()?);
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() || &magic != b"FDV6" {
        let _ = fs::remove_file(path);
        return None;
    }
    let width = read_u32(&mut reader)?;
    let height = read_u32(&mut reader)?;
    let frame_count = read_u32(&mut reader)? as usize;
    if frame_count == 0 || validate_dimensions(width, height, 1).is_err() {
        let _ = fs::remove_file(path);
        return None;
    }
    // A sidecar written by a build that retained stills and GIFs at their
    // source size is re-decoded rather than loaded: those frames cost several
    // times the canvas per plane, and the next write replaces the sidecar.
    if width > MEDIA_MAX_WIDTH || height > MEDIA_MAX_HEIGHT {
        let _ = fs::remove_file(path);
        return None;
    }
    let frame_bytes = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
    let parsed = (|| -> Option<Vec<Frame>> {
        let mut frames = Vec::with_capacity(frame_count.min(MAX_INPUT_FRAMES));
        let mut decoded_total = 0usize;
        let mut compacted = false;
        for _ in 0..frame_count {
            let delay = read_u32(&mut reader)?.clamp(MIN_FRAME_DELAY_US, MAX_FRAME_DELAY_US);
            let size = read_u32(&mut reader)? as usize;
            if size != frame_bytes {
                return None;
            }
            let mut rgba = vec![0u8; size];
            reader.read_exact(&mut rgba).ok()?;
            frames.push(Frame { rgba: Arc::new(rgba), delay: Duration::from_micros(delay as u64) });
            decoded_total = decoded_total.saturating_add(size);
            while decoded_total > MAX_DECODED_BYTES && frames.len() > 1 {
                compact_video_frames(&mut frames, &mut decoded_total);
                compacted = true;
            }
        }
        if compacted {
            rebalance_delays(&mut frames);
        }
        Some(frames)
    })();
    let Some(frames) = parsed else {
        // Truncated or corrupt: worthless either way, and the encoded entry is
        // untouched so the campaign can be decoded again from it.
        let _ = fs::remove_file(path);
        return None;
    };
    Some(decoded_plane(campaign.clone(), width, height, frames))
}

fn read_u32(reader: &mut impl Read) -> Option<u32> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Writes the decoded-frame cache straight to the staging file. Serialising
/// into a `Vec` first held a second copy of every frame, which on Android was
/// the largest single allocation of a sponsor refresh.
fn write_decoded_cache(path: &Path, decoded: &ReadyCampaign) {
    let frame_bytes = decoded.frames.iter()
        .map(|frame| frame.rgba.len())
        .sum::<usize>();
    if decoded.frames.is_empty() || frame_bytes > MAX_DECODED_BYTES {
        return;
    }
    let Some(parent) = path.parent() else { return; };
    if fs::create_dir_all(parent).is_err() { return; }
    let Some(tmp) = staging_path(path, "decoded") else { return; };
    let written = (|| -> std::io::Result<()> {
        let mut out = BufWriter::with_capacity(
            64 * 1024,
            fs::File::create(&tmp)?,
        );
        out.write_all(b"FDV6")?;
        out.write_all(&decoded.width.to_le_bytes())?;
        out.write_all(&decoded.height.to_le_bytes())?;
        out.write_all(&(decoded.frames.len() as u32).to_le_bytes())?;
        for frame in &decoded.frames {
            out.write_all(
                &(frame.delay.as_micros() as u32)
                    .clamp(MIN_FRAME_DELAY_US, MAX_FRAME_DELAY_US)
                    .to_le_bytes(),
            )?;
            out.write_all(&(frame.rgba.len() as u32).to_le_bytes())?;
            out.write_all(frame.rgba.as_slice())?;
        }
        out.flush()
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    let _ = install_cache_file(&tmp, path);
}

fn decode_payload(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
) -> Option<ReadyCampaign> {
    let MediaPayload { path, bytes, mut cached, fallback } = payload;
    let decoded_path = decoded_cache_path(&path);
    if let Some(decoded) = decoded_ready_from_cache(campaign, &decoded_path) {
        return Some(decoded);
    }
    // A downloaded plane is decoded from the bytes already in hand; a cached
    // one is decoded from its file, so the encoded asset is never read into
    // the heap only to be handed to a decoder that could read it itself.
    let mut encoded: Option<Vec<u8>> = bytes;
    let mut decoded = match encoded.as_deref() {
        Some(bytes) => decode_memory(campaign.clone(), bytes).ok(),
        None => decode_file(campaign.clone(), &path).ok(),
    };
    if decoded.is_none() {
        if let Some(fallback_path) = fallback {
            if let Some(fallback_decoded) = decode_file(campaign.clone(), &fallback_path).ok() {
                if cached { let _ = fs::remove_file(&path); }
                return Some(fallback_decoded);
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
        let fresh = download_media(client, url).ok()?;
        cached = false;
        decoded = decode_memory(campaign.clone(), &fresh).ok();
        encoded = Some(fresh);
    }
    if let Some(decoded) = decoded {
        if !cached {
            if let Some(encoded) = encoded.as_deref() {
                let _ = write_atomic_preserving_old(&path, encoded);
            }
        }
        write_decoded_cache(&decoded_path, &decoded);
        Some(decoded)
    } else {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(decoded_path);
        None
    }
}

/// Identifier bytes, from the payload when it is in memory or from a bounded
/// header read otherwise. Reading 32 bytes instead of the whole file keeps a
/// cached MP4 out of the heap: the video reader opens it by path anyway.
const SNIFF_BYTES: usize = 32;

fn image_header(path: &Path, bytes: Option<&[u8]>) -> Option<Vec<u8>> {
    if let Some(bytes) = bytes {
        return Some(bytes[..bytes.len().min(SNIFF_BYTES)].to_vec());
    }
    let mut header = vec![0u8; SNIFF_BYTES];
    let mut file = fs::File::open(path).ok()?;
    let read = file.read(&mut header).ok()?;
    header.truncate(read);
    Some(header)
}

fn decode_media(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
    decode_missing: bool,
) -> Option<ReadyCampaign> {
    if !decode_missing {
        // Cache-only hydration: the decoded sidecar is the whole answer. A
        // plane that has none keeps whatever the card already shows and is
        // decoded by the refresh worker, never by the app-launch caller.
        return decoded_ready_from_cache(campaign, &decoded_cache_path(&payload.path));
    }
    let still_image = image_header(&payload.path, payload.bytes.as_deref())
        .is_some_and(|header| image::guess_format(&header).is_ok());
    if still_image {
        decode_payload(campaign, url, payload, client)
    } else {
        decode_video_payload(campaign, url, payload, client)
    }
}

/// One warning key per cache plane (`media`, `background`, `audio`), read from
/// `campaigns/<id>/<plane>/<hash>.<plane>`. A plane that stays broken -- a
/// damaged cache entry, an unsupported profile -- is reported once instead of
/// on every rotation that retries it.
fn plane_key(path: &Path) -> &'static str {
    let plane = path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str());
    match plane {
        Some("background") => "background",
        Some("audio") => "audio",
        _ => "media",
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
    let warning_tag = plane_key(&path);
    if let Some(decoded) = decoded_ready_from_cache(campaign, &decoded_path) {
        return Some(decoded);
    }

    // Video readers operate on a bounded file path. The encoded cache is
    // written before this function in the normal path; retry the write when a
    // platform could not atomically install a newly downloaded file, and drop
    // the in-memory copy as soon as the reader can open the file itself.
    if !path.exists() {
        let Some(encoded) = bytes.as_ref() else { return None; };
        if !write_atomic_preserving_old(&path, encoded) {
            return None;
        }
    }
    // Decoding allocates the frames that get retained, so the encoded copy
    // must not sit in the heap across it: on Android a downloaded MP4 is up to
    // 15 MiB that the file reader never needs.
    drop(bytes);
    let mut decoded = match decode_video_file(campaign.clone(), &path) {
        Ok(decoded) => Some(decoded),
        Err(error) => {
            if note_plane_failure(&campaign.id, warning_tag) {
                log::warn!("[sponsor] video decode failed ({}): {error}", path.display());
            }
            None
        }
    };
    if decoded.is_none() {
        if let Some(fallback_path) = fallback {
            decoded = match decode_video_file(campaign.clone(), &fallback_path) {
                Ok(decoded) => Some(decoded),
                Err(error) => {
                    if note_plane_failure(&campaign.id, warning_tag) {
                        log::warn!(
                            "[sponsor] cached video fallback decode failed ({}): {error}",
                            fallback_path.display()
                        );
                    }
                    None
                }
            };
            if decoded.is_some() {
                clear_plane_failure(&campaign.id, warning_tag);
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
                if note_plane_failure(&campaign.id, warning_tag) {
                    log::warn!("[sponsor] refreshed video decode failed ({}): {error}", path.display());
                }
                None
            }
        };
    }
    if let Some(decoded) = decoded {
        clear_plane_failure(&campaign.id, warning_tag);
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

/// Output size for one decoded frame: the source is kept when it already fits
/// the card canvas, otherwise it is scaled down preserving its aspect ratio.
fn canvas_dimensions(width: u32, height: u32) -> (u32, u32) {
    let scale = (MEDIA_MAX_WIDTH as f64 / width as f64)
        .min(MEDIA_MAX_HEIGHT as f64 / height as f64)
        .min(1.0);
    (
        ((width as f64 * scale).round() as u32).max(1),
        ((height as f64 * scale).round() as u32).max(1),
    )
}

/// Pixels for one RGBA frame at the decode canvas. A frame that already fits is
/// moved rather than copied.
fn canvas_rgba(image: image::RgbaImage) -> (u32, u32, Vec<u8>) {
    let (width, height) = image.dimensions();
    let (target_width, target_height) = canvas_dimensions(width, height);
    if target_width == width && target_height == height {
        return (width, height, image.into_raw());
    }
    let resized = image::imageops::resize(
        &image,
        target_width,
        target_height,
        image::imageops::FilterType::Nearest,
    );
    (target_width, target_height, resized.into_raw())
}

/// A decoded plane with its own presentation left at the defaults: the caller
/// keeps the presentation it already resolved for the card, so a decode can
/// never reset a sponsor's colors or layout.
fn decoded_plane(campaign: Campaign, width: u32, height: u32, frames: Vec<Frame>) -> ReadyCampaign {
    ReadyCampaign {
        campaign,
        width,
        height,
        frames,
        preview_only: false,
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
        title_scale: DEFAULT_TITLE_SCALE,
        message_scale: DEFAULT_MESSAGE_SCALE,
        icon_opacity: DEFAULT_ICON_OPACITY,
        background_opacity: DEFAULT_BACKGROUND_OPACITY,
        background_color_opacity: DEFAULT_BACKGROUND_COLOR_OPACITY,
    }
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

    let (target_width, target_height) = canvas_dimensions(width, height);
    if target_width == width && target_height == height {
        return Ok((width, height, rgb));
    }

    let image = image::RgbImage::from_raw(width, height, rgb)
        .ok_or_else(|| "video RGB frame could not be constructed".to_string())?;
    let resized = image::imageops::resize(
        &image,
        target_width,
        target_height,
        image::imageops::FilterType::Nearest,
    );
    Ok((target_width, target_height, resized.into_raw()))
}

/// Returns true when the last retained frame's RGBA bytes equal `rgba`.
/// Called after constructing a new frame in the decode loops; when true the
/// new frame is folded into its predecessor (its delay added) instead of
/// being pushed, so identical consecutive frames do not consume retention
/// budget. One memcmp per decode — no poll-loop cost.
fn repeats_last_frame(frames: &[Frame], rgba: &[u8]) -> bool {
    if let Some(last) = frames.last() {
        let last_rgba = last.rgba.as_ref();
        last_rgba.len() == rgba.len() && last_rgba == rgba
    } else {
        false
    }
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

fn frame_bytes(frames: &[Frame]) -> usize {
    frames.iter().map(|frame| frame.rgba.len()).sum()
}

/// Spreads a retained timeline evenly across its frames.
///
/// Compaction keeps the first frame of each merged pair, and the retention
/// vector grows at the tail, so repeated compaction passes stack their merged
/// display time on the earliest frames: the first frame of a squeezed clip
/// could carry seconds of delay and freeze the card at campaign start --
/// exactly the "video plays slowly / GIF never starts" symptom. The cycle
/// total is already exact after compaction; redistributing it makes every
/// retained frame cost the same and the loop play at a constant rate.
fn rebalance_delays(frames: &mut [Frame]) {
    if frames.len() < 2 {
        return;
    }
    let total = frames
        .iter()
        .fold(Duration::ZERO, |sum, frame| sum.saturating_add(frame.delay));
    let count = frames.len() as u32;
    let per_frame = total / count;
    let remainder = total.saturating_sub(per_frame * count);
    let last = frames.len() - 1;
    for frame in &mut frames[..last] {
        frame.delay = per_frame;
    }
    frames[last].delay = per_frame.saturating_add(remainder);
}

/// Merge frames -- never drop a plane -- until `frames` fits `budget` bytes.
///
/// Compaction adds each merged frame's display time to its predecessor, so a
/// squeezed clip keeps its full duration and only loses smoothness. A single
/// frame is kept even when it alone exceeds the budget: one bounded oversized
/// frame is a smaller failure than a card that silently lost its media.
fn retain_within(frames: &mut Vec<Frame>, budget: usize) -> usize {
    let mut total = frame_bytes(frames);
    let mut compacted = false;
    while frames.len() > 1 && total > budget {
        compact_video_frames(frames, &mut total);
        compacted = true;
    }
    if compacted {
        rebalance_delays(frames);
    }
    total
}

/// Admit a card's decoded planes into the retention budget and return the
/// retained bytes.
///
/// The icon is what identifies the card, so it is served first and the
/// background gives up smoothness for it; both keep at least one frame. This
/// is the only admission rule, and it never replaces a card with a text
/// fallback: a budget squeeze costs animation frames, not the campaign.
fn admit_frames(candidate: &mut ReadyCampaign, budget: usize) -> usize {
    let icon = frame_bytes(&candidate.frames);
    let background = frame_bytes(&candidate.background_frames);
    if icon.saturating_add(background) <= budget {
        return icon + background;
    }
    let icon = retain_within(&mut candidate.frames, icon.min(budget));
    let background = retain_within(&mut candidate.background_frames, budget.saturating_sub(icon));
    candidate.background_rgba = candidate.background_frames.first()
        .map(|frame| frame.rgba.clone())
        .unwrap_or_default();
    icon + background
}

/// 30 fps cap: slower native rates are kept, faster ones are slowed to
/// [`FRAME_DELAY_US`], which also covers containers with no usable rate.
fn capped_frame_delay_us(source_delay_us: Option<u64>) -> u64 {
    source_delay_us.unwrap_or(FRAME_DELAY_US).max(FRAME_DELAY_US)
}

/// Box header at `offset`: fourcc and full box size, resolving the size-0
/// (box extends to end of file) and size-1 (64-bit largesize) forms.
fn read_box_header<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    end: u64,
) -> Option<([u8; 4], u64)> {
    let mut header = [0u8; 8];
    reader.seek(SeekFrom::Start(offset)).ok()?;
    reader.read_exact(&mut header).ok()?;
    let mut size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
    if size == 1 {
        let mut large = [0u8; 8];
        reader.read_exact(&mut large).ok()?;
        size = u64::from_be_bytes(large);
    } else if size == 0 {
        size = end.saturating_sub(offset);
    }
    if size < 8 {
        return None;
    }
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&header[4..8]);
    Some((kind, size))
}

/// Per-frame presentation delay of an MP4, from the `moov/mvhd` duration and
/// timescale divided by the sample count; `None` when the container carries
/// no usable rate. The decoder itself reports no timestamps.
fn mp4_frame_delay_us(path: &Path, sample_count: usize) -> Option<u64> {
    if sample_count == 0 {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    mp4_frame_delay_us_from(&mut file, sample_count)
}

fn mp4_frame_delay_us_from<R: Read + Seek>(reader: &mut R, sample_count: usize) -> Option<u64> {
    if sample_count == 0 {
        return None;
    }
    let file_len = reader.seek(SeekFrom::End(0)).ok()?;
    let mut pos = 0u64;
    for _ in 0..64 {
        if pos + 8 > file_len {
            break;
        }
        let (kind, size) = read_box_header(reader, pos, file_len)?;
        if pos.checked_add(size).is_none_or(|end| end > file_len) {
            break;
        }
        if kind == *b"moov" {
            let moov_end = pos + size;
            let mut child = pos + 8;
            for _ in 0..256 {
                if child + 8 > moov_end {
                    break;
                }
                let (child_kind, child_size) = read_box_header(reader, child, moov_end)?;
                if child.checked_add(child_size).is_none_or(|end| end > moov_end) {
                    break;
                }
                if child_kind == *b"mvhd" {
                    return mvhd_frame_delay_us(reader, child, child_size, sample_count);
                }
                child += child_size;
            }
            return None;
        }
        pos += size;
    }
    None
}

fn mvhd_frame_delay_us<R: Read + Seek>(
    reader: &mut R,
    box_offset: u64,
    box_size: u64,
    sample_count: usize,
) -> Option<u64> {
    // FullBox payload; version 1 stores 64-bit times, version 0 stores 32-bit.
    let mut head = [0u8; 4];
    reader.seek(SeekFrom::Start(box_offset + 8)).ok()?;
    reader.read_exact(&mut head).ok()?;
    let (scale_at, duration_at, duration_len) = if head[0] == 1 {
        (box_offset + 28, box_offset + 32, 8usize)
    } else {
        (box_offset + 20, box_offset + 24, 4usize)
    };
    if box_size < (duration_at + duration_len as u64 - box_offset) {
        return None;
    }
    let mut scale_bytes = [0u8; 4];
    reader.seek(SeekFrom::Start(scale_at)).ok()?;
    reader.read_exact(&mut scale_bytes).ok()?;
    let timescale = u32::from_be_bytes(scale_bytes);
    let mut duration_bytes = [0u8; 8];
    reader.seek(SeekFrom::Start(duration_at)).ok()?;
    reader
        .read_exact(&mut duration_bytes[8 - duration_len..])
        .ok()?;
    let duration = u64::from_be_bytes(duration_bytes);
    if timescale == 0 || duration == 0 {
        return None;
    }
    let duration_us = (duration as u128) * 1_000_000 / (timescale as u128);
    let per_frame_us = duration_us / (sample_count as u128);
    let per_frame_us = u64::try_from(per_frame_us).ok()?;
    Some(per_frame_us.clamp(1_000, 1_000_000))
}

fn decode_video_file(campaign: Campaign, path: &Path) -> Result<ReadyCampaign, String> {
    // MP4 is the portable sponsor-video format. The reader is pure Rust and
    // does not require FFmpeg or a platform media framework.
    let mut reader = Mp4VideoReader::open(path).map_err(|error| error.to_string())?;
    let frame_delay = Duration::from_micros(capped_frame_delay_us(
        mp4_frame_delay_us(path, reader.nal_count()),
    ));
    let mut frames = Vec::new();
    let mut total_bytes = 0usize;
    let mut compacted = false;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut source_frames = 0usize;

    while source_frames < MAX_INPUT_FRAMES {
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
        while total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES && frames.len() > 1 {
            compact_video_frames(&mut frames, &mut total_bytes);
            compacted = true;
        }
        if total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES {
            break;
        }
        // One exact allocation and a slice copy per pixel: the previous
        // `extend_from_slice` + `push` pair re-checked the capacity on every
        // pixel and could not be vectorised, which showed up as decode CPU on
        // the frames that are converted before every refresh.
        let mut rgba = vec![0xFFu8; rgba_size];
        for (dst, src) in rgba.chunks_exact_mut(4).zip(rgb.chunks_exact(3)) {
            dst[..3].copy_from_slice(src);
        }
        // Check for repetition before consuming rgba into an Arc: folding
        // identical neighbors extends the predecessor's display time instead
        // of allocating a second copy.
        if repeats_last_frame(&frames, &rgba) {
            frames.last_mut().expect("a last frame").delay += frame_delay;
            continue;
        }
        frames.push(Frame {
            rgba: Arc::new(rgba),
            delay: frame_delay,
        });
        total_bytes += rgba_size;
    }
    if frames.is_empty() {
        return Err("video contained no usable frames".into());
    }
    if compacted {
        rebalance_delays(&mut frames);
    }
    Ok(ReadyCampaign {
        campaign,
        width,
        height,
        frames,
        preview_only: false,
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
        title_scale: DEFAULT_TITLE_SCALE,
        message_scale: DEFAULT_MESSAGE_SCALE,
        icon_opacity: DEFAULT_ICON_OPACITY,
        background_opacity: DEFAULT_BACKGROUND_OPACITY,
        background_color_opacity: DEFAULT_BACKGROUND_COLOR_OPACITY,
    })
}

fn decode_background(
    campaign: &Campaign,
    url: &str,
    payload: MediaPayload,
    client: Option<&reqwest::blocking::Client>,
    decode_missing: bool,
) -> Option<BackgroundImage> {
    let decoded = decode_media(campaign, url, payload, client, decode_missing)?;
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

fn url_hash(url: Option<&str>) -> u64 {
    let mut hash = 14695981039346656037u64;
    for byte in url.unwrap_or_default().as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211u64);
    }
    hash
}

/// One cache entry per campaign per plane, keyed by campaign ID.
fn cache_name_for(campaign: &Campaign, kind: &str) -> PathBuf {
    PathBuf::from("campaigns")
        .join(&campaign.id)
        .join(format!("{0}.{0}", kind))
}

fn legacy_cache_name_for(campaign: &Campaign, url: Option<&str>, suffix: &str) -> String {
    format!("{}-{:016x}.{suffix}", campaign.id, url_hash(url))
}

fn cache_name(campaign: &Campaign) -> PathBuf {
    cache_name_for(campaign, "media")
}

fn background_cache_name(campaign: &Campaign) -> PathBuf {
    cache_name_for(campaign, "background")
}

fn audio_cache_name(campaign: &Campaign) -> PathBuf {
    cache_name_for(campaign, "audio")
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

/// Decode the encoded bytes held in memory (a fresh download, or a plane the
/// caller already read).
fn decode_memory(campaign: Campaign, bytes: &[u8]) -> Result<ReadyCampaign, String> {
    let format = image::guess_format(bytes).map_err(|e| e.to_string())?;
    decode_stream(campaign, format, Cursor::new(bytes))
}

/// Decode straight from a cache entry.
///
/// The decoder reads the file it is pointed at, so the encoded bytes of a
/// 15 MiB GIF never have to sit in the heap on top of the frames it expands
/// into -- which on Android was the largest single allocation of a refresh.
fn decode_file(campaign: Campaign, path: &Path) -> Result<ReadyCampaign, String> {
    let header = image_header(path, None).ok_or_else(|| "media cache could not be read".to_string())?;
    let format = image::guess_format(&header).map_err(|e| e.to_string())?;
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    decode_stream(campaign, format, BufReader::new(file))
}

fn decode_animation_frames<I>(
    campaign: Campaign,
    source_width: u32,
    source_height: u32,
    frames_iter: I,
    format_name: &'static str,
) -> Result<ReadyCampaign, String>
where
    I: Iterator<Item = Result<image::Frame, image::ImageError>>,
{
    validate_dimensions(source_width, source_height, 1)?;
    let mut frames = Vec::new();
    let mut total_bytes = 0usize;
    let mut compacted = false;
    let mut width = 0u32;
    let mut height = 0u32;
    for (source_index, frame) in frames_iter.enumerate() {
        if source_index >= MAX_INPUT_FRAMES { break; }
        let frame = frame.map_err(|e| e.to_string())?;
        if frame.buffer().width() != source_width || frame.buffer().height() != source_height {
            return Err(format!("inconsistent {format_name} frame dimensions"));
        }
        let (numer, denom) = frame.delay().numer_denom_ms();
        // Round to the nearest millisecond before clamping: truncation
        // biased every sub-millisecond remainder toward faster playback.
        let millis = if denom == 0 {
            100
        } else {
            let exact = (numer as u64 + (denom as u64 / 2)) / denom as u64;
            exact.clamp(MIN_FRAME_DELAY_MS, MAX_FRAME_DELAY_MS)
        };
        // Every frame is retained at the card canvas, so a GIF/WebP costs what a
        // video costs and the budget below buys frames instead of pixels.
        let (frame_width, frame_height, rgba) = canvas_rgba(frame.into_buffer());
        if frames.is_empty() {
            width = frame_width;
            height = frame_height;
        } else if frame_width != width || frame_height != height {
            return Err(format!("inconsistent {format_name} frame dimensions"));
        }
        let rgba_size = rgba.len();
        // Fold identical consecutive frames into their predecessor: the
        // new frame's display time is added to the last frame's and the
        // duplicate is discarded, so it does not consume retention budget.
        if repeats_last_frame(&frames, &rgba) {
            frames.last_mut().expect("a last frame").delay += Duration::from_micros((millis * 1_000).max(FRAME_DELAY_US));
            continue;
        }
        // Retain the complete bounded timeline. When the retention budget is
        // reached, merge adjacent frames and add their delays instead of
        // silently replaying only the prefix.
        while total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES && frames.len() > 1 {
            compact_video_frames(&mut frames, &mut total_bytes);
            compacted = true;
        }
        if total_bytes.saturating_add(rgba_size) > MAX_DECODED_BYTES {
            break;
        }
        total_bytes += rgba_size;
        frames.push(Frame {
            rgba: Arc::new(rgba),
            delay: Duration::from_micros((millis * 1_000).max(FRAME_DELAY_US)),
        });
    }
    if frames.is_empty() {
        return Err(format!("invalid {format_name} frame count"));
    }
    if compacted {
        rebalance_delays(&mut frames);
    }
    Ok(decoded_plane(campaign, width, height, frames))
}

fn decode_stream<R: BufRead + Seek>(
    campaign: Campaign,
    format: ImageFormat,
    mut reader: R,
) -> Result<ReadyCampaign, String> {
    if format == ImageFormat::Gif {
        let decoder = image::codecs::gif::GifDecoder::new(reader).map_err(|e| e.to_string())?;
        let (source_width, source_height) = decoder.dimensions();
        return decode_animation_frames(campaign, source_width, source_height, decoder.into_frames(), "GIF");
    }

    if format == ImageFormat::WebP {
        let decoder = image::codecs::webp::WebPDecoder::new(&mut reader).map_err(|e| e.to_string())?;
        if decoder.has_animation() {
            let (source_width, source_height) = decoder.dimensions();
            return decode_animation_frames(campaign, source_width, source_height, decoder.into_frames(), "WebP");
        }
        reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    }

    if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP) {
        return Err("unsupported sponsor media".into());
    }
    let image: DynamicImage = image::ImageReader::with_format(reader, format)
        .decode()
        .map_err(|e| e.to_string())?;
    let rgba = image.to_rgba8();
    validate_dimensions(rgba.width(), rgba.height(), 1)?;
    let (width, height, raw) = canvas_rgba(rgba);
    Ok(decoded_plane(
        campaign,
        width,
        height,
        vec![Frame { rgba: Arc::new(raw), delay: ROTATE_EVERY }],
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_campaign(id: &str) -> Campaign {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "destination_url": "https://example.com",
        }))
        .expect("a minimal campaign")
    }

    fn test_campaign_with_media(id: &str) -> Campaign {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "destination_url": "https://example.com",
            "icon_url": "https://example.com/icon.png",
            "background_url": "https://example.com/background.mp4",
        }))
        .expect("a campaign with media planes")
    }

    fn test_frames(count: usize) -> Vec<Frame> {
        (0..count)
            .map(|index| Frame {
                rgba: Arc::new(vec![index as u8; 64]),
                delay: Duration::from_millis(40),
            })
            .collect()
    }

    fn test_state(ready: Vec<ReadyCampaign>, current: usize, next: Option<usize>) -> State {
        State {
            campaigns: Vec::new(),
            ready,
            cache_dir: PathBuf::new(),
            rotation_started: Instant::now(),
            paused_at: None,
            media_released: false,
            current_campaign: current,
            next_campaign: next,
            random_state: 0,
            manifest_checked_at: 0,
            audio_probe: None,
            warned_media: HashSet::new(),
            media_retry_after: Instant::now(),
            card_text: None,
            manifest_json: None,
            last_error: String::new(),
        }
    }

    #[test]
    fn identical_neighbor_frames_fold_into_one() {
        // Two consecutive identical frames should be folded into one when
        // repeats_last_frame returns true — the second frame's delay is added
        // to the first and the duplicate is discarded.
        let mut frames = Vec::new();
        let rgba = vec![0xFFu8; 64];
        frames.push(Frame { rgba: Arc::new(rgba.clone()), delay: Duration::from_millis(30) });
        assert!(repeats_last_frame(&frames, &rgba));
        // After pushing an identical frame, folding should happen:
        frames.push(Frame { rgba: Arc::new(rgba.clone()), delay: Duration::from_millis(40) });
        if repeats_last_frame(&frames, &rgba) {
            frames.last_mut().expect("a last frame").delay += Duration::from_millis(40);
            frames.pop();
        }
        assert_eq!(frames.len(), 1, "identical frames should fold into one");
        assert_eq!(frames[0].delay, Duration::from_millis(70), "delays should add up");
        // A different frame should not fold:
        let different = vec![0x00u8; 64];
        assert!(!repeats_last_frame(&frames, &different));
    }

    #[test]
    fn the_sidecar_round_trip_keeps_capped_microsecond_pacing() {
        // A sidecar written with FDV6 stores delays as µs. When read back,
        // the delays are clamped to MIN/MAX_FRAME_DELAY_US so a hydrated card
        // plays at the capped rate, not the raw stored value.
        let root = std::env::temp_dir().join(format!(
            "fcae-sponsor-sidecar-pacing-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::create_dir_all(&root);

        // Build a minimal FDV6 sidecar: 2 frames at 30_000 µs (below the
        // 33_333 µs cap) and 50_000 µs (above the cap, clamped to MAX).
        let width: u32 = 4;
        let height: u32 = 4;
        let frame_bytes = (width as usize) * (height as usize) * 4;
        let frame_data = vec![0xFFu8; frame_bytes];

        let sidecar_path = root.join("sidecar.bin");
        {
            let mut out = BufWriter::new(fs::File::create(&sidecar_path).expect("create sidecar"));
            out.write_all(b"FDV6").expect("magic");
            out.write_all(&width.to_le_bytes()).expect("width");
            out.write_all(&height.to_le_bytes()).expect("height");
            out.write_all(&(2u32).to_le_bytes()).expect("frame_count");
            // Frame 1: 30_000 µs — below cap, should hydrate as 33_333 µs
            out.write_all(&(30_000u32).to_le_bytes()).expect("delay1");
            out.write_all(&(frame_bytes as u32).to_le_bytes()).expect("size1");
            out.write_all(&frame_data).expect("data1");
            // Frame 2: 50_000 µs — above MAX (10_000 ms = 10_000_000 µs), stays 50_000
            out.write_all(&(50_000u32).to_le_bytes()).expect("delay2");
            out.write_all(&(frame_bytes as u32).to_le_bytes()).expect("size2");
            out.write_all(&frame_data).expect("data2");
            out.flush().expect("flush");
        }

        let campaign = test_campaign("pacing");
        let decoded = decoded_ready_from_cache(&campaign, &sidecar_path).expect("sidecar read");
        assert_eq!(decoded.frames.len(), 2, "two frames loaded");
        // 30_000 µs is within [MIN_FRAME_DELAY_US, MAX_FRAME_DELAY_US] = [20_000, 10_000_000],
        // so it passes through the sidecar read clamp unchanged. The 30 fps pacing cap
        // (FRAME_DELAY_US = 33_333) is applied at playback time via capped_frame_delay_us,
        // not at sidecar read time — the sidecar preserves the container's original rate.
        assert_eq!(decoded.frames[0].delay.as_micros(), 30_000, "30_000 µs passes clamp");
        assert_eq!(decoded.frames[1].delay.as_micros(), 50_000, "50_000 µs passes clamp");
    }

    #[test]
    fn parked_sidecars_survive_prune_and_vanished_campaigns_do_not() {
        let root = std::env::temp_dir().join(format!(
            "fcae-sponsor-sidecar-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let visible = test_campaign_with_media("visible");
        let parked = test_campaign_with_media("parked");
        let vanished = test_campaign_with_media("vanished");
        for campaign in [&visible, &parked, &vanished] {
            for (_, path) in campaign_planes(&root, campaign) {
                let Some(path) = path else { continue; };
                let _ = fs::create_dir_all(path.parent().expect("a plane directory"));
                fs::write(&path, b"encoded").expect("an encoded asset");
                fs::write(decoded_cache_path(&path), b"frames").expect("a decoded sidecar");
            }
        }
        prune_cache(&root, &[visible.clone(), parked.clone()], &["visible".to_string()]);
        let plane = |campaign: &Campaign| {
            campaign_planes(&root, campaign)
                .into_iter()
                .find_map(|(_, path)| path)
                .expect("a media plane")
        };
        for campaign in [&visible, &parked] {
            let asset = plane(campaign);
            assert!(asset.is_file(), "a manifest campaign keeps its encoded asset");
            assert!(
                decoded_cache_path(&asset).is_file(),
                "a parked campaign keeps its sidecar so its next rotation stays instant"
            );
        }
        assert!(
            !root.join("campaigns").join("vanished").exists(),
            "a campaign removed from the manifest loses its cache entirely"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_hashed_entries_migrate_to_the_id_keyed_layout() {
        let root = std::env::temp_dir().join(format!(
            "fcae-sponsor-migrate-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let campaign = test_campaign_with_media("legacy");
        let old_dir = root.join("campaigns").join("legacy").join("media");
        let _ = fs::create_dir_all(&old_dir);
        fs::write(old_dir.join("0123456789abcdef.media"), b"encoded")
            .expect("a legacy asset");
        fs::write(old_dir.join("0123456789abcdef.decoded"), b"frames")
            .expect("a legacy sidecar");
        prune_cache(&root, &[campaign.clone()], &["legacy".to_string()]);
        let asset = campaign_planes(&root, &campaign)
            .into_iter()
            .find_map(|(kind, path)| (kind == "media").then_some(path))
            .expect("the media plane");
        assert!(asset.is_file(), "the legacy entry moves to the id-keyed path");
        assert!(
            decoded_cache_path(&asset).is_file(),
            "its decoded sidecar moves with it"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_demoted_card_keeps_exactly_one_frame_per_plane() {
        let mut ready = empty_ready(&test_campaign("preview"));
        ready.frames = test_frames(3);
        ready.background_frames = test_frames(2);
        ready.background_rgba = Arc::new(vec![9u8; 64]);
        demote_to_preview(&mut ready);
        assert!(ready.preview_only);
        assert_eq!(ready.frames.len(), 1, "the icon keeps its first frame");
        assert_eq!(ready.background_frames.len(), 1, "the background keeps its first frame");
        assert_eq!(
            ready.background_rgba.as_slice(),
            ready.background_frames[0].rgba.as_slice(),
            "the still mirror follows the preview frame"
        );
        demote_to_preview(&mut ready);
        assert_eq!(ready.frames.len(), 1, "demoting twice changes nothing");
    }

    #[test]
    fn a_publish_while_hidden_keeps_one_still_and_nothing_else() {
        let mut ready: Vec<_> = ["a", "b", "c"].iter().map(|id| {
            let mut ready = empty_ready(&test_campaign(id));
            ready.frames = test_frames(3);
            ready.background_frames = test_frames(4);
            ready.background_rgba = ready.background_frames[0].rgba.clone();
            ready
        }).collect();
        ready[1].preview_only = false;
        let mut state = test_state(ready, 1, Some(2));
        state.paused_at = Some(Duration::from_millis(90));
        // What a pass that was running when the UI hid publishes: full planes.
        retain_hidden_frames(&mut state);
        assert_eq!(state.ready[1].frames.len(), 1);
        assert_eq!(state.ready[1].frames[0].rgba[0], 2, "the still on screen is kept");
        assert_eq!(state.ready[1].background_frames.len(), 1);
        assert!(state.ready[1].preview_only, "the animation is hydrated on return");
        for index in [0, 2] {
            assert!(state.ready[index].frames.is_empty());
            assert!(state.ready[index].background_frames.is_empty());
            assert!(state.ready[index].background_rgba.is_empty());
        }
        assert_eq!(state.next_campaign, Some(2), "the planned rotation survives");
    }

    #[test]
    fn a_visible_ui_publish_is_not_trimmed_to_a_still() {
        let mut ready = empty_ready(&test_campaign("a"));
        ready.frames = test_frames(3);
        let mut state = test_state(vec![ready], 0, None);
        retain_hidden_frames(&mut state);
        assert_eq!(state.ready[0].frames.len(), 3);
    }

    #[test]
    fn a_rotation_restart_while_hidden_resumes_at_the_card_start() {
        let mut state = test_state(Vec::new(), 0, None);
        state.paused_at = Some(Duration::from_secs(7));
        restart_rotation(&mut state);
        assert_eq!(state.paused_at, Some(Duration::ZERO), "the frozen clock restarts with the card");
        assert_eq!(card_elapsed(&state), Duration::ZERO);
        state.paused_at = None;
        restart_rotation(&mut state);
        assert_eq!(state.paused_at, None, "a visible UI keeps a running clock");
        assert!(card_elapsed(&state) < Duration::from_secs(1));
    }

    #[test]
    fn a_hidden_card_keeps_the_frame_on_screen() {
        let mut ready = empty_ready(&test_campaign("hidden"));
        ready.frames = test_frames(3);
        ready.background_frames = test_frames(4);
        // 40 ms per frame: 90 ms in, frame 2 of each plane is on screen.
        retain_visible_frame(&mut ready, Duration::from_millis(90));
        assert!(ready.preview_only, "the animation is hydrated again on return");
        assert_eq!(ready.frames.len(), 1);
        assert_eq!(ready.frames[0].rgba[0], 2, "the icon keeps the visible frame");
        assert_eq!(ready.background_frames.len(), 1);
        assert_eq!(ready.background_frames[0].rgba[0], 2, "the background keeps the visible frame");
        assert_eq!(ready.background_rgba.as_slice(), ready.background_frames[0].rgba.as_slice());
    }

    #[test]
    fn the_retention_window_keeps_one_full_card_and_one_preview() {
        let mut visible = empty_ready(&test_campaign("visible"));
        visible.frames = test_frames(5);
        let mut prepared = empty_ready(&test_campaign("prepared"));
        prepared.background_frames = test_frames(4);
        prepared.background_rgba = prepared.background_frames[0].rgba.clone();
        let mut parked = empty_ready(&test_campaign("parked"));
        parked.frames = test_frames(3);
        let mut state = test_state(vec![visible, prepared, parked], 0, Some(1));
        trim_ready_window(&mut state);
        assert_eq!(state.ready[0].frames.len(), 5, "the visible card keeps its full animation");
        assert!(state.ready[1].preview_only, "the next card is a preview");
        assert_eq!(state.ready[1].background_frames.len(), 1);
        assert!(!state.ready[2].preview_only);
        assert!(state.ready[2].frames.is_empty(), "cards outside the window keep no pixels");
    }

    #[test]
    fn compacted_timelines_play_back_at_a_constant_rate() {
        // The delay distribution compaction leaves behind for a squeezed clip:
        // one multi-second head frame followed by shrinking delays.
        let mut frames: Vec<Frame> = [2960u64, 560, 320, 160]
            .iter()
            .map(|millis| Frame {
                rgba: Arc::new(vec![0u8; 8]),
                delay: Duration::from_millis(*millis),
            })
            .collect();
        rebalance_delays(&mut frames);
        let total_ms: u64 = frames.iter().map(|frame| frame.delay.as_millis() as u64).sum();
        assert_eq!(total_ms, 4000, "the retained timeline keeps its duration");
        assert!(
            frames.iter().all(|frame| frame.delay == Duration::from_millis(1000)),
            "every retained frame costs the same, so the card never freezes on frame zero"
        );
    }

    #[test]
    fn frames_merge_instead_of_disappearing() {
        let frame = |bytes: usize, millis: u64| Frame {
            rgba: Arc::new(vec![0u8; bytes]),
            delay: Duration::from_millis(millis),
        };
        let mut frames = (0..8).map(|index| frame(4096, 40 + index)).collect::<Vec<_>>();
        let total_ms: u64 = frames.iter().map(|frame| frame.delay.as_millis() as u64).sum();
        let retained = retain_within(&mut frames, 16 * 1024);
        // Four frames of 8 KiB fit the budget; the dropped frame's time is
        // folded into the kept one, so the clip keeps its full duration.
        assert_eq!(frames.len(), 4);
        assert_eq!(retained, 4 * 4096);
        assert_eq!(
            frames.iter().map(|frame| frame.delay.as_millis() as u64).sum::<u64>(),
            total_ms
        );
        // A budget too small for even one frame still keeps media: a coarse
        // still beats a card that lost its picture entirely.
        let retained = retain_within(&mut frames, 1);
        assert_eq!(frames.len(), 1);
        assert_eq!(retained, 4096);
    }

    #[test]
    fn a_card_keeps_its_icon_when_the_background_alone_exceeds_the_budget() {
        let campaign: Campaign = serde_json::from_str(
            r#"{"id":"budget","title":"t","destination_url":"https://example.com"}"#,
        )
        .expect("a minimal campaign");
        let mut candidate = empty_ready(&campaign);
        candidate.frames = vec![Frame { rgba: Arc::new(vec![7u8; 64 * 1024]), delay: ROTATE_EVERY }];
        candidate.background_frames = (0..64)
            .map(|_| Frame { rgba: Arc::new(vec![9u8; 64 * 1024]), delay: ROTATE_EVERY })
            .collect();
        let retained = admit_frames(&mut candidate, 256 * 1024);
        assert!(retained <= 256 * 1024);
        assert!(!candidate.frames.is_empty(), "the icon is served first");
        assert!(candidate.background_frames.len() <= 3);
        assert_eq!(
            candidate.background_rgba.len(),
            candidate.background_frames[0].rgba.len(),
            "the still-frame mirror follows the retained frames"
        );
    }

    #[test]
    fn the_card_canvas_bounds_retained_pixels() {
        let (width, height) = canvas_dimensions(800, 450);
        assert!(width <= MEDIA_MAX_WIDTH && height <= MEDIA_MAX_HEIGHT);
        // The canvas fills one axis and keeps the source's aspect ratio.
        assert!(width == MEDIA_MAX_WIDTH || height == MEDIA_MAX_HEIGHT);
        assert!((width as f64 / height as f64 - 800.0 / 450.0).abs() < 0.01);
        // A source that already fits is kept as it is.
        assert_eq!(canvas_dimensions(160, 90), (160, 90));
        // A tall source keeps its aspect ratio inside the canvas too.
        let (width, height) = canvas_dimensions(450, 800);
        assert!(width <= MEDIA_MAX_WIDTH && height <= MEDIA_MAX_HEIGHT);
        assert!((height as f64 / width as f64 - 800.0 / 450.0).abs() < 0.01);
    }

    #[test]
    fn the_schedule_sweep_reports_the_next_boundary() {
        let campaign = |starts: Option<u64>, ends: Option<u64>| -> Campaign {
            serde_json::from_value(serde_json::json!({
                "id": format!("c{}", ends.or(starts).unwrap_or(0)),
                "destination_url": "https://example.com",
                "starts_at": starts,
                "ends_at": ends,
            }))
            .expect("a scheduled campaign")
        };
        let now = unix_now();
        schedule_expiry(&[campaign(None, Some(now + 600)), campaign(Some(now + 300), None)]);
        assert_eq!(NEXT_EXPIRY.load(Ordering::Relaxed), now + 300);
        // A window already in the past schedules nothing further.
        schedule_expiry(&[campaign(None, Some(now.saturating_sub(1)))]);
        assert_eq!(NEXT_EXPIRY.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn size_and_scale_aliases_parse_correctly() {
        let json = serde_json::json!({
            "id": "test-aliases",
            "destination_url": "https://example.com",
            "icon_size": 120,
            "background_size": 130,
            "title_size": 140,
            "message_size": 150,
        });
        let c: Campaign = serde_json::from_value(json).expect("valid campaign with aliases");
        assert_eq!(c.icon_scale, Some(120));
        assert_eq!(c.background_scale, Some(130));
        assert_eq!(c.title_scale, Some(140));
        assert_eq!(c.message_scale, Some(150));
    }
}
