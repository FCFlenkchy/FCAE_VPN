#include "ui_render.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <new>
#include <cerrno>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <cwchar>
#include <utility>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#elif !defined(ANDROID)
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// The Linux host blocks in glfwWaitEventsTimeout(), so a change reported from a
// worker thread can only end that wait early if it can post a GLFW event --
// otherwise it appears after the idle timeout, as a late repaint the user sees
// as a flicker. This is a separate branch on purpose: adding it as another
// `#elif` above would have ended the platform chain and silently dropped every
// POSIX header on Linux.
#if defined(__linux__) && !defined(ANDROID)
#include <GLFW/glfw3.h>
#endif

// UI-lifetime audio gate is an embedding hook rather than a public ABI field.
extern "C" void fcae_sponsor_set_ui_active(bool active);
extern "C" void fcae_ui_diagnostic(uint32_t event, uint32_t value);
// A `fcae-ffi` export rather than part of the `fcae-abi` header: what the live
// cores are listening on, as `core|position|name|protocol|port|scope` records.
extern "C" uint32_t fcae_live_listeners(char* out, uint32_t capacity);


static std::string join_chain_transports(const std::vector<int>& transports) {
    std::string out;
    for (int transport : transports) {
        if (!out.empty()) out += ',';
        out += std::to_string(transport);
    }
    return out;
}

static std::vector<int> parse_chain_transports(const std::string& value) {
    std::vector<int> out;
    size_t start = 0;
    while (start < value.size()) {
        size_t end = value.find(',', start);
        if (end == std::string::npos) end = value.size();
        if (end > start) out.push_back(atoi(value.substr(start, end - start).c_str()));
        start = end + 1;
    }
    return out;
}

AppState g_app;
static uint64_t s_save_status_revision = 0;
static uint64_t s_save_status_painted_revision = 0;
static bool s_save_status_error = false;

static void set_save_status_v(bool error, const char* format, va_list args) {
    vsnprintf(g_app.save_status, sizeof(g_app.save_status), format, args);
    s_save_status_error = error;
    ++s_save_status_revision;
    ui_request_redraw();
}
static void set_save_status(const char* format, ...) {
    va_list args;
    va_start(args, format);
    set_save_status_v(false, format, args);
    va_end(args);
}
static void set_save_status_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    set_save_status_v(true, format, args);
    va_end(args);
}
static bool s_loaded_chain_transports = false;
static bool s_loaded_socks_port = false;
static bool s_loaded_http_port = false;
static bool s_loaded_firefox_socks_port = false;
static bool s_loaded_firefox_http_port = false;
static bool s_loaded_firefox_socks_enabled = false;
static bool s_loaded_firefox_http_enabled = false;
static bool s_loaded_aether_http_enabled = false;
static bool s_loaded_unified_aether_http = false;
static bool s_loaded_unified_firefox_http = false;
static bool s_legacy_tun_http = false;
static bool s_legacy_firefox_tun_http = false;
static bool s_loaded_legacy_firefox_tun_http = false;
static int s_loaded_legacy_chain_count = -1;
static int s_loaded_legacy_chain_exits[3] = {};
// The routing mode Tor and Psiphon used to have. It is read only to turn an old
// file into the chain that describes the same route, and is never written back:
// the mode is not a setting any more, the route is.
static int s_loaded_tor_mode = 0;

// The UI fingerprint lets platform loops skip frames whose pixels would not change.

// Keep update state outside render_ui() so the fingerprint observes live panel changes.
static bool s_update_checked = false;
static bool s_update_available = false;
static char s_update_status[256] = {};
static uint32_t s_update_error_kind = FCAE_UPDATE_ERROR_NONE;
static char s_update_raw_body[4096] = {};
static bool s_update_decode_popup_open = false;
static bool s_update_error_popup_open = false;
static char s_update_latest[32] = {};
static char s_update_notes[1024] = {};
static char s_update_dl_url[512] = {};
static bool s_update_popup_open = false;
static bool s_about_popup_open = false;
static bool s_connection_info_popup_open = false;
static char s_update_date[32] = {};
static std::chrono::steady_clock::time_point s_check_start_time = std::chrono::steady_clock::now();
static bool s_update_in_progress = false;
static FcaeSponsorInfo s_sponsor = {};
static std::vector<uint8_t> s_sponsor_rgba;
static std::vector<uint8_t> s_sponsor_background_rgba;
static uint64_t s_sponsor_loaded_foreground_generation = 0;
static uint64_t s_sponsor_loaded_background_generation = 0;
// Sponsor generation packs campaign/published metadata above bit 24,
// foreground frame in bits 12..23, and background frame in bits 0..11.
static constexpr uint64_t kSponsorBackgroundFrameMask = 0xFFFULL;
static constexpr uint64_t kSponsorForegroundFrameMask = 0xFFF000ULL;
static bool sponsor_foreground_changed(uint64_t current, uint64_t previous) {
    return ((current ^ previous) & ~kSponsorBackgroundFrameMask) != 0;
}
static bool sponsor_background_changed(uint64_t current, uint64_t previous) {
    return ((current ^ previous) & ~kSponsorForegroundFrameMask) != 0;
}
static bool s_sponsor_started = false;
static uint64_t s_sponsor_logged_generation = 0;
static std::chrono::steady_clock::time_point s_sponsor_manifest_check = {};
// Sponsor polling honors this visibility gate so hidden windows keep audio disabled.
static std::atomic<bool> s_ui_window_visible{true};
static std::atomic<bool> s_ui_window_focused{true};
// Native window of the active platform front end, set once at startup; a
// redraw request posts to it so a worker thread wakes the parked window loop.
static std::atomic<uintptr_t> s_ui_window{0};
#ifdef _WIN32
// Tick count at which an elevated relaunch succeeded; the window thread ends
// this process once the hand-off window has passed. Zero while none is pending.
static std::atomic<DWORD> s_elevation_handoff_at{0};
// How long the copy that asked for elevation may look like it is still there
// after the elevated process has started. Only long enough for the shell to
// bring the new window forward; the window is hidden and destroyed at this
// point, so nothing of this process stays on screen during cleanup.
static constexpr DWORD kHandoffWindowMs = 150;
#endif
static int s_sponsor_ui_active_sent = -1;
static int s_sponsor_connected_sent = -1;
static std::string s_sponsor_last_error;
static bool s_tun_paused = false;

static const std::string& data_dir();
static std::string join_path(const std::string& dir, const char* name);

static void poll_sponsor() {
    const auto now = std::chrono::steady_clock::now();
    if (!s_sponsor_started) {
        if (fcae_sponsor_set_cache_dir(join_path(data_dir(), "sponsors").c_str()) != FCAE_OK)
            fcae_sponsor_load_cache();
        s_sponsor_started = true;
    }
    const int ui_active = s_ui_window_visible.load() ? 1 : 0;
    if (ui_active != s_sponsor_ui_active_sent) {
        fcae_sponsor_set_ui_active(ui_active != 0);
        s_sponsor_ui_active_sent = ui_active;
    }
    const int connected = g_app.ffi_state.load() == FCAE_STATE_CONNECTED ? 1 : 0;
    if (connected != s_sponsor_connected_sent) {
        fcae_sponsor_set_connected(connected != 0);
        s_sponsor_connected_sent = connected;
    }
    if (now >= s_sponsor_manifest_check) {
        const uint64_t remaining = fcae_sponsor_manifest_refresh_remaining_secs();
        if (remaining == 0) fcae_sponsor_refresh_manifest_async();
        // Retry a failed due check without shortening the successful refresh interval.
        const uint64_t check_after = remaining == 0 ? 60 : remaining;
        s_sponsor_manifest_check = now + std::chrono::seconds(check_after);
    }
    FcaeSponsorInfo info = {};
    info.struct_size = sizeof(info);
    info.abi_version = FCAE_ABI_VERSION;
    const FcaeStatus poll_status = fcae_sponsor_poll(&info);
    if (poll_status != FCAE_OK) {
        const char* error = fcae_last_error();
        if (s_sponsor_last_error != error) {
            s_sponsor_last_error = error;
            g_app.add_log(FCAE_LOG_WARN, error);
        }
        return;
    }
    s_sponsor_last_error.clear();
    const bool card_available = info.available || info.campaign_count != 0;
    const bool card_changed = card_available != s_sponsor.available
        || info.generation != s_sponsor.generation;
    const bool foreground_shape_changed = info.width != s_sponsor.width
        || info.height != s_sponsor.height;
    const bool background_shape_changed = info.background_width != s_sponsor.background_width
        || info.background_height != s_sponsor.background_height;
    // Card metadata excludes frame indices, so animated cards log once when published.
    const uint64_t sponsor_card = info.generation >> 24;
    if (card_available && sponsor_card != s_sponsor_logged_generation) {
        s_sponsor_logged_generation = sponsor_card;
        char message[192];
        snprintf(message, sizeof(message),
                 "[sponsor] UI card available=%s: id=%s card=%llu campaigns=%u rgba=%u",
                 info.available ? "true" : "inferred",
                 info.id, (unsigned long long)sponsor_card,
                 info.campaign_count, info.rgba_size);
        g_app.add_log(FCAE_LOG_INFO, message);
    }
    s_sponsor = info;
    s_sponsor.available = card_available;
    bool media_copied = false;
    if (!card_available) {
        s_sponsor_rgba.clear();
        s_sponsor_background_rgba.clear();
        s_sponsor_loaded_foreground_generation = 0;
        s_sponsor_loaded_background_generation = 0;
    } else {
        const bool foreground_changed = sponsor_foreground_changed(
            info.generation, s_sponsor_loaded_foreground_generation)
            || foreground_shape_changed
            || (info.rgba_size != 0 && s_sponsor_rgba.empty());
        const bool background_changed = sponsor_background_changed(
            info.generation, s_sponsor_loaded_background_generation)
            || background_shape_changed
            || (info.background_rgba_size != 0 && s_sponsor_background_rgba.empty());
        if (foreground_changed) {
            try {
                s_sponsor_rgba.resize(info.rgba_size);
            } catch (const std::bad_alloc&) {
                s_sponsor_rgba.clear();
                return;
            }
            const bool copied = info.rgba_size == 0
                || fcae_sponsor_copy_rgba(s_sponsor_rgba.data(), s_sponsor_rgba.size()) == FCAE_OK;
            if (copied) {
                s_sponsor_loaded_foreground_generation = info.generation;
                media_copied = true;
            } else {
                s_sponsor_rgba.clear();
                s_sponsor_loaded_foreground_generation = 0;
            }
        }
        if (background_changed) {
            try {
                s_sponsor_background_rgba.resize(info.background_rgba_size);
            } catch (const std::bad_alloc&) {
                s_sponsor_background_rgba.clear();
                return;
            }
            const bool copied = info.background_rgba_size == 0
                || fcae_sponsor_copy_background_rgba(
                    s_sponsor_background_rgba.data(), s_sponsor_background_rgba.size()) == FCAE_OK;
            if (copied) {
                s_sponsor_loaded_background_generation = info.generation;
                media_copied = true;
            } else {
                s_sponsor_background_rgba.clear();
                s_sponsor_loaded_background_generation = 0;
            }
        }
    }
    if (card_changed || media_copied) ui_request_redraw();
}

static ImVec4 sponsor_color(uint32_t packed, ImVec4 fallback) {
    if (packed == 0) return fallback;
    return ImVec4(
        ((packed >> 16) & 0xFF) / 255.0f,
        ((packed >> 8) & 0xFF) / 255.0f,
        (packed & 0xFF) / 255.0f,
        ((packed >> 24) & 0xFF) / 255.0f);
}

static ImVec4 sponsor_color(uint32_t packed, ImVec4 fallback, uint8_t opacity) {
    ImVec4 color = sponsor_color(packed, fallback);
    color.w *= (float)opacity / 100.0f;
    return color;
}

// Sponsor text coordinates share Android's contract: x_percent is the horizontal
// centre and top_y the top edge of the text block, both relative to the whole
// card, with every wrapped line centred inside the block.
struct SponsorText {
    const char* text = nullptr;
    const char* end = nullptr;
    float scale = 1.0f;
    float size = 0.0f;
    float wrap_w = 0.0f;
    ImVec2 block{};
    ImVec2 pos{};
};

static SponsorText layout_sponsor_text(const char* text, const ImVec2& card, float inset,
                                       unsigned x_percent, float top_y, float scale) {
    SponsorText t;
    if (!text || !*text) return t;
    t.text = text;
    t.end = text + strlen(text);
    t.scale = scale;
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * scale);
    t.size = ImGui::GetFontSize();
    t.wrap_w = std::max(1.0f, card.x - inset * 2.0f);
    t.block = ImGui::GetFont()->CalcTextSizeA(t.size, FLT_MAX, t.wrap_w, t.text, t.end);
    ImGui::PopFont();
    const float anchor_x = card.x * std::clamp((float)x_percent / 100.0f, 0.0f, 1.0f);
    t.pos.x = std::clamp(anchor_x - t.block.x * 0.5f, inset, std::max(inset, card.x - inset - t.block.x));
    t.pos.y = std::clamp(top_y, 0.0f, std::max(0.0f, card.y - t.block.y));
    return t;
}

// Title and message are placed independently, so positions meant for a taller
// card can stack them on top of each other. When the blocks collide the lower
// one moves below the upper one, and both are lifted to stay on the card.
// Android's positionSponsorText applies the same rule.
static void separate_sponsor_text(SponsorText& title, SponsorText& message, float card_h, float gap) {
    if (!title.text || !message.text) return;
    const bool overlap_x = title.pos.x < message.pos.x + message.block.x
        && message.pos.x < title.pos.x + title.block.x;
    const bool overlap_y = title.pos.y < message.pos.y + message.block.y + gap
        && message.pos.y < title.pos.y + title.block.y + gap;
    if (!overlap_x || !overlap_y) return;
    SponsorText& upper = message.pos.y < title.pos.y ? message : title;
    SponsorText& lower = &upper == &title ? message : title;
    lower.pos.y = upper.pos.y + upper.block.y + gap;
    const float overflow = lower.pos.y + lower.block.y - card_h;
    if (overflow > 0.0f) {
        upper.pos.y = std::max(0.0f, upper.pos.y - overflow);
        lower.pos.y = upper.pos.y + upper.block.y + gap;
    }
}

static void draw_sponsor_text(const SponsorText& t, const ImVec2& origin, const ImVec4& color) {
    if (!t.text) return;
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * t.scale);
    ImFont* const font = ImGui::GetFont();
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImU32 col = ImGui::GetColorU32(color);
    const float left = origin.x + t.pos.x;
    float y = origin.y + t.pos.y;
    for (const char* s = t.text; s < t.end; y += t.size) {
        const char* line_end = static_cast<const char*>(memchr(s, '\n', (size_t)(t.end - s)));
        if (!line_end) line_end = t.end;
        const char* const wrap = font->CalcWordWrapPosition(t.size, s, line_end, t.wrap_w);
        const char* visible_end = wrap;
        while (visible_end > s && (visible_end[-1] == ' ' || visible_end[-1] == '\t')) --visible_end;
        const float line_w = font->CalcTextSizeA(t.size, FLT_MAX, 0.0f, s, visible_end).x;
        draw->AddText(font, t.size, ImVec2(left + (t.block.x - line_w) * 0.5f, y), col, s, visible_end);
        s = wrap;
        while (s < line_end && (*s == ' ' || *s == '\t')) ++s;
        if (s == line_end && line_end < t.end) ++s;
    }
    ImGui::PopFont();
}

// What the last painted frame looked like / when it was painted.
static uint64_t s_painted_sig = 0;
static uint64_t s_frame_log_revision = 0;
static bool s_log_scroll_pending = false;
static bool     s_painted_once = false;

// Animation (sponsor frames, spinner) advances at 30 FPS; an unchanged window
// is not repainted, only re-checked at the idle intervals below.
static constexpr unsigned kUiFrameRate = 30;
static constexpr unsigned kUiFrameIntervalMs = 1000 / kUiFrameRate;
static constexpr unsigned kUiIdleIntervalMs = 250;
static constexpr unsigned kUiUnfocusedIntervalMs = 500;
static constexpr unsigned kUiCaretIntervalMs = 100;
static constexpr double kUiCaretPhaseSeconds = 0.4;

// UI state that keeps needing frames on its own.
static bool s_busy_anim = false;      // connect/scan spinner is on screen

// The native runtime and config are initialized off the render thread. The UI
// never enters an FFI-backed code path until the release-store publishes all
// initialization writes, so startup is responsive without partial-runtime races.
enum class RuntimeInitState : uint8_t { Starting, Ready, Failed };
static std::atomic<RuntimeInitState> s_runtime_init{RuntimeInitState::Starting};
// Flips true once the settings file has been loaded into AppState. The UI
// may paint the real window as soon as this is set; the runtime itself
// publishes Ready separately.
static std::atomic<bool> s_config_loaded{false};
static std::thread s_runtime_init_thread;

bool build_is_prerelease() {
#ifdef FCAE_IS_PRERELEASE
    return true;
#else
    return false;
#endif
}

static const char* fcae_display_version() {
    static char buf[64] = {};
    if (buf[0] == '\0') {
        snprintf(buf, sizeof(buf), "%s", FCAE_VERSION);
        char* pre = strstr(buf, "_pre-release");
        if (pre) *pre = '\0';
    }
    return buf;
}

double ui_now_seconds() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

static uint64_t fnv_bytes(uint64_t h, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static uint64_t fnv_cstr(uint64_t h, const char* s) {
    if (!s) return fnv_bytes(h, "", 1);
    return fnv_bytes(h, s, strlen(s) + 1);
}

template <typename T>
static uint64_t fnv_value(uint64_t h, const T& v) {
    return fnv_bytes(h, &v, sizeof(T));
}

/// The saved core configs and the one the main protocol runs: an edit has to
/// repaint and has to reach the config the engine reads.
static uint64_t fnv_core_configs(uint64_t h) {
    h = fnv_value(h, g_app.core_selected);
    h = fnv_value(h, (int)g_app.core_configs.size());
    for (const AppState::CoreConfigEntry& entry : g_app.core_configs) {
        h = fnv_cstr(h, entry.name.c_str());
        h = fnv_value(h, entry.backend);
        h = fnv_cstr(h, entry.text.c_str());
    }
    return h;
}

static uint64_t config_signature() {
    uint64_t h = 1469598103934665603ull;
    h = fnv_value(h, g_app.chain_transports.size());
    for (int transport : g_app.chain_transports) h = fnv_value(h, transport);
    h = fnv_core_configs(h);
    h = fnv_value(h, g_app.protocol);
    h = fnv_value(h, g_app.backend);
    h = fnv_cstr(h, g_app.firefox_account_id);
    h = fnv_cstr(h, g_app.firefox_location);
    h = fnv_cstr(h, g_app.firefox_server);
    h = fnv_value(h, g_app.firefox_transport);
    h = fnv_value(h, g_app.tor_socks_port);
    h = fnv_cstr(h, g_app.psiphon_region);
    h = fnv_cstr(h, g_app.psiphon_region_list);
    h = fnv_value(h, g_app.psiphon_transport);
    h = fnv_cstr(h, g_app.psiphon_data_dir);
    h = fnv_value(h, g_app.psiphon_socks_port);
    h = fnv_value(h, g_app.psiphon_http_port);
    h = fnv_value(h, g_app.mode);
    h = fnv_value(h, g_app.tun_engine);
    h = fnv_value(h, g_app.lan_sharing);
    h = fnv_value(h, g_app.scan_mode);
    h = fnv_value(h, g_app.ip_version);
    h = fnv_value(h, g_app.quick_reconnect);
    h = fnv_cstr(h, g_app.noize_profile);
    h = fnv_value(h, g_app.fragment_enabled);
    h = fnv_value(h, g_app.frag_min_size);
    h = fnv_value(h, g_app.frag_max_size);
    h = fnv_value(h, g_app.frag_min_delay);
    h = fnv_value(h, g_app.frag_max_delay);
    h = fnv_value(h, g_app.socks_port);
    h = fnv_value(h, g_app.http_port);
    h = fnv_value(h, g_app.firefox_socks_port);
    h = fnv_value(h, g_app.firefox_http_port);
    h = fnv_value(h, g_app.xray_socks_port);
    h = fnv_value(h, g_app.xray_http_port);
    h = fnv_value(h, g_app.singbox_socks_port);
    h = fnv_value(h, g_app.singbox_http_port);
    h = fnv_value(h, g_app.tor_http_port);
    h = fnv_value(h, g_app.tor_http_enabled);
    h = fnv_value(h, g_app.socks_enabled);
    h = fnv_value(h, g_app.http_enabled);
    h = fnv_value(h, g_app.firefox_socks_enabled);
    h = fnv_value(h, g_app.firefox_http_enabled);
    h = fnv_value(h, g_app.xray_socks_enabled);
    h = fnv_value(h, g_app.xray_http_enabled);
    h = fnv_value(h, g_app.singbox_socks_enabled);
    h = fnv_value(h, g_app.singbox_http_enabled);
    h = fnv_value(h, g_app.psiphon_socks_enabled);
    h = fnv_value(h, g_app.psiphon_http_enabled);
    h = fnv_value(h, g_app.tor_socks_enabled);
    h = fnv_cstr(h, g_app.force_peer);
    h = fnv_cstr(h, g_app.upstream_proxy);
    h = fnv_cstr(h, g_app.config_path);
    h = fnv_value(h, g_app.h2_enabled);
    h = fnv_value(h, g_app.ech_enabled);
    h = fnv_cstr(h, g_app.sni);
    h = fnv_cstr(h, g_app.ech_dns);
    h = fnv_cstr(h, g_app.ech_domain);
    h = fnv_cstr(h, g_app.gool_inner);
    h = fnv_cstr(h, g_app.tls_ciphers);
    h = fnv_cstr(h, g_app.api_address);
    h = fnv_cstr(h, g_app.api_host);
    h = fnv_cstr(h, g_app.api_sni);
    h = fnv_cstr(h, g_app.exit_loc);
    h = fnv_cstr(h, g_app.tls_groups);
    h = fnv_cstr(h, g_app.tls13_ciphers);
    h = fnv_cstr(h, g_app.tls_key_shares);
    h = fnv_cstr(h, g_app.tls_sigalgs);
    h = fnv_cstr(h, g_app.tls_cert_compression);
    h = fnv_cstr(h, g_app.tls_alps);
    h = fnv_cstr(h, g_app.tls_trust_anchors);
    h = fnv_cstr(h, g_app.tls_server_padding);
    h = fnv_value(h, g_app.tls_verify);
    h = fnv_value(h, g_app.disable_grease);
    h = fnv_value(h, g_app.fragment_sni);
    h = fnv_value(h, g_app.enable_grease_sigalgs);
    h = fnv_value(h, g_app.enable_ech_grease);
    h = fnv_value(h, g_app.disable_ocsp_stapling);
    h = fnv_value(h, g_app.disable_sct);
    h = fnv_value(h, g_app.disable_session_ticket);
    h = fnv_value(h, g_app.disable_extension_permutation);
    h = fnv_cstr(h, g_app.tun_mtu);
    h = fnv_cstr(h, g_app.tun_tcp_sndbuf);
    h = fnv_cstr(h, g_app.tun_tcp_rcvbuf);
    h = fnv_value(h, g_app.tun_tcp_auto_tuning);
    h = fnv_value(h, g_app.tun_exclude_private);
    h = fnv_cstr(h, g_app.tun_dns4);
    h = fnv_cstr(h, g_app.tun_dns6);
    h = fnv_value(h, g_app.logging_enabled.load());
    h = fnv_value(h, g_app.auto_scroll);
    h = fnv_value(h, g_app.auto_update_check);
    h = fnv_value(h, g_app.check_prereleases);
    h = fnv_value(h, g_app.sys_profile);
    h = fnv_value(h, g_app.engine_log);
    h = fnv_value(h, g_app.core_log);
    h = fnv_value(h, g_app.t2s_log);
    h = fnv_value(h, g_app.tor_bridges);
    h = fnv_cstr(h, g_app.tor_bridge_lines);
    h = fnv_cstr(h, g_app.team_name);
    h = fnv_cstr(h, g_app.access_token);
    h = fnv_cstr(h, g_app.access_client_id);
    h = fnv_cstr(h, g_app.access_client_secret);
    h = fnv_cstr(h, g_app.access_email);
    h = fnv_cstr(h, g_app.routes_file);
    h = fnv_cstr(h, g_app.routes_inline);
    return h;
}

/// Fingerprint of everything the UI paints. Unchanged fingerprint + no input ⇒
/// the next frame would be pixel-identical, so it can be skipped.
static bool s_error_detail_visible = false;

static uint64_t ui_content_signature() {
    uint64_t h = 1469598103934665603ull;   // FNV-1a offset basis

    const FcaeTelemetry& t = g_app.telem;
    h = fnv_value(h, t.state);
    h = fnv_value(h, t.rtt_ms);
    h = fnv_value(h, t.rx_bytes_sec);
    h = fnv_value(h, t.tx_bytes_sec);
    h = fnv_value(h, t.total_rx);
    h = fnv_value(h, t.total_tx);
    h = fnv_cstr(h, t.lan_ip);
    h = fnv_cstr(h, t.last_error);
    h = fnv_value(h, s_error_detail_visible);

    // Log revision also detects identical new lines after the ring fills.
    {
        std::lock_guard<std::mutex> lock(g_app.logs_mutex);
        h = fnv_value(h, g_app.logs_revision);
        const size_t n = g_app.logs.size();
        h = fnv_value(h, n);
        if (n) h = fnv_cstr(h, g_app.logs.back().second.c_str());
    }

    // Settings the user can edit (changed by input, but a config load or a
    // programmatic change must repaint too), plus transient notices.
    h = fnv_value(h, g_app.protocol);
    h = fnv_value(h, g_app.backend);
    h = fnv_value(h, (int)g_app.chain_transports.size());
    for (int transport : g_app.chain_transports) h = fnv_value(h, transport);
    h = fnv_core_configs(h);
    h = fnv_cstr(h, g_app.firefox_account_id);
    h = fnv_cstr(h, g_app.firefox_location);
    h = fnv_cstr(h, g_app.firefox_server);
    h = fnv_value(h, g_app.firefox_transport);
    h = fnv_cstr(h, g_app.firefox_email);
    h = fnv_cstr(h, g_app.firefox_pending_id);
    h = fnv_cstr(h, g_app.firefox_status);
    h = fnv_value(h, g_app.firefox_job);
    h = fnv_value(h, g_app.firefox_totp);
    h = fnv_value(h, g_app.mode);
    h = fnv_value(h, g_app.tun_engine);
    h = fnv_value(h, g_app.scan_mode);
    h = fnv_value(h, g_app.ip_version);
    h = fnv_value(h, g_app.lan_sharing);
    h = fnv_value(h, g_app.quick_reconnect);
    h = fnv_value(h, g_app.socks_enabled);
    h = fnv_value(h, g_app.http_enabled);
    h = fnv_value(h, g_app.firefox_socks_enabled);
    h = fnv_value(h, g_app.firefox_http_enabled);
    h = fnv_value(h, g_app.xray_socks_enabled);
    h = fnv_value(h, g_app.xray_http_enabled);
    h = fnv_value(h, g_app.singbox_socks_enabled);
    h = fnv_value(h, g_app.singbox_http_enabled);
    h = fnv_value(h, g_app.psiphon_socks_enabled);
    h = fnv_value(h, g_app.psiphon_http_enabled);
    h = fnv_value(h, g_app.tor_socks_enabled);
    h = fnv_value(h, g_app.tor_http_enabled);
    h = fnv_value(h, g_app.tor_http_port);
    h = fnv_value(h, g_app.socks_port);
    h = fnv_value(h, g_app.http_port);
    h = fnv_value(h, g_app.firefox_socks_port);
    h = fnv_value(h, g_app.firefox_http_port);
    h = fnv_value(h, g_app.xray_socks_port);
    h = fnv_value(h, g_app.xray_http_port);
    h = fnv_value(h, g_app.singbox_socks_port);
    h = fnv_value(h, g_app.singbox_http_port);
    h = fnv_value(h, g_app.h2_enabled);
    h = fnv_value(h, g_app.ech_enabled);
    h = fnv_value(h, g_app.sys_profile);
    h = fnv_value(h, g_app.engine_log);
    h = fnv_value(h, g_app.core_log);
    h = fnv_value(h, g_app.t2s_log);
    h = fnv_value(h, g_app.tor_bridges);
    h = fnv_cstr(h, g_app.tor_bridge_lines);
    h = fnv_cstr(h, g_app.tun_mtu);
    h = fnv_cstr(h, g_app.tun_tcp_sndbuf);
    h = fnv_cstr(h, g_app.tun_tcp_rcvbuf);
    h = fnv_value(h, g_app.tun_tcp_auto_tuning);
    h = fnv_value(h, g_app.tun_exclude_private);
    h = fnv_cstr(h, g_app.tun_dns4);
    h = fnv_cstr(h, g_app.tun_dns6);
    h = fnv_cstr(h, g_app.noize_profile);
    h = fnv_cstr(h, g_app.force_peer);
    h = fnv_cstr(h, g_app.upstream_proxy);
    h = fnv_cstr(h, g_app.config_path);
    h = fnv_cstr(h, g_app.sni);
    h = fnv_cstr(h, g_app.ech_dns);
    h = fnv_cstr(h, g_app.ech_domain);
    h = fnv_cstr(h, g_app.gool_inner);
    h = fnv_cstr(h, g_app.tls_ciphers);
    h = fnv_cstr(h, g_app.api_address);
    h = fnv_cstr(h, g_app.api_host);
    h = fnv_cstr(h, g_app.api_sni);
    h = fnv_cstr(h, g_app.exit_loc);
    h = fnv_cstr(h, g_app.tls_groups);
    h = fnv_cstr(h, g_app.tls13_ciphers);
    h = fnv_cstr(h, g_app.tls_key_shares);
    h = fnv_cstr(h, g_app.tls_sigalgs);
    h = fnv_cstr(h, g_app.tls_cert_compression);
    h = fnv_cstr(h, g_app.tls_alps);
    h = fnv_cstr(h, g_app.tls_trust_anchors);
    h = fnv_cstr(h, g_app.tls_server_padding);
    h = fnv_value(h, g_app.tls_verify);
    h = fnv_value(h, g_app.disable_grease);
    h = fnv_value(h, g_app.fragment_sni);
    h = fnv_value(h, g_app.enable_grease_sigalgs);
    h = fnv_value(h, g_app.enable_ech_grease);
    h = fnv_value(h, g_app.disable_ocsp_stapling);
    h = fnv_value(h, g_app.disable_sct);
    h = fnv_value(h, g_app.disable_session_ticket);
    h = fnv_value(h, g_app.disable_extension_permutation);
    h = fnv_cstr(h, g_app.team_name);
    h = fnv_cstr(h, g_app.access_token);
    h = fnv_cstr(h, g_app.access_email);
    h = fnv_cstr(h, g_app.routes_file);
    h = fnv_cstr(h, g_app.routes_inline);
    h = fnv_cstr(h, g_app.save_status);
    h = fnv_value(h, s_save_status_error);
    h = fnv_cstr(h, g_app.copy_status);
    h = fnv_value(h, g_app.start_busy.load());

    // Update panel (button label, "Checking... (Ns)" counter, popup contents).
    h = fnv_value(h, s_update_checked);
    h = fnv_value(h, s_update_available);
    h = fnv_value(h, s_update_in_progress);
    h = fnv_value(h, s_update_popup_open);
    h = fnv_value(h, s_update_decode_popup_open);
    h = fnv_value(h, s_update_error_popup_open);
    h = fnv_value(h, s_update_error_kind);
    h = fnv_cstr(h, s_update_raw_body);
    h = fnv_value(h, s_about_popup_open);
    h = fnv_value(h, s_connection_info_popup_open);
    h = fnv_cstr(h, s_update_status);
    h = fnv_cstr(h, s_update_latest);
    h = fnv_cstr(h, s_update_notes);
    h = fnv_cstr(h, s_update_dl_url);
    if (s_update_in_progress) {
        h = fnv_value(h, (long long)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - s_check_start_time).count());
    }
    h = fnv_value(h, s_tun_paused);
    if (ImGui::GetCurrentContext() && ImGui::GetIO().WantTextInput) {
        h = fnv_value(h, (long long)(ui_now_seconds() / kUiCaretPhaseSeconds));
    }
    h = fnv_value(h, s_sponsor.available);
    h = fnv_value(h, s_sponsor.generation);
    h = fnv_value(h, fcae_sponsor_audio_enabled());
    return h;
}

/// Pull telemetry from the FFI when due: once per second, matching the
/// engine's 1 s rate window — the published rates are bytes-per-second
/// measured over exactly that window, so faster polling would only repaint
/// the same numbers. Throttled by g_app.last_telem_t, so the in-frame poll
/// and this one never double-poll.
static void ui_poll_telemetry(double now) {
    const double interval = 1.0;
    const bool stop_refresh = g_app.ffi_state.load() == FCAE_STATE_DISCONNECTED
                            && g_app.telem.state != FCAE_STATE_DISCONNECTED;
    if (!stop_refresh && now - g_app.last_telem_t < interval) return;

    FcaeTelemetry telem = {};
    telem.struct_size = sizeof(telem);
    telem.abi_version = FCAE_ABI_VERSION;
    fcae_get_telemetry(&telem);
    static double next_lan_probe = 0.0;
    if (telem.lan_enabled && now >= next_lan_probe) {
        char lan_ip[64] = {};
        if (fcae_detect_lan_ip(lan_ip, sizeof(lan_ip)) == FCAE_OK && lan_ip[0]) {
            snprintf(telem.lan_ip, sizeof(telem.lan_ip), "%s", lan_ip);
        }
        next_lan_probe = now + 5.0;
    }
    g_app.telem = telem;
    g_app.ffi_state.store(telem.state);
    g_app.ffi_connected.store(telem.state == FCAE_STATE_CONNECTED);
    g_app.last_telem_t = now;
}

/// Wake the window thread so it paints the state a caller just published.
///
/// Engine log lines, status notices and state changes all arrive on worker
/// threads. Without this the window thread parked in `MsgWaitForMultipleObjects`
/// keeps its full idle timeout, so a change shows up as a late repaint -- a
/// visible flicker -- instead of on the next frame. `windows.h` is included at
/// the top of this file on Windows, so the stored handle is cast back to HWND.
void ui_request_redraw() {
    g_app.redraw_requested.store(true);
#ifdef _WIN32
    if (auto window = reinterpret_cast<HWND>(s_ui_window.load())) PostMessageW(window, WM_NULL, 0, 0);
#elif defined(__linux__) && !defined(ANDROID)
    // glfwPostEmptyEvent() is safe from any thread and wakes whichever window
    // the host wait is parked on; the stored handle only decides whether a host
    // has registered at all, so the value itself is deliberately unused.
    // macOS renders through Metal: AppKit may only be poked from the main
    // thread, so that host bounds its wait instead.
    if (s_ui_window.load() != 0) glfwPostEmptyEvent();
#endif
}

/// Finish an elevation hand-off from the window thread.
///
/// `PostQuitMessage` only posts to the calling thread's queue, so the exit the
/// elevated relaunch depends on has to happen here, not on the worker that
/// started it.
void ui_handoff_tick() {
#ifdef _WIN32
    const DWORD at = s_elevation_handoff_at.load(std::memory_order_relaxed);
    if (at == 0) return;
    // The worker arms this the moment the shell hands back the elevated
    // process, so the window has done its job by then. Waiting here instead of
    // exiting straight away is what made the old copy sit on screen: the frame
    // loop only sees the flag on its next tick, and ui_shutdown() then spends
    // its time in fcae_shutdown() restoring routes and DNS before the process
    // finally exits -- all of it with the window still up.
    //
    // So the visible part happens now, and the cleanup follows invisibly:
    // hide and destroy the window first (both happen on this, the owning,
    // thread), then let the loop's teardown run.
    if (GetTickCount() - at >= kHandoffWindowMs) {
        s_elevation_handoff_at.store(0, std::memory_order_relaxed);
        g_app.running.store(false);
        const HWND hwnd = reinterpret_cast<HWND>(s_ui_window.load());
        if (hwnd != nullptr) {
            ShowWindow(hwnd, SW_HIDE);
            // Destroying now, not after ui_shutdown(), is what the user sees:
            // the window is gone before any route or DNS restore begins.
            DestroyWindow(hwnd);
            s_ui_window.store(0, std::memory_order_relaxed);
        }
        PostQuitMessage(0);
    }
#endif
}

void ui_set_window_handle(void* window) {
    s_ui_window.store(reinterpret_cast<uintptr_t>(window));
}

// A hidden window keeps the one still per plane it is showing; the engine
// releases every other frame and pauses rotation until the window returns.
void ui_set_window_visible(bool visible) {
    s_ui_window_visible.store(visible);
    fcae_sponsor_set_ui_active(visible);
    s_sponsor_ui_active_sent = visible ? 1 : 0;
}

void ui_set_window_focused(bool focused) {
    s_ui_window_focused.store(focused);
}

static void update_error_detail(double now) {
    static std::string previous_error;
    static bool was_error = false;
    static double deadline = 0.0;
    const bool is_error = g_app.telem.state == FCAE_STATE_ERROR;
    const std::string error = is_error ? g_app.telem.last_error : "";
    if (!is_error || error.empty()) {
        previous_error.clear();
        was_error = is_error;
        s_error_detail_visible = false;
        deadline = 0.0;
        return;
    }
    if (!was_error || error != previous_error) {
        previous_error = error;
        deadline = now + 3.0;
    }
    was_error = true;
    s_error_detail_visible = now < deadline;
}

static void expire_save_status(double now) {
    static uint64_t observed_revision = 0;
    static double deadline = 0.0;
    if (observed_revision != s_save_status_revision) {
        observed_revision = s_save_status_revision;
        deadline = g_app.save_status[0] ? now + 3.0 : 0.0;
    }
    if (deadline && now >= deadline) {
        g_app.save_status[0] = 0;
        s_save_status_error = false;
        deadline = 0.0;
    }
}

static void firefox_poll_captcha();
static void firefox_poll_job();
static void firefox_poll_background();
static void firefox_expire_status(double now);
static void firefox_refresh_usage(double now);

static void autosave_config(double now);

void ui_autosave_tick() {
    if (s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Ready)
        autosave_config(ui_now_seconds());
}

bool ui_should_render(bool interacting) {
    const double now = ui_now_seconds();

    // Initialization owns the non-atomic AppState fields until it publishes
    // Ready. Do not fingerprint or poll them concurrently.
    if (s_runtime_init.load(std::memory_order_acquire) != RuntimeInitState::Ready) {
        return g_app.redraw_requested.load() || interacting || !s_painted_once;
    }

    autosave_config(now);

    // Telemetry and locally animated sponsor frames change without input.
    ui_poll_telemetry(now);
    update_error_detail(now);
    expire_save_status(now);
    poll_sponsor();
    firefox_poll_captcha();
    firefox_poll_job();
    firefox_poll_background();
    firefox_expire_status(now);
    firefox_refresh_usage(now);
    s_tun_paused = fcae_tun_paused();
    {
        std::lock_guard<std::mutex> lock(g_app.logs_mutex);
        s_frame_log_revision = g_app.logs_revision;
    }

    // A redraw request is only cleared once a frame is really painted, so it
    // cannot be lost while the window is minimized.
    if (g_app.redraw_requested.load() || s_log_scroll_pending ||
        (g_app.save_status[0] && s_save_status_painted_revision != s_save_status_revision)) return true;

    // The user is interacting: paint every frame the caller offers (hover,
    // drag, typing, scroll). The platform limits the frame rate.
    if (interacting) return true;

    // Spinner/connect animation is running: it moves on its own.
    if (s_busy_anim) return true;

    // Polling above refreshes asynchronous UI state; repaint only when its
    // fingerprint changes. A periodic forced frame can flash flip-model
    // swapchains even though the visible content is unchanged.
    return !s_painted_once || ui_content_signature() != s_painted_sig;
}

unsigned ui_sleep_ms() {
    const bool focused = s_ui_window_focused.load();
    if (s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Starting)
        return 16;
    if (s_busy_anim || (s_sponsor.available && s_sponsor.animated))
        return focused ? kUiFrameIntervalMs : 2 * kUiFrameIntervalMs;
    if (!focused) return kUiUnfocusedIntervalMs;
    if (ImGui::GetCurrentContext() && ImGui::GetIO().WantTextInput) return kUiCaretIntervalMs;
    return kUiIdleIntervalMs;
}

void ui_note_frame_drawn() {
    if (s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Ready)
        s_painted_sig = ui_content_signature();
    s_painted_once = true;
    // A callback during the frame may have missed the rendered snapshot while
    // already being included in the painted signature above.
    if (s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Ready) {
        std::lock_guard<std::mutex> lock(g_app.logs_mutex);
        if (g_app.logs_revision != s_frame_log_revision) g_app.redraw_requested.store(true);
    }
}


#if defined(_WIN32)
static constexpr char kPathSep = '\\';

static std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

static std::string narrow(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}
#else
static constexpr char kPathSep = '/';
#endif

static bool is_absolute_path(const char* p) {
    return p[0] == '/' || p[0] == '\\' || (p[0] && p[1] == ':');
}

static std::string join_path(const std::string& dir, const char* name) {
    if (dir.empty()) return name;
    if (dir.back() == '/' || dir.back() == '\\') return dir + name;
    return dir + kPathSep + name;
}

static std::string join_cfg(const std::string& dir) { return join_path(dir, "FCAE_VPN.cfg"); }

static std::string exe_dir() {
#if defined(ANDROID)
    return "/data/data/com.fc.fcaevpn/files";
#elif defined(_WIN32)
    std::wstring w(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, &w[0], (DWORD)w.size());
        if (n == 0) return {};
        if (n < w.size()) { w.resize(n); break; }
        if (w.size() >= 32768) return {};
        w.resize(w.size() * 2);
    }
    size_t slash = w.find_last_of(L"\\/");
    if (slash != std::wstring::npos) w.resize(slash);
    return narrow(w.c_str());
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string p(size, '\0');
    if (_NSGetExecutablePath(&p[0], &size) != 0) return {};
    p.resize(strlen(p.c_str()));
    char real[PATH_MAX];
    if (realpath(p.c_str(), real)) p = real;
    size_t slash = p.find_last_of('/');
    if (slash != std::string::npos) p.resize(slash);
    return p;
#else
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    std::string p(buf);
    size_t slash = p.find_last_of('/');
    if (slash != std::string::npos) p.resize(slash);
    return p;
#endif
}

static bool dir_exists(const std::string& dir) {
#if defined(_WIN32)
    const DWORD attr = GetFileAttributesW(widen(dir).c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool make_dir(const std::string& dir, bool private_dir) {
#if defined(_WIN32)
    (void)private_dir;
    return CreateDirectoryW(widen(dir).c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
#else
    return mkdir(dir.c_str(), private_dir ? 0700 : 0755) == 0 || errno == EEXIST;
#endif
}

// Open for read/write. On Windows use wide paths so UTF-8 exe dirs work.
static FILE* open_cfg(const std::string& path, const char* mode) {
#if defined(_WIN32)
    const std::wstring wpath = widen(path);
    const std::wstring wmode = widen(mode);
    if (wpath.empty() || wmode.empty()) return nullptr;
    return _wfopen(wpath.c_str(), wmode.c_str());
#else
    if (mode && mode[0] == 'w') {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) return nullptr;
        fchmod(fd, 0600);
        return fdopen(fd, mode);
    }
    return fopen(path.c_str(), mode);
#endif
}

static bool file_exists(const std::string& path) {
    FILE* f = open_cfg(path, "rb");
    if (!f) return false;
    fclose(f);
    return true;
}

static bool dir_writable(const std::string& dir) {
    if (dir.empty() || !make_dir(dir, false)) return false;
    const std::string probe = join_path(dir, ".fcae_write_probe");
    FILE* f = open_cfg(probe, "wb");
    if (!f) return false;
    fclose(f);
#if defined(_WIN32)
    _wremove(widen(probe).c_str());
#else
    unlink(probe.c_str());
#endif
    return true;
}

#if !defined(_WIN32) && !defined(ANDROID)
static std::string home_dir() {
    const char* home = getenv("HOME");
    if (!home || !*home) {
        const passwd* pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : nullptr;
    }
    return home && *home ? home : "";
}
#endif

#if defined(__APPLE__)
static std::string mac_support_dir() {
    const std::string home = home_dir();
    if (home.empty()) return {};
    make_dir(home + "/Library/Application Support", false);
    std::string dir = home + "/Library/Application Support/FCAE VPN";
    return make_dir(dir, true) ? dir : std::string();
}

static bool ends_with(const std::string& s, const char* suffix) {
    const size_t n = strlen(suffix);
    return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}
#endif

// The folder that travels with the app: next to the .exe, next to the
// AppImage file (its own directory is a read-only mount), or next to the
// .app bundle (never inside it, which would break the signature). An app
// installed under /Applications is not portable.
static std::string portable_root() {
#if defined(__APPLE__)
    std::string dir = exe_dir();
    if (!ends_with(dir, ".app/Contents/MacOS")) return dir;
    dir.resize(dir.size() - strlen("/Contents/MacOS"));
    const size_t slash = dir.find_last_of('/');
    if (slash == std::string::npos || slash == 0) return {};
    dir.resize(slash);
    if (ends_with(dir, "/Applications") || dir.find("/Applications/") != std::string::npos
        || dir.find("/AppTranslocation/") != std::string::npos)
        return {};
    return dir;
#elif defined(_WIN32) || defined(ANDROID)
    return exe_dir();
#else
    const char* appimage = getenv("APPIMAGE");
    if (appimage && appimage[0] == '/') {
        std::string dir(appimage);
        const size_t slash = dir.find_last_of('/');
        dir.resize(slash == 0 ? 1 : slash);
        return dir;
    }
    return exe_dir();
#endif
}

// Per-user location for when the portable folder is read-only.
static std::string user_data_dir() {
#if defined(_WIN32)
    const wchar_t* root = _wgetenv(L"LOCALAPPDATA");
    if (!root || !*root) return {};
    std::string dir = narrow(root) + "\\FCAE_VPN";
    return make_dir(dir, true) ? dir : std::string();
#elif defined(__APPLE__)
    return mac_support_dir();
#elif defined(ANDROID)
    return {};
#else
    std::string base;
    const char* xdg = getenv("XDG_DATA_HOME");
    if (xdg && xdg[0] == '/') {
        base = xdg;
    } else {
        const std::string home = home_dir();
        if (home.empty()) return {};
        make_dir(home + "/.local", false);
        base = home + "/.local/share";
    }
    make_dir(base, false);
    std::string dir = base + "/fcae-vpn";
    return make_dir(dir, true) ? dir : std::string();
#endif
}

// Root of every file the app writes: settings, identity, Psiphon datastore,
// sponsor cache. Relative paths in the settings resolve against it.
static const std::string& data_dir() {
    static const std::string dir = [] {
        std::string root = portable_root();
        if (dir_writable(root)) return root;
        std::string user = user_data_dir();
        return user.empty() ? root : user;
    }();
    return dir;
}

static std::string resolve_data_path(const char* stored) {
    if (!stored[0] || is_absolute_path(stored)) return stored;
    return join_path(data_dir(), stored);
}

// An absolute path written by an older build becomes relative when it lies
// inside data_dir(), and falls back to its file name when it points into a
// folder that no longer exists (the portable folder moved).
static bool make_portable(char* buf, size_t cap) {
    if (!buf[0] || !is_absolute_path(buf)) return false;
    const std::string path = buf;
    const std::string& root = data_dir();
    const size_t n = root.size();
    if (n && path.size() > n + 1 && path.compare(0, n, root) == 0
        && (path[n] == '/' || path[n] == '\\')) {
        snprintf(buf, cap, "%s", path.c_str() + n + 1);
        return true;
    }
    const size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos || slash + 1 == path.size() || slash == 0) return false;
    if (dir_exists(path.substr(0, slash))) return false;
    snprintf(buf, cap, "%s", path.c_str() + slash + 1);
    return true;
}

static std::string get_config_path() {
    static const std::string path = join_cfg(data_dir());
    return path;
}

// Resolve which cfg to load: the write path first, then the locations older
// builds wrote to; the next save lands on the write path.
static std::string resolve_config_path_for_load() {
    const std::string primary = get_config_path();
    if (file_exists(primary)) return primary;
    std::vector<std::string> legacy = {join_cfg(exe_dir())};
#if defined(__APPLE__)
    legacy.push_back(join_cfg(mac_support_dir()));
#endif
    legacy.push_back("FCAE_VPN.cfg");
    for (const std::string& candidate : legacy)
        if (candidate != primary && file_exists(candidate)) return candidate;
    return primary;
}

/// Upper bound on saved core configs, mirroring fcae-runtime's library limit.
/// Nothing in the UI shows or enforces it: a library is the user's own list, and
/// the document's byte limit is what a real one runs into. It is here so a
/// corrupt config file cannot ask for an unbounded resize.
static constexpr int kMaxCoreConfigs = 1000;
/// Largest single saved config, mirroring fcae-runtime's library limit.
static constexpr size_t kMaxCoreConfigText = 128 * 1024;
/// Longest saved-config name in bytes, mirroring fcae-runtime's library limit.
static constexpr size_t kMaxCoreConfigName = 48;

// Defined next to the protocol list, below: the config loader prunes chain
// positions against it before the UI helpers are in scope.
static int transport_count();
static bool transport_is_core(int transport);
static int current_transport();
static void apply_transport(int transport);

/// Positions in the protocol list that are hops and never sessions. Tor and
/// Psiphon only exist behind a carrier and in front of an exit, so a route
/// names them among its exits; the carrier is the protocol above them.
static constexpr int kTorTransport = 4;
static constexpr int kPsiphonTransport = 5;

// atoi wraps out-of-range and negative values; a config line saying
// socks_port=-1 would otherwise bind port 65535. Keep the previous value
// instead of trusting garbage.
static int parse_port(const std::string& v, int fallback) {
    int p = atoi(v.c_str());
    return (p > 0 && p < 65536) ? p : fallback;
}

static std::string encode_config_text(const char* text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p) {
        result.push_back(hex[*p >> 4]);
        result.push_back(hex[*p & 15]);
    }
    return result;
}

/// A saved core config is one line of a line-based file, so its newlines are
/// escaped rather than hex-encoded: a native config JSON is mostly newlines and
/// indentation, and doubling every byte of it would only cost disk.
static std::string core_text_encode(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    for (char c : text) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            default: result.push_back(c); break;
        }
    }
    return result;
}

static std::string core_text_decode(const std::string& encoded) {
    std::string result;
    result.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] != '\\' || i + 1 >= encoded.size()) {
            result.push_back(encoded[i]);
            continue;
        }
        switch (encoded[++i]) {
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case '\\': result.push_back('\\'); break;
            default:
                result.push_back('\\');
                result.push_back(encoded[i]);
                break;
        }
    }
    return result;
}

static bool decode_config_text(const std::string& encoded, char* out, size_t size) {
    if (encoded.size() % 2 || encoded.size() / 2 >= size) return false;
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string decoded;
    decoded.reserve(encoded.size() / 2);
    for (size_t i = 0; i < encoded.size(); i += 2) {
        const int hi = digit(encoded[i]), lo = digit(encoded[i + 1]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0)) return false;
        decoded.push_back(static_cast<char>((hi << 4) | lo));
    }
    memcpy(out, decoded.c_str(), decoded.size() + 1);
    return true;
}

static void apply_config_kv(const std::string& key, const std::string& val) {
    if (key == "protocol") g_app.protocol = atoi(val.c_str());
    else if (key == "backend") g_app.backend = atoi(val.c_str());
    else if (key == "chain_transports") {
        g_app.chain_transports = parse_chain_transports(val);
        s_loaded_chain_transports = true;
    } else if (key == "chain_count") s_loaded_legacy_chain_count = atoi(val.c_str());
    else if (key == "chain_exit_0") s_loaded_legacy_chain_exits[0] = atoi(val.c_str());
    else if (key == "chain_exit_1") s_loaded_legacy_chain_exits[1] = atoi(val.c_str());
    else if (key == "chain_exit_2") s_loaded_legacy_chain_exits[2] = atoi(val.c_str());
    else if (key == "firefox_account_id") snprintf(g_app.firefox_account_id, sizeof(g_app.firefox_account_id), "%s", val.c_str());
    else if (key == "firefox_location") snprintf(g_app.firefox_location, sizeof(g_app.firefox_location), "%s", val.c_str());
    else if (key == "firefox_server") snprintf(g_app.firefox_server, sizeof(g_app.firefox_server), "%s", val.c_str());
    else if (key == "firefox_transport") g_app.firefox_transport = atoi(val.c_str());
    else if (key == "tor_socks_port") g_app.tor_socks_port = parse_port(val, g_app.tor_socks_port);
    else if (key == "psiphon_region") snprintf(g_app.psiphon_region, sizeof(g_app.psiphon_region), "%s", val.c_str());
    else if (key == "tun_mtu") snprintf(g_app.tun_mtu, sizeof(g_app.tun_mtu), "%s", val.c_str());
    else if (key == "tun_tcp_sndbuf") snprintf(g_app.tun_tcp_sndbuf, sizeof(g_app.tun_tcp_sndbuf), "%s", val.c_str());
    else if (key == "tun_tcp_rcvbuf") snprintf(g_app.tun_tcp_rcvbuf, sizeof(g_app.tun_tcp_rcvbuf), "%s", val.c_str());
    else if (key == "tun_tcp_auto_tuning") g_app.tun_tcp_auto_tuning = atoi(val.c_str()) != 0;
    else if (key == "tun_exclude_private") g_app.tun_exclude_private = atoi(val.c_str()) != 0;
    else if (key == "tun_dns4") snprintf(g_app.tun_dns4, sizeof(g_app.tun_dns4), "%s", val.c_str());
    else if (key == "tun_dns6") snprintf(g_app.tun_dns6, sizeof(g_app.tun_dns6), "%s", val.c_str());
    else if (key == "psiphon_region_list")
        snprintf(g_app.psiphon_region_list, sizeof(g_app.psiphon_region_list), "%s", val.c_str());
    else if (key == "psiphon_transport") g_app.psiphon_transport = atoi(val.c_str());
    else if (key == "psiphon_data_dir") snprintf(g_app.psiphon_data_dir, sizeof(g_app.psiphon_data_dir), "%s", val.c_str());
    else if (key == "psiphon_socks_port") g_app.psiphon_socks_port = parse_port(val, g_app.psiphon_socks_port);
    else if (key == "psiphon_http_port") g_app.psiphon_http_port = parse_port(val, g_app.psiphon_http_port);
    else if (key == "mode") g_app.mode = atoi(val.c_str());
    else if (key == "tun_engine") { int e = atoi(val.c_str()); g_app.tun_engine = (e > 0 && e < (int)fcae_tun_engine_count()) ? e : 0; }
    else if (key == "lan_sharing") g_app.lan_sharing = atoi(val.c_str()) != 0;
    else if (key == "scan_mode") g_app.scan_mode = atoi(val.c_str());
    else if (key == "ip_version") g_app.ip_version = atoi(val.c_str());
    else if (key == "quick_reconnect") g_app.quick_reconnect = atoi(val.c_str()) != 0;
    else if (key == "noize_profile")
        snprintf(g_app.noize_profile, sizeof(g_app.noize_profile), "%s", val.c_str());
    else if (key == "fragment_enabled") g_app.fragment_enabled = atoi(val.c_str()) != 0;
    else if (key == "frag_min_size") g_app.frag_min_size = atoi(val.c_str());
    else if (key == "frag_max_size") g_app.frag_max_size = atoi(val.c_str());
    else if (key == "frag_min_delay") g_app.frag_min_delay = atoi(val.c_str());
    else if (key == "frag_max_delay") g_app.frag_max_delay = atoi(val.c_str());
    else if (key == "socks_port") { g_app.socks_port = (uint16_t)parse_port(val, g_app.socks_port); s_loaded_socks_port = true; }
    else if (key == "http_port") { g_app.http_port = (uint16_t)parse_port(val, g_app.http_port); s_loaded_http_port = true; }
    else if (key == "firefox_socks_port") {
        g_app.firefox_socks_port = (uint16_t)parse_port(val, g_app.firefox_socks_port);
        s_loaded_firefox_socks_port = true;
    }
    else if (key == "firefox_http_port") {
        g_app.firefox_http_port = (uint16_t)parse_port(val, g_app.firefox_http_port);
        s_loaded_firefox_http_port = true;
    }
    else if (key == "xray_socks_port") g_app.xray_socks_port = (uint16_t)parse_port(val, g_app.xray_socks_port);
    else if (key == "xray_http_port") g_app.xray_http_port = (uint16_t)parse_port(val, g_app.xray_http_port);
    else if (key == "singbox_socks_port") g_app.singbox_socks_port = (uint16_t)parse_port(val, g_app.singbox_socks_port);
    else if (key == "singbox_http_port") g_app.singbox_http_port = (uint16_t)parse_port(val, g_app.singbox_http_port);
    else if (key == "xray_socks_enabled") g_app.xray_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "xray_http_enabled") g_app.xray_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "singbox_socks_enabled") g_app.singbox_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "singbox_http_enabled") g_app.singbox_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "aether_http_unified") { g_app.http_enabled = atoi(val.c_str()) != 0; s_loaded_unified_aether_http = true; }
    else if (key == "firefox_http_unified") { g_app.firefox_http_enabled = atoi(val.c_str()) != 0; s_loaded_unified_firefox_http = true; }
    else if (key == "aether_http_enabled" && !s_loaded_unified_aether_http) { g_app.http_enabled = atoi(val.c_str()) != 0; s_loaded_aether_http_enabled = true; }
    else if (key == "firefox_socks_enabled") { g_app.firefox_socks_enabled = atoi(val.c_str()) != 0; s_loaded_firefox_socks_enabled = true; }
    else if (key == "firefox_http_enabled" && !s_loaded_unified_firefox_http) { g_app.firefox_http_enabled = atoi(val.c_str()) != 0; s_loaded_firefox_http_enabled = true; }
    else if (key == "firefox_tun_http_enabled") { s_legacy_firefox_tun_http = atoi(val.c_str()) != 0; s_loaded_legacy_firefox_tun_http = true; }
    else if (key == "psiphon_socks_enabled") g_app.psiphon_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "psiphon_http_enabled") g_app.psiphon_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "tor_socks_enabled") g_app.tor_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "socks_enabled") g_app.socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "tor_http_port") g_app.tor_http_port = parse_port(val, g_app.tor_http_port);
    else if (key == "tor_http_enabled") g_app.tor_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "http_enabled" && !s_loaded_aether_http_enabled && !s_loaded_unified_aether_http) g_app.http_enabled = atoi(val.c_str()) != 0;
    else if (key == "tun_http_enabled") s_legacy_tun_http = atoi(val.c_str()) != 0;
    else if (key == "force_peer")
        snprintf(g_app.force_peer, sizeof(g_app.force_peer), "%s", val.c_str());
    else if (key == "upstream_proxy")
        snprintf(g_app.upstream_proxy, sizeof(g_app.upstream_proxy), "%s", val.c_str());
    else if (key == "config_path")
        snprintf(g_app.config_path, sizeof(g_app.config_path), "%s", val.c_str());
    else if (key == "h2_enabled") g_app.h2_enabled = atoi(val.c_str()) != 0;
    else if (key == "ech_enabled") g_app.ech_enabled = atoi(val.c_str()) != 0;
    else if (key == "sni")
        snprintf(g_app.sni, sizeof(g_app.sni), "%s", val.c_str());
    else if (key == "ech_dns") snprintf(g_app.ech_dns, sizeof(g_app.ech_dns), "%s", val.c_str());
    else if (key == "ech_domain") snprintf(g_app.ech_domain, sizeof(g_app.ech_domain), "%s", val.c_str());
    else if (key == "gool_inner") snprintf(g_app.gool_inner, sizeof(g_app.gool_inner), "%s", val.c_str());
    else if (key == "tls_ciphers") snprintf(g_app.tls_ciphers, sizeof(g_app.tls_ciphers), "%s", val.c_str());
    // Read the v2.3 key as a migration path; saves always use api_address.
    else if (key == "api_address" || key == "enroll_address") snprintf(g_app.api_address, sizeof(g_app.api_address), "%s", val.c_str());
    else if (key == "api_host") snprintf(g_app.api_host, sizeof(g_app.api_host), "%s", val.c_str());
    else if (key == "api_sni") snprintf(g_app.api_sni, sizeof(g_app.api_sni), "%s", val.c_str());
    else if (key == "exit_loc") snprintf(g_app.exit_loc, sizeof(g_app.exit_loc), "%s", val.c_str());
    else if (key == "tls_groups") snprintf(g_app.tls_groups, sizeof(g_app.tls_groups), "%s", val.c_str());
    else if (key == "tls13_ciphers") snprintf(g_app.tls13_ciphers, sizeof(g_app.tls13_ciphers), "%s", val.c_str());
    else if (key == "tls_key_shares") snprintf(g_app.tls_key_shares, sizeof(g_app.tls_key_shares), "%s", val.c_str());
    else if (key == "tls_sigalgs") snprintf(g_app.tls_sigalgs, sizeof(g_app.tls_sigalgs), "%s", val.c_str());
    else if (key == "tls_cert_compression") snprintf(g_app.tls_cert_compression, sizeof(g_app.tls_cert_compression), "%s", val.c_str());
    else if (key == "tls_alps") snprintf(g_app.tls_alps, sizeof(g_app.tls_alps), "%s", val.c_str());
    else if (key == "tls_trust_anchors") snprintf(g_app.tls_trust_anchors, sizeof(g_app.tls_trust_anchors), "%s", val.c_str());
    else if (key == "tls_server_padding") snprintf(g_app.tls_server_padding, sizeof(g_app.tls_server_padding), "%s", val.c_str());
    else if (key == "tls_verify") g_app.tls_verify = atoi(val.c_str()) != 0;
    else if (key == "disable_grease") g_app.disable_grease = atoi(val.c_str()) != 0;
    else if (key == "fragment_sni") g_app.fragment_sni = atoi(val.c_str()) != 0;
    else if (key == "enable_grease_sigalgs") g_app.enable_grease_sigalgs = atoi(val.c_str()) != 0;
    else if (key == "enable_ech_grease") g_app.enable_ech_grease = atoi(val.c_str()) != 0;
    else if (key == "disable_ocsp_stapling") g_app.disable_ocsp_stapling = atoi(val.c_str()) != 0;
    else if (key == "disable_sct") g_app.disable_sct = atoi(val.c_str()) != 0;
    else if (key == "disable_session_ticket") g_app.disable_session_ticket = atoi(val.c_str()) != 0;
    else if (key == "disable_extension_permutation") g_app.disable_extension_permutation = atoi(val.c_str()) != 0;
    else if (key == "logging_enabled") g_app.logging_enabled = atoi(val.c_str()) != 0;
    else if (key == "auto_scroll") g_app.auto_scroll = atoi(val.c_str()) != 0;
    else if (key == "auto_update_check") g_app.auto_update_check = atoi(val.c_str()) != 0;
    else if (key == "check_prereleases") g_app.check_prereleases = atoi(val.c_str()) != 0;
    else if (key == "ui_scale_percent") {
        // Clamped on load: a hand-edited file must not be able to ask for a
        // font size that pushes the layout off the window.
        int scale = atoi(val.c_str());
        if (scale < 75) scale = 75;
        if (scale > 250) scale = 250;
        g_app.ui_scale_percent = scale;
    }
    else if (key == "sys_profile") g_app.sys_profile = atoi(val.c_str());
    else if (key == "engine_log") g_app.engine_log = atoi(val.c_str());
    else if (key == "core_log") g_app.core_log = atoi(val.c_str());
    else if (key == "tun2socks_log") g_app.t2s_log = atoi(val.c_str());
    else if (key == "tor_mode") s_loaded_tor_mode = atoi(val.c_str());
    else if (key == "tor_bridges") g_app.tor_bridges = atoi(val.c_str());
    else if (key == "tor_bridge_lines")
        snprintf(g_app.tor_bridge_lines, sizeof(g_app.tor_bridge_lines), "%s", val.c_str());
    else if (key == "team_name")
        snprintf(g_app.team_name, sizeof(g_app.team_name), "%s", val.c_str());
    else if (key == "access_token")
        snprintf(g_app.access_token, sizeof(g_app.access_token), "%s", val.c_str());
    else if (key == "access_client_id")
        snprintf(g_app.access_client_id, sizeof(g_app.access_client_id), "%s", val.c_str());
    else if (key == "access_client_secret")
        snprintf(g_app.access_client_secret, sizeof(g_app.access_client_secret), "%s", val.c_str());
    else if (key == "access_email")
        snprintf(g_app.access_email, sizeof(g_app.access_email), "%s", val.c_str());
    else if (key == "routes_file")
        snprintf(g_app.routes_file, sizeof(g_app.routes_file), "%s", val.c_str());
    else if (key == "routes_inline")
        snprintf(g_app.routes_inline, sizeof(g_app.routes_inline), "%s", val.c_str());
    else if (key == "routes_inline_hex")
        decode_config_text(val, g_app.routes_inline, sizeof(g_app.routes_inline));
    else if (key == "core_selected") g_app.core_selected = atoi(val.c_str());
    else if (key.rfind("core_config", 0) == 0) {
        // core_config<index>_<field>. The count key is not needed: an entry is
        // created by the fields that describe it, so a short or reordered file
        // still loads every field it does carry.
        const char* cursor = key.c_str() + strlen("core_config");
        char* end = nullptr;
        const long index = strtol(cursor, &end, 10);
        if (!end || end == cursor || index < 0 || index >= kMaxCoreConfigs) return;
        if (g_app.core_configs.size() < (size_t)index + 1)
            g_app.core_configs.resize((size_t)index + 1);
        AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)index];
        // A line longer than the largest config the engine accepts is a corrupt
        // file, not a config to keep in memory.
        if (strcmp(end, "_name") == 0 && val.size() <= kMaxCoreConfigName) entry.name = val;
        else if (strcmp(end, "_backend") == 0) entry.backend = atoi(val.c_str()) == 1 ? 1 : 0;
        else if (strcmp(end, "_text") == 0) {
            std::string text = core_text_decode(val);
            if (text.size() <= kMaxCoreConfigText) entry.text = std::move(text);
        }
    }
}

static bool s_config_needs_retry = false;
static bool s_config_load_failed = false;

static bool save_config(bool quiet = false) {
    const std::string path = get_config_path();
    const std::string temporary = path + ".tmp";
    FILE* f = open_cfg(temporary, "wb");
    if (!f) {
        s_config_needs_retry = true;
        set_save_status_error("Save failed");
        g_app.add_log(1, ("[ui] save failed: " + path).c_str());
        return false;
    }
    // Always LF; empty values allowed. Line-based load is robust on Win/Linux.
    fprintf(f, "protocol=%d\n", g_app.protocol);
    fprintf(f, "backend=%d\n", g_app.backend);
    fprintf(f, "chain_transports=%s\n", join_chain_transports(g_app.chain_transports).c_str());
    fprintf(f, "core_selected=%d\n", g_app.core_selected);
    for (size_t i = 0; i < g_app.core_configs.size(); ++i) {
        const AppState::CoreConfigEntry& entry = g_app.core_configs[i];
        fprintf(f, "core_config%zu_name=%s\n", i, entry.name.c_str());
        fprintf(f, "core_config%zu_backend=%d\n", i, entry.backend);
        fprintf(f, "core_config%zu_text=%s\n", i, core_text_encode(entry.text).c_str());
    }
    fprintf(f, "firefox_account_id=%s\n", g_app.firefox_account_id);
    fprintf(f, "firefox_location=%s\n", g_app.firefox_location);
    fprintf(f, "firefox_server=%s\n", g_app.firefox_server);
    fprintf(f, "firefox_transport=%d\n", g_app.firefox_transport);
    fprintf(f, "tor_socks_port=%d\n", g_app.tor_socks_port);
    fprintf(f, "psiphon_region=%s\n", g_app.psiphon_region);
    fprintf(f, "psiphon_region_list=%s\n", g_app.psiphon_region_list);
    fprintf(f, "psiphon_transport=%d\n", g_app.psiphon_transport);
    fprintf(f, "psiphon_data_dir=%s\n", g_app.psiphon_data_dir);
    fprintf(f, "psiphon_socks_port=%d\n", g_app.psiphon_socks_port);
    fprintf(f, "psiphon_http_port=%d\n", g_app.psiphon_http_port);
    fprintf(f, "mode=%d\n", g_app.mode);
    fprintf(f, "tun_engine=%d\n", g_app.tun_engine);
    fprintf(f, "lan_sharing=%d\n", g_app.lan_sharing ? 1 : 0);
    fprintf(f, "scan_mode=%d\n", g_app.scan_mode);
    fprintf(f, "ip_version=%d\n", g_app.ip_version);
    fprintf(f, "quick_reconnect=%d\n", g_app.quick_reconnect ? 1 : 0);
    fprintf(f, "noize_profile=%s\n", g_app.noize_profile);
    fprintf(f, "fragment_enabled=%d\n", g_app.fragment_enabled ? 1 : 0);
    fprintf(f, "frag_min_size=%d\n", g_app.frag_min_size);
    fprintf(f, "frag_max_size=%d\n", g_app.frag_max_size);
    fprintf(f, "frag_min_delay=%d\n", g_app.frag_min_delay);
    fprintf(f, "frag_max_delay=%d\n", g_app.frag_max_delay);
    fprintf(f, "socks_port=%u\n", (unsigned)g_app.socks_port);
    fprintf(f, "http_port=%u\n", (unsigned)g_app.http_port);
    fprintf(f, "firefox_socks_port=%u\n", (unsigned)g_app.firefox_socks_port);
    fprintf(f, "firefox_http_port=%u\n", (unsigned)g_app.firefox_http_port);
    fprintf(f, "xray_socks_port=%u\n", (unsigned)g_app.xray_socks_port);
    fprintf(f, "xray_http_port=%u\n", (unsigned)g_app.xray_http_port);
    fprintf(f, "singbox_socks_port=%u\n", (unsigned)g_app.singbox_socks_port);
    fprintf(f, "singbox_http_port=%u\n", (unsigned)g_app.singbox_http_port);
    fprintf(f, "tor_http_port=%u\n", (unsigned)g_app.tor_http_port);
    fprintf(f, "tor_http_enabled=%d\n", g_app.tor_http_enabled ? 1 : 0);
    fprintf(f, "socks_enabled=%d\n", g_app.socks_enabled ? 1 : 0);
    fprintf(f, "aether_http_unified=%d\n", g_app.http_enabled ? 1 : 0);
    fprintf(f, "firefox_socks_enabled=%d\n", g_app.firefox_socks_enabled ? 1 : 0);
    fprintf(f, "firefox_http_unified=%d\n", g_app.firefox_http_enabled ? 1 : 0);
    fprintf(f, "xray_socks_enabled=%d\n", g_app.xray_socks_enabled ? 1 : 0);
    fprintf(f, "xray_http_enabled=%d\n", g_app.xray_http_enabled ? 1 : 0);
    fprintf(f, "singbox_socks_enabled=%d\n", g_app.singbox_socks_enabled ? 1 : 0);
    fprintf(f, "singbox_http_enabled=%d\n", g_app.singbox_http_enabled ? 1 : 0);
    fprintf(f, "psiphon_socks_enabled=%d\n", g_app.psiphon_socks_enabled ? 1 : 0);
    fprintf(f, "psiphon_http_enabled=%d\n", g_app.psiphon_http_enabled ? 1 : 0);
    fprintf(f, "tor_socks_enabled=%d\n", g_app.tor_socks_enabled ? 1 : 0);
    fprintf(f, "force_peer=%s\n", g_app.force_peer);
    fprintf(f, "upstream_proxy=%s\n", g_app.upstream_proxy);
    fprintf(f, "config_path=%s\n", g_app.config_path);
    fprintf(f, "h2_enabled=%d\n", g_app.h2_enabled ? 1 : 0);
    fprintf(f, "ech_enabled=%d\n", g_app.ech_enabled ? 1 : 0);
    fprintf(f, "sni=%s\n", g_app.sni);
    fprintf(f, "ech_dns=%s\n", g_app.ech_dns);
    fprintf(f, "ech_domain=%s\n", g_app.ech_domain);
    fprintf(f, "gool_inner=%s\n", g_app.gool_inner);
    fprintf(f, "tls_ciphers=%s\n", g_app.tls_ciphers);
    fprintf(f, "api_address=%s\n", g_app.api_address);
    fprintf(f, "api_host=%s\n", g_app.api_host);
    fprintf(f, "api_sni=%s\n", g_app.api_sni);
    fprintf(f, "exit_loc=%s\n", g_app.exit_loc);
    fprintf(f, "tls_groups=%s\n", g_app.tls_groups);
    fprintf(f, "tls13_ciphers=%s\n", g_app.tls13_ciphers);
    fprintf(f, "tls_key_shares=%s\n", g_app.tls_key_shares);
    fprintf(f, "tls_sigalgs=%s\n", g_app.tls_sigalgs);
    fprintf(f, "tls_cert_compression=%s\n", g_app.tls_cert_compression);
    fprintf(f, "tls_alps=%s\n", g_app.tls_alps);
    fprintf(f, "tls_trust_anchors=%s\n", g_app.tls_trust_anchors);
    fprintf(f, "tls_server_padding=%s\n", g_app.tls_server_padding);
    fprintf(f, "tls_verify=%d\n", g_app.tls_verify ? 1 : 0);
    fprintf(f, "disable_grease=%d\n", g_app.disable_grease ? 1 : 0);
    fprintf(f, "fragment_sni=%d\n", g_app.fragment_sni ? 1 : 0);
    fprintf(f, "enable_grease_sigalgs=%d\n", g_app.enable_grease_sigalgs ? 1 : 0);
    fprintf(f, "enable_ech_grease=%d\n", g_app.enable_ech_grease ? 1 : 0);
    fprintf(f, "disable_ocsp_stapling=%d\n", g_app.disable_ocsp_stapling ? 1 : 0);
    fprintf(f, "disable_sct=%d\n", g_app.disable_sct ? 1 : 0);
    fprintf(f, "disable_session_ticket=%d\n", g_app.disable_session_ticket ? 1 : 0);
    fprintf(f, "disable_extension_permutation=%d\n", g_app.disable_extension_permutation ? 1 : 0);
    fprintf(f, "tun_mtu=%s\n", g_app.tun_mtu);
    fprintf(f, "tun_tcp_sndbuf=%s\n", g_app.tun_tcp_sndbuf);
    fprintf(f, "tun_tcp_rcvbuf=%s\n", g_app.tun_tcp_rcvbuf);
    fprintf(f, "tun_tcp_auto_tuning=%d\n", g_app.tun_tcp_auto_tuning ? 1 : 0);
    fprintf(f, "tun_exclude_private=%d\n", g_app.tun_exclude_private ? 1 : 0);
    fprintf(f, "tun_dns4=%s\n", g_app.tun_dns4);
    fprintf(f, "tun_dns6=%s\n", g_app.tun_dns6);
    fprintf(f, "logging_enabled=%d\n", g_app.logging_enabled ? 1 : 0);
    fprintf(f, "auto_scroll=%d\n", g_app.auto_scroll ? 1 : 0);
    fprintf(f, "auto_update_check=%d\n", g_app.auto_update_check ? 1 : 0);
    fprintf(f, "check_prereleases=%d\n", g_app.check_prereleases ? 1 : 0);
    fprintf(f, "ui_scale_percent=%d\n", g_app.ui_scale_percent);
    fprintf(f, "sys_profile=%d\n", g_app.sys_profile);
    fprintf(f, "engine_log=%d\n", g_app.engine_log);
    fprintf(f, "core_log=%d\n", g_app.core_log);
    fprintf(f, "tun2socks_log=%d\n", g_app.t2s_log);
    fprintf(f, "tor_bridges=%d\n", g_app.tor_bridges);
    // The cfg file is line-based, so newlines in a value would corrupt it on
    // reload. The engine accepts ';' as a bridge-line separator too, so store
    // the multi-line box that way.
    {
        char tor_lines[sizeof(g_app.tor_bridge_lines)];
        snprintf(tor_lines, sizeof(tor_lines), "%s", g_app.tor_bridge_lines);
        for (char* p = tor_lines; *p; ++p) {
            if (*p == '\n' || *p == '\r') *p = ';';
        }
        fprintf(f, "tor_bridge_lines=%s\n", tor_lines);
    }
    fprintf(f, "team_name=%s\n", g_app.team_name);
    fprintf(f, "access_token=%s\n", g_app.access_token);
    fprintf(f, "access_client_id=%s\n", g_app.access_client_id);
    fprintf(f, "access_client_secret=%s\n", g_app.access_client_secret);
    fprintf(f, "access_email=%s\n", g_app.access_email);
    fprintf(f, "routes_file=%s\n", g_app.routes_file);
    fprintf(f, "routes_inline_hex=%s\n", encode_config_text(g_app.routes_inline).c_str());
    const bool write_ok = !ferror(f);
    const bool close_ok = fclose(f) == 0;
#if defined(_WIN32)
    const bool replaced = write_ok && close_ok && MoveFileExW(widen(temporary).c_str(), widen(path).c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!replaced) _wremove(widen(temporary).c_str());
#else
    const bool replaced = write_ok && close_ok && rename(temporary.c_str(), path.c_str()) == 0;
    if (!replaced) remove(temporary.c_str());
#endif
    if (!replaced) {
        s_config_needs_retry = true;
        set_save_status_error("Save failed");
        g_app.add_log(1, ("[ui] save failed: " + path).c_str());
        return false;
    }
    s_config_needs_retry = false;
    if (!quiet) {
        set_save_status("Config saved!");
        g_app.add_log(4, ("[ui] config saved: " + path).c_str());
    }
    return true;
}

static uint64_t s_config_observed = 0;
static uint64_t s_config_persisted = 0;
static double s_config_changed_at = 0;
static double s_config_retry_at = 0;
static bool s_config_tracking = false;

static void autosave_config(double now) {
    const uint64_t signature = config_signature();
    if (!s_config_tracking) {
        s_config_observed = signature;
        s_config_persisted = s_config_needs_retry ? ~signature : signature;
        s_config_changed_at = now;
        s_config_tracking = true;
        return;
    }
    if (signature != s_config_observed) {
        s_config_observed = signature;
        s_config_changed_at = now;
    }
    if ((s_config_needs_retry || signature != s_config_persisted) && now >= s_config_retry_at && now - s_config_changed_at >= 0.6) {
        if (save_config(true)) s_config_persisted = signature;
        else s_config_retry_at = now + 5.0;
    }
}

static bool load_config_from(const std::string& path) {
    s_config_load_failed = false;
    FILE* f = open_cfg(path, "rb");
    if (!f) { s_config_load_failed = file_exists(path); return false; }

    // A saved core config is one line and can be far longer than a page, so a
    // line is read to its newline: a split one would be parsed as two keys, and
    // the second half would be discarded as malformed.
    static std::vector<char> chunk(8192);
    std::string line;
    // The file is the source of truth for the saved core configs, exactly as it
    // is for every other setting.
    g_app.core_configs.clear();
    s_loaded_chain_transports = false;
    s_loaded_tor_mode = 0;
    s_loaded_socks_port = false;
    s_loaded_http_port = false;
    s_loaded_firefox_socks_port = false;
    s_loaded_firefox_http_port = false;
    s_loaded_firefox_socks_enabled = false;
    s_loaded_firefox_http_enabled = false;
    s_loaded_aether_http_enabled = false;
    s_loaded_unified_aether_http = false;
    s_loaded_unified_firefox_http = false;
    s_legacy_tun_http = false;
    s_legacy_firefox_tun_http = false;
    s_loaded_legacy_firefox_tun_http = false;
    s_loaded_legacy_chain_count = -1;
    int applied = 0;
    bool continued = false;
    while (fgets(chunk.data(), (int)chunk.size(), f)) {
        const size_t got = strlen(chunk.data());
        if (!continued) line.clear();
        line.append(chunk.data(), got);
        const bool complete = got > 0 && chunk[got - 1] == '\n';
        if (!complete && !feof(f)) {
            continued = true;
            if (chunk.size() < (1u << 21)) chunk.resize(chunk.size() * 2);
            continue;
        }
        continued = false;
        size_t len = line.size();
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ' || line[len - 1] == '\t')) {
            --len;
        }
        line.resize(len);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        char* body = line.data();
        char* eq = strchr(body, '=');
        if (!eq) continue;
        *eq = '\0';
        const char* key = body;
        const char* val = eq + 1;
        while (*key == ' ' || *key == '\t') key++;
        char* kend = (char*)key + strlen(key);
        while (kend > key && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = '\0';
        // trim val leading only (preserve peer strings)
        while (*val == ' ' || *val == '\t') val++;

        if (*key) {
            apply_config_kv(key, val);
            applied++;
        }
    }
    fclose(f);

    if (applied == 0) { s_config_load_failed = true; return false; }
    if (!s_loaded_firefox_socks_enabled) g_app.firefox_socks_enabled = g_app.socks_enabled;
    if (!s_loaded_unified_firefox_http && !s_loaded_firefox_http_enabled)
        g_app.firefox_http_enabled = g_app.http_enabled;
    if (g_app.mode == 1) {
        if (!s_loaded_unified_aether_http) g_app.http_enabled = s_legacy_tun_http;
        if (!s_loaded_unified_firefox_http)
            g_app.firefox_http_enabled = s_loaded_legacy_firefox_tun_http ? s_legacy_firefox_tun_http : s_legacy_tun_http;
    }
    // Preserve explicit Firefox values and custom legacy ports; migrate old defaults.
    if (!s_loaded_firefox_socks_port)
        g_app.firefox_socks_port = s_loaded_socks_port && g_app.socks_port != 1819
            ? g_app.socks_port : AppState::kFirefoxDefaultSocksPort;
    if (!s_loaded_firefox_http_port)
        g_app.firefox_http_port = s_loaded_http_port && g_app.http_port != 1820
            ? g_app.http_port : AppState::kFirefoxDefaultHttpPort;
    if (!s_loaded_chain_transports && s_loaded_legacy_chain_count > 0) {
        g_app.chain_transports.clear();
        const int count = std::min(s_loaded_legacy_chain_count, 3);
        for (int i = 0; i < count; ++i) {
            const int backend = s_loaded_legacy_chain_exits[i];
            g_app.chain_transports.push_back(backend == 1 ? 5 : backend == 2 ? 10 : 0);
        }
    }
    // The protocol is the route's outermost element and the chain is what rides
    // it, so Tor and Psiphon are as valid there as MASQUE -- they are simply not
    // a route on their own. What used to be the engine's Tor routing mode says
    // the same thing in that one order, and is rewritten once: 1 = Tor behind the
    // tunnel, 2 = the tunnel behind Tor, 3 = the Psiphon egress. The mode itself
    // is no longer written back.
    {
        const int stored = current_transport();
        const bool stored_is_hop = stored == kTorTransport || stored == kPsiphonTransport;
        bool repaired = false;
        // The hop the old mode added behind the carrier the profile keeps. Mode 2
        // is the one that moves the carrier itself: Tor carries there, so Tor is
        // the protocol and the transport the profile names is what rides it.
        int exit_hop = -1;
        if (s_loaded_tor_mode == 2) {
            apply_transport(kTorTransport);
            exit_hop = stored_is_hop ? 0 : stored;
        } else if (s_loaded_tor_mode == 1) {
            exit_hop = kTorTransport;
        } else if (s_loaded_tor_mode == 3) {
            exit_hop = kPsiphonTransport;
        }
        if (exit_hop >= 0 && g_app.chain_transports.empty()) {
            // A hop never rides a copy of itself: where the carrier the profile
            // keeps is already that hop, the WARP transport becomes the exit it
            // used to sit on instead.
            g_app.chain_transports.push_back(exit_hop == current_transport() ? 0 : exit_hop);
            repaired = true;
        }
        // A route whose carrier is Tor or Psiphon needs something behind it, so
        // what used to be a standalone session becomes that carrier with the
        // WARP transport as its exit.
        const int carrier = current_transport();
        if ((carrier == kTorTransport || carrier == kPsiphonTransport)
            && g_app.chain_transports.empty()) {
            g_app.chain_transports.push_back(0);
            repaired = true;
        }
        s_loaded_tor_mode = 0;
        if (repaired)
            g_app.add_log(4, "[ui] the saved Tor/Psiphon route was rewritten as a chain");
    }
    // A saved config only counts when it has a name and a body: the per-field
    // keys of a half-written file must not become anonymous protocol entries.
    g_app.core_configs.erase(
        std::remove_if(g_app.core_configs.begin(), g_app.core_configs.end(),
                       [](const AppState::CoreConfigEntry& entry) {
                           return entry.name.empty() || entry.text.empty();
                       }),
        g_app.core_configs.end());
    // What each config can answer on, and the ports it pins, are cached for the
    // listener switches; the library only settles here.
    g_app.refresh_core_listeners();
    // Every reference to a saved config is a position, so a config that did not
    // survive above takes its references with it.
    if (g_app.core_selected < 0 || g_app.core_selected >= (int)g_app.core_configs.size()) {
        g_app.core_selected = -1;
        if (g_app.backend >= 3) {
            g_app.backend = 0;
            // Auto is the saved config's own transport talking; without one the
            // file's protocol field would claim it still has a profile.
            if (g_app.protocol == 3) g_app.protocol = 0;
        }
    }
    const int positions = transport_count();
    g_app.chain_transports.erase(
        std::remove_if(g_app.chain_transports.begin(), g_app.chain_transports.end(),
                       [positions](int transport) { return transport < 0 || transport >= positions; }),
        g_app.chain_transports.end());
    g_app.add_log(4, ("[ui] config loaded (" + std::to_string(applied) + " keys): " + path).c_str());
    return true;
}

static bool load_config() {
    std::string path = resolve_config_path_for_load();
    if (!load_config_from(path)) return false;
    // A legacy cfg was loaded: write it to the current location for next time.
    std::string primary = get_config_path();
    if (path != primary && !file_exists(primary)) {
        save_config();
        g_app.add_log(4, ("[ui] migrated config to " + primary).c_str());
    }
    return true;
}

void log_callback(FcaeLogLevel level, const char* message, void* user_data) {
    (void)user_data;
    if (g_app.logging_enabled.load(std::memory_order_relaxed)) {
        g_app.add_log((int)level, message);
        ui_request_redraw();
    }
}

// GetContentRegionAvail() after an item reports the next line's width, so
// right alignment must be measured from the previous item's end instead.
static void same_line_right_aligned(float right_edge_x, float item_w, float min_spacing) {
    ImGui::SameLine(0.0f, 0.0f);
    const float gap = right_edge_x - item_w - ImGui::GetCursorScreenPos().x;
    ImGui::SameLine(0.0f, gap > min_spacing ? gap : min_spacing);
}

enum class UiIcon : uint8_t { Info, Refresh, SoundOn, SoundOff };

// The round icon buttons follow the text: the whole row they sit on scales
// with the font, and a 20 px circle next to 26 px type looked like a speck.
// Every glyph below is expressed in units of this, through `k`, so the icon
// keeps its proportions at any size instead of growing a hollow circle.
static float icon_button_size() {
    return ImGui::GetTextLineHeight() * 1.15f;
}

// Shared by the About and sponsor buttons so they match Android's round icon
// buttons. Geometry is snapped to whole pixels: strokes centred on pixel edges
// were smeared across two columns and shimmered next to the crisp UI text.
// The button is vertically centred on the text line it follows. Info adds a
// white ring on top of the shared fill.
static bool round_icon_button(const char* id, UiIcon icon, bool toggled, const char* tooltip) {
    const float kIconButtonSize = icon_button_size();
    // Glyph geometry was authored against a 20 px circle; k rescales it.
    const float k = kIconButtonSize / 20.0f;
    const ImVec2 pos = ImGui::GetCursorScreenPos();
    const bool clicked = ImGui::InvisibleButton(id, ImVec2(kIconButtonSize, kIconButtonSize));
    const bool hovered = ImGui::IsItemHovered();
    const bool held = ImGui::IsItemActive();
    if (hovered) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImGui::SetItemTooltip("%s", tooltip);

    const ImU32 fg = IM_COL32(241, 247, 255, 255);
    const float cx = std::floor(pos.x) + kIconButtonSize * 0.5f;
    const float cy = std::floor(pos.y) + kIconButtonSize * 0.5f;
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImVec4 base = toggled ? ImVec4(0.102f, 0.380f, 0.620f, 1.0f)
                                : ImVec4(0.200f, 0.255f, 0.333f, 1.0f);
    const float tint = held ? -0.04f : hovered ? 0.06f : 0.0f;
    draw->AddCircleFilled(ImVec2(cx, cy), kIconButtonSize * 0.5f,
        ImGui::GetColorU32(ImVec4(base.x + tint, base.y + tint, base.z + tint, 1.0f)), 32);
    const float kRingWidth = 1.5f * k;
    if (icon == UiIcon::Info) {
        draw->AddCircle(ImVec2(cx, cy), kIconButtonSize * 0.5f - kRingWidth * 0.5f, fg, 32, kRingWidth);
    }

    switch (icon) {
    case UiIcon::Info:
        draw->AddRectFilled(ImVec2(cx - 1.0f * k, cy - 5.0f * k), ImVec2(cx + 1.0f * k, cy - 3.0f * k), fg);
        draw->AddRectFilled(ImVec2(cx - 1.0f * k, cy - 1.0f * k), ImVec2(cx + 1.0f * k, cy + 5.0f * k), fg);
        break;
    case UiIcon::Refresh: {
        constexpr float kPi = 3.14159265f;
        const float kRadius = 5.5f * k;
        constexpr float kGapCentre = -kPi * 0.25f;
        constexpr float kGapHalf = 0.5f;
        const float a0 = kGapCentre + kGapHalf;
        const float a1 = kGapCentre - kGapHalf + kPi * 2.0f;
        draw->PathArcTo(ImVec2(cx, cy), kRadius, a0, a1, 24);
        draw->PathStroke(fg, ImDrawFlags_None, 1.5f * k);
        const ImVec2 n(cosf(a1), sinf(a1));
        const ImVec2 t(-n.y, n.x);
        const ImVec2 e(cx + n.x * kRadius, cy + n.y * kRadius);
        draw->AddTriangleFilled(ImVec2(e.x + n.x * 3.0f * k, e.y + n.y * 3.0f * k),
                                ImVec2(e.x + t.x * 3.5f * k, e.y + t.y * 3.5f * k),
                                ImVec2(e.x - n.x * 3.0f * k, e.y - n.y * 3.0f * k), fg);
        break;
    }
    case UiIcon::SoundOn:
    case UiIcon::SoundOff: {
        const float ox = icon == UiIcon::SoundOn ? cx - 2.0f * k : cx;
        draw->AddRectFilled(ImVec2(ox - 5.0f * k, cy - 2.0f * k), ImVec2(ox - 2.0f * k, cy + 2.0f * k), fg);
        const ImVec2 cone[4] = {
            ImVec2(ox - 2.0f * k, cy - 2.0f * k), ImVec2(ox + 2.0f * k, cy - 5.0f * k),
            ImVec2(ox + 2.0f * k, cy + 5.0f * k), ImVec2(ox - 2.0f * k, cy + 2.0f * k),
        };
        draw->AddConvexPolyFilled(cone, 4, fg);
        if (icon == UiIcon::SoundOn) {
            draw->PathArcTo(ImVec2(ox + 2.0f * k, cy), 3.5f * k, -0.9f, 0.9f, 8);
            draw->PathStroke(fg, ImDrawFlags_None, 1.5f * k);
            draw->PathArcTo(ImVec2(ox + 2.0f * k, cy), 6.5f * k, -0.8f, 0.8f, 10);
            draw->PathStroke(fg, ImDrawFlags_None, 1.5f * k);
        } else {
            draw->AddLine(ImVec2(cx - 5.0f * k, cy - 5.0f * k), ImVec2(cx + 5.0f * k, cy + 5.0f * k),
                          IM_COL32(239, 68, 68, 255), 1.5f * k);
        }
        break;
    }
    }
    return clicked;
}

static void fmt_bytes(char* buf, size_t len, uint64_t b) {
    if (b >= 1073741824ULL) snprintf(buf, len, "%.2f GB", (double)b / 1073741824.0);
    else if (b >= 1048576ULL) snprintf(buf, len, "%.2f MB", (double)b / 1048576.0);
    else if (b >= 1024ULL) snprintf(buf, len, "%.2f KB", (double)b / 1024.0);
    else snprintf(buf, len, "%llu B", (unsigned long long)b);
}

static void fmt_rate(char* buf, size_t len, uint64_t bps) {
    if (bps >= 1073741824ULL) snprintf(buf, len, "%.2f GB/s", (double)bps / 1073741824.0);
    else if (bps >= 1048576ULL) snprintf(buf, len, "%.2f MB/s", (double)bps / 1048576.0);
    else if (bps >= 1024ULL) snprintf(buf, len, "%.2f KB/s", (double)bps / 1024.0);
    else snprintf(buf, len, "%llu B/s", (unsigned long long)bps);
}

static ImVec4 state_color(FcaeState s) {
    switch (s) {
        case FCAE_STATE_DISCONNECTED: return ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
        case FCAE_STATE_PROVISIONING:
        case FCAE_STATE_SCANNING:
        case FCAE_STATE_CONNECTING:   return ImVec4(0.30f, 0.60f, 1.00f, 1.0f);
        // Amber: the tunnel dropped and is being re-established. Previously
        // indistinguishable from a first connect.
        case FCAE_STATE_RECONNECTING: return ImVec4(1.00f, 0.72f, 0.20f, 1.0f);
        case FCAE_STATE_CONNECTED:    return ImVec4(0.20f, 0.90f, 0.35f, 1.0f);
        case FCAE_STATE_ERROR:        return ImVec4(1.00f, 0.30f, 0.30f, 1.0f);
    }
    return ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
}

static const char* state_label(FcaeState s) {
    if (s == FCAE_STATE_CONNECTED)
        return g_app.mode == 1 ? "CONNECTED - TUN" : "CONNECTED - PROXY";
    switch (s) {
        case FCAE_STATE_DISCONNECTED: return "DISCONNECTED";
        case FCAE_STATE_PROVISIONING:
        case FCAE_STATE_SCANNING:
        case FCAE_STATE_CONNECTING:   return "CONNECTING";
        case FCAE_STATE_RECONNECTING: return "RECONNECTING";
        case FCAE_STATE_CONNECTED:    return "CONNECTED";
        case FCAE_STATE_ERROR:        return "ERROR";
    }
    return "UNKNOWN";
}

/// One proxy listener, the way sing-box configures one: a single switch and the
/// port it answers on, on the same line.
///
/// Every backend used to spell this out itself, with a checkbox named "<backend>
/// SOCKS5 proxy" and then an InputScalar a row or two below, enabled or not.
/// Two different widgets for one idea is what made the settings pages look
/// unlike each other, so they all go through here now. The port field is
/// disabled while the listener is off, because a port for something that is not
/// listening is only ever a way to mis-set it.
///
/// Returns true when the switch was toggled, so a caller that has to restart
/// something can react; the toggle itself is already applied.
static bool listener_row(const char* label, bool* enabled, ImU16* port,
                         ImU16 min_port, ImU16 max_port) {
    ImGui::PushID(label);
    // The switch carries the port, so the row is: [x] SOCKS5   port [ 1819 ]
    const bool row_toggled = ImGui::Checkbox("##enabled", enabled);
    // The checkbox, the label and the port field are three different heights on
    // one line. ImGui aligns them by their top edge, so at anything above the
    // default type size the label sat high against the box and the field -- the
    // "status is not centred on the row" complaint. Centre each on the square
    // one, which is the tallest of the three.
    const float row_h = ImGui::GetFrameHeight();
    const float label_dy = std::floor((row_h - ImGui::GetTextLineHeight()) * 0.5f);
    const float field_dy = std::floor((row_h - ImGui::GetFrameHeight()) * 0.5f);
    ImGui::SameLine(0, 8);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + label_dy);
    ImGui::TextUnformatted(label);
    ImGui::SameLine(0, 10);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + field_dy);
    ImGui::BeginDisabled(!*enabled);
    // Wide enough for the widest text this field can hold, so "65535" never
    // touches the frame edge; 90 px was sized for the old font.
    const float port_w = ImGui::CalcTextSize("65535").x + ImGui::GetStyle().FramePadding.x * 2.0f + 8.0f;
    ImGui::PushItemWidth(port_w);
    ImGui::InputScalar("##port", ImGuiDataType_U16, port, nullptr, nullptr, "%u");
    ImGui::PopItemWidth();
    ImGui::EndDisabled();
    // Clamp once the field has lost focus, so typing "18" on the way to "1819"
    // is not fought with on every keystroke.
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        if (*port < min_port) *port = min_port;
        if (*port > max_port) *port = max_port;
    }
    ImGui::PopID();
    return row_toggled;
}

/// A ring of dots that spins: the "something is happening" indicator beside the
/// CONNECT button and the scan/save status line.
///
/// It reserves a square as tall as the current text line and centres the ring
/// in it, so it shares a baseline with the label next to it whatever the font
/// size is. The previous version centred on (x + radius + 2, y + radius) while
/// reserving a box of (radius * 2 + 4) on both axes: the ring sat 2 px high
/// inside its own box, and since it was drawn from the top of a 32 px action
/// row the whole thing rode above the button it was meant to sit beside.
static void draw_spinner(float radius, float speed) {
    const float t = (float)ImGui::GetTime() * speed;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetCursorScreenPos();

    // The box this widget reserves is line-height tall, so the ring has to be
    // centred inside that box -- not on the text baseline, which is what put it
    // above the middle of its row before. (The previous version centred on
    // p.y + line_h / 2 while reserving an `extent`-tall box, so the ring rode
    // high by (extent - line_h) / 2 whenever the two differed.)
    const float line_h = ImGui::GetTextLineHeight();
    const float extent = (radius * 2.0f + 4.0f) > line_h ? (radius * 2.0f + 4.0f) : line_h;
    const ImVec2 c(p.x + extent * 0.5f, p.y + extent * 0.5f);

    // One arc on a fixed radius, fading from transparent to bright along its
    // length, so it reads as a ring turning in place. The old version varied
    // the radius with the same parameter as the angle, which drew a spiral
    // and made the "ring" look lopsided and off-centre rather than orbiting.
    const float thickness = 2.0f;
    const int   arc_segments = 12;
    for (int i = 0; i < arc_segments; i++) {
        const float phase = (float)i / (float)arc_segments;
        const float a = phase * 4.7124f + t;      // three quarters of a turn
        // Alpha ramps up along the arc: the head is solid, the tail fades out.
        const float alpha = 0.15f + 0.85f * phase;
        const ImVec4 col(0.35f + 0.15f * phase, 0.65f + 0.15f * phase, 1.0f, alpha);
        dl->AddCircleFilled(ImVec2(c.x + cosf(a) * radius, c.y + sinf(a) * radius),
                            thickness, ImGui::ColorConvertFloat4ToU32(col), 8);
    }
    ImGui::Dummy(ImVec2(extent, extent));
}

void ui_init() {
    s_runtime_init.store(RuntimeInitState::Starting, std::memory_order_relaxed);
    s_runtime_init_thread = std::thread([] {
        // Settings first: the file parse takes milliseconds and the first
        // paints need nothing else. Once this block finishes it flips
        // s_config_loaded and the UI swaps the splash shell for the real
        // window; runtime initialisation below runs in the background of
        // that first paint and publishes Ready separately.
        if (!load_config()) {
            if (s_config_load_failed) {
                // The file is there but none of it could be applied; don't
                // pretend this was a fresh install.
                set_save_status_error("Couldn't load config (invalid or unreadable)");
                g_app.add_log(1, ("[ui] couldn't load config (invalid or unreadable): "
                                  + resolve_config_path_for_load()).c_str());
            } else if (save_config()) {
                // First run: write defaults next to the executable (or app files on
                // Android). AppState defaults mode = 1, so a fresh install starts in
                // TUN (full-system) mode on every desktop platform; a saved config
                // keeps whatever the user last chose.
                set_save_status("Created FCAE_VPN.cfg");
                g_app.add_log(4, ("[ui] created default config: " + get_config_path()).c_str());
            }
        }
        // Data paths stay relative to data_dir() so the folder can move
        // between machines; resolve_data_path() anchors them at use.
        bool migrated = make_portable(g_app.config_path, sizeof(g_app.config_path));
        migrated |= make_portable(g_app.psiphon_data_dir, sizeof(g_app.psiphon_data_dir));
        migrated |= make_portable(g_app.routes_file, sizeof(g_app.routes_file));
        if (!g_app.psiphon_data_dir[0]) {
            snprintf(g_app.psiphon_data_dir, sizeof(g_app.psiphon_data_dir), "psiphon");
            migrated = true;
        }
        if (migrated) save_config();
        g_app.add_log(4, ("[ui] data folder: " + data_dir()).c_str());
        g_app.add_log(4, ("[ui] settings file: " + get_config_path()).c_str());
        g_app.add_log(4, ("[ui] identity file: " + resolve_data_path(g_app.config_path)).c_str());
        s_config_loaded.store(true, std::memory_order_release);
        ui_request_redraw();   // the first real frame becomes paintable
        // Nothing here needs the parent to be gone: process teardown is
        // independent, and there is no lock either process takes. The wait used
        // to run right here, in front of fcae_init(), so every byte of engine
        // setup was serialised behind a parent that can take its full eight
        // seconds to exit -- most of why an elevated start felt slow. It now
        // runs on its own thread purely to record how long the parent took,
        // and initialisation begins immediately.
        #ifdef _WIN32
        DWORD handoff_pid = 0;
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv) {
            if (argc == 3 && std::wcscmp(argv[1], L"--fcae-wait-parent") == 0) {
                wchar_t* end = nullptr;
                unsigned long pid = std::wcstoul(argv[2], &end, 10);
                if (end != argv[2] && *end == L'\0' && pid != 0 && pid != GetCurrentProcessId())
                    handoff_pid = static_cast<DWORD>(pid);
            }
            LocalFree(argv);
        }
        if (handoff_pid) {
            fcae_ui_diagnostic(6, handoff_pid);
            std::thread([handoff_pid] {
                DWORD handoff_result = WAIT_FAILED;
                HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, handoff_pid);
                if (parent) {
                    handoff_result = WaitForSingleObject(parent, 8000);
                    CloseHandle(parent);
                }
                fcae_ui_diagnostic(7, handoff_result);
            }).detach();
        }
        #endif
        bool runtime_ok = true;
        FcaeInitOptions opt = {};
        opt.struct_size   = sizeof(opt);
        opt.abi_version   = FCAE_ABI_VERSION;
        opt.log_cb        = log_callback;
        opt.state_cb      = nullptr;   // the UI already polls telemetry each frame
        opt.user_data     = nullptr;
        opt.max_log_level = FCAE_LOG_INFO;
        if (fcae_init(&opt) != FCAE_OK) {
            g_app.add_log(FCAE_LOG_ERROR, fcae_last_error());
            runtime_ok = false;
        }
        if (runtime_ok && g_app.mode == 1)
            fcae_ui_diagnostic(0, uint32_t(g_app.tun_engine));

        // Auto-trigger update check once on startup if enabled and the FFI is live.
        if (runtime_ok && g_app.auto_update_check) {
            fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
        }
        s_runtime_init.store(
            runtime_ok ? RuntimeInitState::Ready : RuntimeInitState::Failed,
            std::memory_order_release);
        ui_request_redraw();
    });
}

static void render_startup_shell(bool failed) {
    const ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);
    ImGui::Text("FCAE VPN");
    ImGui::SameLine();
    ImGui::TextDisabled("%s  |  %s", fcae_display_version(),
                        build_is_prerelease() ? "pre-release" : "release");
    ImGui::Spacing();
    ImGui::TextColored(failed ? ImVec4(0.9f, 0.25f, 0.25f, 1.0f)
                              : ImVec4(0.55f, 0.58f, 0.65f, 1.0f),
                       failed ? "INITIALIZATION FAILED" : "INITIALIZING...");
    ImGui::BeginDisabled();
    ImGui::Button("CONNECT", ImVec2(140, 34));
    ImGui::EndDisabled();
    ImGui::End();
}

void ui_frame() {
    // An elevation hand-off is armed on a worker and has to be finished on this
    // thread. This is the only place that keeps running: the old single call
    // site was inside the CONNECT click handler, one instant after arming the
    // flag, so at the moment it ran the flag was still clear and the check
    // never fired again -- the relaunched elevated instance appeared while this
    // one went on living, which is the second window behind it.
    ui_handoff_tick();

    // The user's text scale, applied every frame. Font size is not baked at
    // init in this ImGui: the base size is multiplied by the scale factors
    // each frame and glyphs are rasterised per size on demand, so this is a
    // live setting, not a restart-to-apply one. FontSizeBase itself is left
    // alone -- ImGui resolves it from the loaded font on the first frame --
    // and per-monitor DPI stays the host's business (style.FontScaleDpi), so
    // the two factors never compound.
    {
        ImGuiStyle& style = ImGui::GetStyle();
        float user_scale = (float)g_app.ui_scale_percent / 100.0f;
        if (user_scale < 0.75f) user_scale = 0.75f;
        if (user_scale > 2.50f) user_scale = 2.50f;
        if (style.FontScaleMain != user_scale) style.FontScaleMain = user_scale;
    }

    // Consume the request before drawing so a request arriving during this
    // frame (including initialization completing) remains pending.
    g_app.redraw_requested.exchange(false);
    // The update panel sets this again below when a check is running; resetting
    // it first keeps the flag honest on frames that return early.
    s_update_in_progress = false;

    const RuntimeInitState init = s_runtime_init.load(std::memory_order_acquire);
    if (!s_config_loaded.load()) {
        // Settings parse only: this phase lasts a frame or two.
        render_startup_shell(false);
        s_busy_anim = false;
        s_painted_once = true;
        return;
    }
    if (init == RuntimeInitState::Failed) {
        render_startup_shell(true);
        s_busy_anim = false;
        s_painted_once = true;
        return;
    }

    // The real UI from the first frame; engine-dependent actions gate
    // themselves on Ready inside render_ui() instead of blocking everything
    // behind the INITIALIZING shell.
    render_ui();

    // The connect/scan spinner keeps requesting frames while it moves; every
    // other repaint is gated on content changes in ui_should_render().
    const int st = g_app.ffi_state.load();
    s_busy_anim = g_app.start_busy.load()
               || st == FCAE_STATE_PROVISIONING
               || st == FCAE_STATE_SCANNING
               || st == FCAE_STATE_CONNECTING
               || st == FCAE_STATE_RECONNECTING;

    ui_note_frame_drawn();
}

void ui_shutdown() {
    // The initializer owns the runtime and AppState until it has finished.
    if (s_runtime_init_thread.joinable()) s_runtime_init_thread.join();
    fcae_ui_diagnostic(5, 0);
    fcae_sponsor_set_ui_active(false);
    s_sponsor_rgba.clear();
    s_sponsor_rgba.shrink_to_fit();
    s_sponsor_background_rgba.clear();
    s_sponsor_background_rgba.shrink_to_fit();
    s_sponsor_loaded_foreground_generation = 0;
    s_sponsor_loaded_background_generation = 0;
    if (s_config_tracking && (s_config_needs_retry || config_signature() != s_config_persisted)) save_config(true);

    // fcae_shutdown() stops any running session and then waits (bounded) for
    // the background worker to finish its OS restore — routes and DNS back —
    // so the process may exit with nothing left dangling. The wait is capped
    // because the slow tail (a Psiphon controller join) dies with the process
    // anyway, and the kernel cleans that up.
    FcaeStatus s = fcae_shutdown();
    if (s != FCAE_OK) {
        // Log the failure before forcing termination: a stuck session worker
        // (e.g. a route restore that never returns) otherwise hides its cause
        // behind an "app closed and the system DNS stayed broken" report. Not a
        // stderr printf -- this runs on GUI-subsystem Windows too, where the
        // in-process log is the only record still alive at this point.
        const char* why = fcae_last_error();
        g_app.add_log(FCAE_LOG_ERROR,
            why && why[0]
                ? why
                : "fcae_shutdown() failed; routes/DNS may need manual restore");
    }
#if defined(_WIN32)
    // ExitProcess is the right call here: a normal `return` would unwind the
    // GUI thread while background workers are still tearing down, and a
    // runtime shutdown abort would still leave the ImGui render thread
    // holding the only strong reference to device resources. Process exit is
    // the documented contract for this binary.
    ExitProcess(0);
#endif
}

static const char* psiphon_country_name(const std::string& code) {
    static const std::unordered_map<std::string, const char*> kCountryNames = {
        {"AD", "Andorra"},
        {"AE", "United Arab Emirates"},
        {"AF", "Afghanistan"},
        {"AG", "Antigua and Barbuda"},
        {"AI", "Anguilla"},
        {"AL", "Albania"},
        {"AM", "Armenia"},
        {"AO", "Angola"},
        {"AQ", "Antarctica"},
        {"AR", "Argentina"},
        {"AS", "American Samoa"},
        {"AT", "Austria"},
        {"AU", "Australia"},
        {"AW", "Aruba"},
        {"AX", "Åland Islands"},
        {"AZ", "Azerbaijan"},
        {"BA", "Bosnia and Herzegovina"},
        {"BB", "Barbados"},
        {"BD", "Bangladesh"},
        {"BE", "Belgium"},
        {"BF", "Burkina Faso"},
        {"BG", "Bulgaria"},
        {"BH", "Bahrain"},
        {"BI", "Burundi"},
        {"BJ", "Benin"},
        {"BL", "Saint Barthélemy"},
        {"BM", "Bermuda"},
        {"BN", "Brunei"},
        {"BO", "Bolivia"},
        {"BQ", "Caribbean Netherlands"},
        {"BR", "Brazil"},
        {"BS", "Bahamas"},
        {"BT", "Bhutan"},
        {"BV", "Bouvet Island"},
        {"BW", "Botswana"},
        {"BY", "Belarus"},
        {"BZ", "Belize"},
        {"CA", "Canada"},
        {"CC", "Cocos (Keeling) Islands"},
        {"CD", "Congo (DRC)"},
        {"CF", "Central African Republic"},
        {"CG", "Congo (Republic)"},
        {"CH", "Switzerland"},
        {"CI", "Côte d'Ivoire"},
        {"CK", "Cook Islands"},
        {"CL", "Chile"},
        {"CM", "Cameroon"},
        {"CN", "China"},
        {"CO", "Colombia"},
        {"CR", "Costa Rica"},
        {"CU", "Cuba"},
        {"CV", "Cape Verde"},
        {"CW", "Curaçao"},
        {"CX", "Christmas Island"},
        {"CY", "Cyprus"},
        {"CZ", "Czechia"},
        {"DE", "Germany"},
        {"DJ", "Djibouti"},
        {"DK", "Denmark"},
        {"DM", "Dominica"},
        {"DO", "Dominican Republic"},
        {"DZ", "Algeria"},
        {"EC", "Ecuador"},
        {"EE", "Estonia"},
        {"EG", "Egypt"},
        {"EH", "Western Sahara"},
        {"ER", "Eritrea"},
        {"ES", "Spain"},
        {"ET", "Ethiopia"},
        {"FI", "Finland"},
        {"FJ", "Fiji"},
        {"FK", "Falkland Islands"},
        {"FM", "Micronesia"},
        {"FO", "Faroe Islands"},
        {"FR", "France"},
        {"GA", "Gabon"},
        {"GB", "United Kingdom"},
        {"GD", "Grenada"},
        {"GE", "Georgia"},
        {"GF", "French Guiana"},
        {"GG", "Guernsey"},
        {"GH", "Ghana"},
        {"GI", "Gibraltar"},
        {"GL", "Greenland"},
        {"GM", "Gambia"},
        {"GN", "Guinea"},
        {"GP", "Guadeloupe"},
        {"GQ", "Equatorial Guinea"},
        {"GR", "Greece"},
        {"GS", "South Georgia"},
        {"GT", "Guatemala"},
        {"GU", "Guam"},
        {"GW", "Guinea-Bissau"},
        {"GY", "Guyana"},
        {"HK", "Hong Kong"},
        {"HM", "Heard and McDonald Islands"},
        {"HN", "Honduras"},
        {"HR", "Croatia"},
        {"HT", "Haiti"},
        {"HU", "Hungary"},
        {"ID", "Indonesia"},
        {"IE", "Ireland"},
        {"IL", "Israel"},
        {"IM", "Isle of Man"},
        {"IN", "India"},
        {"IO", "British Indian Ocean Territory"},
        {"IQ", "Iraq"},
        {"IR", "Iran"},
        {"IS", "Iceland"},
        {"IT", "Italy"},
        {"JE", "Jersey"},
        {"JM", "Jamaica"},
        {"JO", "Jordan"},
        {"JP", "Japan"},
        {"KE", "Kenya"},
        {"KG", "Kyrgyzstan"},
        {"KH", "Cambodia"},
        {"KI", "Kiribati"},
        {"KM", "Comoros"},
        {"KN", "Saint Kitts and Nevis"},
        {"KP", "North Korea"},
        {"KR", "South Korea"},
        {"KW", "Kuwait"},
        {"KY", "Cayman Islands"},
        {"KZ", "Kazakhstan"},
        {"LA", "Laos"},
        {"LB", "Lebanon"},
        {"LC", "Saint Lucia"},
        {"LI", "Liechtenstein"},
        {"LK", "Sri Lanka"},
        {"LR", "Liberia"},
        {"LS", "Lesotho"},
        {"LT", "Lithuania"},
        {"LU", "Luxembourg"},
        {"LV", "Latvia"},
        {"LY", "Libya"},
        {"MA", "Morocco"},
        {"MC", "Monaco"},
        {"MD", "Moldova"},
        {"ME", "Montenegro"},
        {"MF", "Saint Martin"},
        {"MG", "Madagascar"},
        {"MH", "Marshall Islands"},
        {"MK", "North Macedonia"},
        {"ML", "Mali"},
        {"MM", "Myanmar"},
        {"MN", "Mongolia"},
        {"MO", "Macao"},
        {"MP", "Northern Mariana Islands"},
        {"MQ", "Martinique"},
        {"MR", "Mauritania"},
        {"MS", "Montserrat"},
        {"MT", "Malta"},
        {"MU", "Mauritius"},
        {"MV", "Maldives"},
        {"MW", "Malawi"},
        {"MX", "Mexico"},
        {"MY", "Malaysia"},
        {"MZ", "Mozambique"},
        {"NA", "Namibia"},
        {"NC", "New Caledonia"},
        {"NE", "Niger"},
        {"NF", "Norfolk Island"},
        {"NG", "Nigeria"},
        {"NI", "Nicaragua"},
        {"NL", "Netherlands"},
        {"NO", "Norway"},
        {"NP", "Nepal"},
        {"NR", "Nauru"},
        {"NU", "Niue"},
        {"NZ", "New Zealand"},
        {"OM", "Oman"},
        {"PA", "Panama"},
        {"PE", "Peru"},
        {"PF", "French Polynesia"},
        {"PG", "Papua New Guinea"},
        {"PH", "Philippines"},
        {"PK", "Pakistan"},
        {"PL", "Poland"},
        {"PM", "Saint Pierre and Miquelon"},
        {"PN", "Pitcairn"},
        {"PR", "Puerto Rico"},
        {"PS", "Palestine"},
        {"PT", "Portugal"},
        {"PW", "Palau"},
        {"PY", "Paraguay"},
        {"QA", "Qatar"},
        {"RE", "Réunion"},
        {"RO", "Romania"},
        {"RS", "Serbia"},
        {"RU", "Russia"},
        {"RW", "Rwanda"},
        {"SA", "Saudi Arabia"},
        {"SB", "Solomon Islands"},
        {"SC", "Seychelles"},
        {"SD", "Sudan"},
        {"SE", "Sweden"},
        {"SG", "Singapore"},
        {"SH", "Saint Helena"},
        {"SI", "Slovenia"},
        {"SJ", "Svalbard and Jan Mayen"},
        {"SK", "Slovakia"},
        {"SL", "Sierra Leone"},
        {"SM", "San Marino"},
        {"SN", "Senegal"},
        {"SO", "Somalia"},
        {"SR", "Suriname"},
        {"SS", "South Sudan"},
        {"ST", "São Tomé and Príncipe"},
        {"SV", "El Salvador"},
        {"SX", "Sint Maarten"},
        {"SY", "Syria"},
        {"SZ", "Eswatini"},
        {"TC", "Turks and Caicos Islands"},
        {"TD", "Chad"},
        {"TF", "French Southern Territories"},
        {"TG", "Togo"},
        {"TH", "Thailand"},
        {"TJ", "Tajikistan"},
        {"TK", "Tokelau"},
        {"TL", "Timor-Leste"},
        {"TM", "Turkmenistan"},
        {"TN", "Tunisia"},
        {"TO", "Tonga"},
        {"TR", "Turkey"},
        {"TT", "Trinidad and Tobago"},
        {"TV", "Tuvalu"},
        {"TW", "Taiwan"},
        {"TZ", "Tanzania"},
        {"UA", "Ukraine"},
        {"UG", "Uganda"},
        {"UM", "U.S. Minor Outlying Islands"},
        {"US", "United States"},
        {"UY", "Uruguay"},
        {"UZ", "Uzbekistan"},
        {"VA", "Vatican City"},
        {"VC", "Saint Vincent and the Grenadines"},
        {"VE", "Venezuela"},
        {"VG", "British Virgin Islands"},
        {"VI", "U.S. Virgin Islands"},
        {"VN", "Vietnam"},
        {"VU", "Vanuatu"},
        {"WF", "Wallis and Futuna"},
        {"WS", "Samoa"},
        {"YE", "Yemen"},
        {"YT", "Mayotte"},
        {"ZA", "South Africa"},
        {"ZM", "Zambia"},
        {"ZW", "Zimbabwe"}
    };
    auto it = kCountryNames.find(code);
    return (it != kCountryNames.end()) ? it->second : nullptr;
}

static std::string psiphon_region_label(const std::string& code) {
    if (code.empty()) return "Auto";
    const char* name = psiphon_country_name(code);
    if (name) {
        return std::string(name) + " (" + code + ")";
    }
    return code;
}

// https only, host-allowlisted, exec'd as one argv entry (never shell text).
static bool open_external_url(const char* url) {
    if (!url || strncmp(url, "https://", 8) != 0) return false;

    static const char* const kAllowedHosts[] = { "github.com", "t.me" };
    const char* host = url + 8;
    bool host_ok = false;
    for (const char* allowed : kAllowedHosts) {
        const size_t n = strlen(allowed);
        if (strncmp(host, allowed, n) == 0 && (host[n] == '/' || host[n] == '\0')) {
            host_ok = true;
            break;
        }
    }
    if (!host_ok && strcmp(url, "https://accounts.firefox.com/signup") == 0) host_ok = true;
    if (!host_ok) return false;

    for (const char* c = url; *c; ++c) {
        if (*c == '\'' || *c == '"' || *c == '`' || *c == '\\' ||
            *c == '\n' || *c == '\r') return false;
    }
#if defined(_WIN32)
    return (INT_PTR)ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL) > 32;
#elif defined(ANDROID)
    return false;
#else
    pid_t pid = fork();
    if (pid == 0) {
#if defined(__APPLE__)
        execlp("open", "open", url, static_cast<char*>(nullptr));
#else
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execlp("xdg-open", "xdg-open", url, static_cast<char*>(nullptr));
#endif
        _exit(127);
    }
    if (pid < 0) return false;
    int status = 0;
    waitpid(pid, &status, 0);
    return status == 0;
#endif
}

static void open_link(const char* url) {
    if (open_external_url(url)) return;
    ImGui::SetClipboardText(url);
    g_app.add_log(FCAE_LOG_WARN, "[ui] could not open the link in a browser; it is on the clipboard");
}

static ImVec2 viewport_center() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    return ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f, vp->WorkPos.y + vp->WorkSize.y * 0.5f);
}

static const char* const kLinkTelegram = "https://t.me/FCAE_VPN";
static const char* const kLinkGithub = "https://github.com/FCFlenkchy/FCAE_VPN";
static const std::string kLinkCredits = std::string(kLinkGithub) + "#credits";
static const std::string kLinkLicense = std::string(kLinkGithub) + "/blob/main/LICENSE";
static const char* const kGramAddress = "UQAz9mcfJ5qlba97SPbrCw-Yt8OhhT58yG9PzARyu1Muz0jV";
struct CommunityLink { const char* label; const char* url; const char* shown; };
static const CommunityLink kCommunityLinks[] = {
    { "Telegram", kLinkTelegram, "t.me/FCAE_VPN" },
    { "GitHub",   kLinkGithub,   "github.com/FCFlenkchy/FCAE_VPN" },
};

static std::string firefox_json_escape(const char* value) {
    std::string out;
    if (!value) return out;
    for (const unsigned char c : std::string(value)) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char escaped[7];
                    snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned)c);
                    out += escaped;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    return out;
}

static std::string firefox_json_string(const std::string& json, const char* key, size_t from = 0) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t search = from;
    while (true) {
        size_t pos = json.find(needle, search);
        if (pos == std::string::npos) return {};
        pos = json.find(':', pos + needle.size());
        if (pos == std::string::npos) return {};
        ++pos;
        while (pos < json.size() && isspace((unsigned char)json[pos])) ++pos;
        if (pos >= json.size() || json[pos] != '"') {
            search = pos;
            continue;
        }
        ++pos;
        std::string out;
        while (pos < json.size()) {
            char c = json[pos++];
            if (c == '"') return out;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (pos >= json.size()) return {};
            char escaped = json[pos++];
            switch (escaped) {
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case '"': case '\\': case '/': out.push_back(escaped); break;
                case 'u':
                    if (pos + 4 > json.size()) return {};
                    out.push_back('?');
                    pos += 4;
                    break;
                default: return {};
            }
        }
        return {};
    }
}

static bool firefox_json_bool(const std::string& json, const char* key, size_t from = 0) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle, from);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && isspace((unsigned char)json[pos])) ++pos;
    return json.compare(pos, 4, "true") == 0;
}

struct FirefoxLocationOption {
    std::string value;
    std::string label;
    std::string alias;
};

struct FirefoxAccountOption {
    std::string id;
    std::string email;
    std::string monthly_usage;
    bool usage_exhausted = false;
};

static bool s_firefox_has_locations = false;
static std::vector<FirefoxLocationOption> s_firefox_location_options = {
    {"", "Auto", ""},
};
static std::vector<FirefoxAccountOption> s_firefox_account_options;
static uint64_t s_firefox_status_revision = 0;

static void set_firefox_status(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(g_app.firefox_status, sizeof(g_app.firefox_status), format, args);
    va_end(args);
    ++s_firefox_status_revision;
}

static void firefox_submit(const std::string& request, const char* pending);
static void firefox_start_regions(bool cached);
static void firefox_queue_usage(const std::string& id);
static bool s_firefox_accounts_loaded = false;
static std::string s_firefox_removing_account_id;
static bool s_firefox_settings_popup_open = false;
static bool s_firefox_settings_visible = false;
static double s_firefox_usage_refresh_at = 0.0;
static bool s_firefox_add_popup_open = false;
static bool s_firefox_code_popup_open = false;
static bool s_firefox_add_should_close = false;
static bool s_firefox_code_should_close = false;
static bool s_firefox_unblock_required = false;
static bool s_firefox_email_link = false;
static bool s_chain_editor_popup_open = false;
static int s_protocol_draft = 0;
static std::vector<int> s_chain_draft;

static std::vector<std::string> firefox_json_objects(const std::string& json, const char* key) {
    std::vector<std::string> objects;
    const size_t key_pos = json.find(std::string("\"") + key + "\"");
    if (key_pos == std::string::npos) return objects;
    size_t cursor = json.find('[', key_pos);
    if (cursor == std::string::npos) return objects;
    ++cursor;
    while (cursor < json.size()) {
        const size_t start = json.find_first_of("{]", cursor);
        if (start == std::string::npos || json[start] == ']') break;
        bool quoted = false;
        bool escaped = false;
        int depth = 1;
        size_t end = start + 1;
        for (; end < json.size(); ++end) {
            const char c = json[end];
            if (escaped) {
                escaped = false;
            } else if (quoted && c == '\\') {
                escaped = true;
            } else if (c == '"') {
                quoted = !quoted;
            } else if (!quoted && c == '{') {
                ++depth;
            } else if (!quoted && c == '}' && --depth == 0) {
                break;
            }
        }
        if (end >= json.size()) break;
        objects.push_back(json.substr(start, end - start + 1));
        cursor = end + 1;
    }
    return objects;
}

static std::vector<FirefoxLocationOption> firefox_parse_locations(const std::string& json) {
    std::vector<FirefoxLocationOption> options;
    for (const std::string& object : firefox_json_objects(json, "locations")) {
        FirefoxLocationOption option{
            firefox_json_string(object, "value"),
            firefox_json_string(object, "label"),
            firefox_json_string(object, "alias"),
        };
        if (!option.value.empty() && !option.label.empty()) options.push_back(std::move(option));
    }
    return options;
}

static std::vector<FirefoxAccountOption> firefox_parse_accounts(const std::string& json) {
    std::vector<FirefoxAccountOption> accounts;
    for (const std::string& object : firefox_json_objects(json, "accounts")) {
        FirefoxAccountOption account{
            firefox_json_string(object, "id"),
            firefox_json_string(object, "email"),
            firefox_json_string(object, "monthly_usage"),
            firefox_json_bool(object, "monthly_usage_exhausted"),
        };
        if (!account.id.empty()) accounts.push_back(std::move(account));
    }
    return accounts;
}

static void firefox_clear_login_form() {
    g_app.firefox_password[0] = 0;
    g_app.firefox_code[0] = 0;
    g_app.firefox_pending_id[0] = 0;
    g_app.firefox_totp = false;
    g_app.firefox_email[0] = 0;
    s_firefox_unblock_required = false;
    s_firefox_email_link = false;
}

static void firefox_select_account(const FirefoxAccountOption& account) {
    snprintf(g_app.firefox_account_id, sizeof(g_app.firefox_account_id), "%s", account.id.c_str());
    snprintf(g_app.firefox_email, sizeof(g_app.firefox_email), "%s", account.email.c_str());
    save_config();
}

static void firefox_account_rows(const std::string& root) {
    if (s_firefox_account_options.empty() && s_firefox_accounts_loaded) {
        ImGui::TextDisabled("No saved Firefox accounts.");
        ImGui::TextUnformatted("Don't have an account?");
        ImGui::SameLine();
        if (ImGui::TextLink("Create one")) open_link("https://accounts.firefox.com/signup");
    }
    for (const FirefoxAccountOption& account : s_firefox_account_options) {
        ImGui::PushID(account.id.c_str());
        const std::string email = account.email.empty() ? account.id : account.email;
        const bool selected = g_app.firefox_account_id == account.id;
        ImGui::TextUnformatted(email.c_str());
        if (account.usage_exhausted)
            ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "Monthly usage: %s", account.monthly_usage.c_str());
        else
            ImGui::TextDisabled("Monthly usage: %s", account.monthly_usage.empty() ? "Unavailable" : account.monthly_usage.c_str());
        ImGui::BeginDisabled(selected);
        if (ImGui::SmallButton(selected ? "Selected" : "Use")) firefox_select_account(account);
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(g_app.firefox_job != 0);
        if (ImGui::SmallButton("Remove")) {
            s_firefox_removing_account_id = account.id;
            g_app.firefox_remove_in_flight = true;
            firefox_submit("{\"op\":\"remove\",\"data_dir\":\"" + root
                + "\",\"account_id\":\"" + firefox_json_escape(account.id.c_str()) + "\"}",
                "Removing Firefox account…");
        }
        ImGui::EndDisabled();
        ImGui::Separator();
        ImGui::PopID();
    }
    if (g_app.firefox_pending_id[0] && ImGui::Button("Continue verification")) {
        s_firefox_code_popup_open = true;
    }
    if (s_firefox_unblock_required && ImGui::Button("Continue sign-in with emailed code")) {
        s_firefox_code_popup_open = true;
    }
    ImGui::BeginDisabled(g_app.firefox_job != 0 || g_app.firefox_pending_id[0] || s_firefox_unblock_required);
    if (ImGui::Button("Add new account")) {
        firefox_clear_login_form();
        s_firefox_add_popup_open = true;
        s_firefox_add_should_close = false;
    }
    ImGui::EndDisabled();
    ImGui::Spacing();
}

static void firefox_location_combo() {
    std::vector<FirefoxLocationOption> options = s_firefox_location_options;
    const std::string saved = g_app.firefox_location;
    auto normalize = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        return value;
    };
    const std::string normalized = normalize(saved);
    auto selected = std::find_if(options.begin(), options.end(), [&](const FirefoxLocationOption& option) {
        return normalize(option.value) == normalized;
    });
    if (normalized == "rec" || normalized == "recommended") {
        selected = options.begin();
    } else if (selected == options.end() && !saved.empty()) {
        selected = std::find_if(options.begin(), options.end(), [&](const FirefoxLocationOption& option) {
            return !option.alias.empty() && normalize(option.alias) == normalized;
        });
    }
    int selected_index = selected == options.end() ? 0 : (int)std::distance(options.begin(), selected);
    if (!saved.empty() && selected == options.end()) {
        options.push_back({saved, saved + " (saved location)", ""});
        selected_index = (int)options.size() - 1;
    }
    std::vector<const char*> labels;
    labels.reserve(options.size());
    for (const auto& option : options) labels.push_back(option.label.c_str());
    if (ImGui::Combo("Region", &selected_index, labels.data(), (int)labels.size())) {
        snprintf(g_app.firefox_location, sizeof(g_app.firefox_location), "%s",
                 options[(size_t)selected_index].value.c_str());
    }
}

static uint64_t firefox_account_submit(const std::string& request) {
    static const char* const transports[] = {"auto", "h2", "h1"};
    const int selected = g_app.firefox_transport;
    const char* transport = transports[(selected >= 0 && selected <= 2) ? selected : 0];
    const size_t end = request.rfind('}');
    if (end == std::string::npos) return 0;
    std::string with_transport = request;
    with_transport.insert(end, std::string(",\"transport\":\"") + transport + "\"");
    return fcae_firefox_account_submit(with_transport.c_str());
}

static void firefox_submit(const std::string& request, const char* pending) {
    if (g_app.firefox_job != 0) return;
    g_app.firefox_job = firefox_account_submit(request);
    if (g_app.firefox_job) {
        const std::string operation = firefox_json_string(request, "op");
        snprintf(g_app.firefox_operation, sizeof(g_app.firefox_operation), "%s", operation.c_str());
    } else {
        g_app.firefox_operation[0] = 0;
        g_app.firefox_remove_in_flight = false;
    }
    set_firefox_status("%s",
             g_app.firefox_job ? pending : "Could not submit the Firefox account operation");
}

static void firefox_expire_status(double now) {
    static std::string observed;
    static uint64_t observed_revision = 0;
    static double deadline = 0.0;
    if (observed_revision != s_firefox_status_revision || observed != g_app.firefox_status) {
        observed_revision = s_firefox_status_revision;
        observed = g_app.firefox_status;
        deadline = 0.0;
    }
    if (observed.empty() || g_app.firefox_job) {
        deadline = 0.0;
        return;
    }
    if (deadline == 0.0) deadline = now + 3.0;
    if (now >= deadline) {
        g_app.firefox_status[0] = 0;
        observed.clear();
        deadline = 0.0;
    }
}

static bool firefox_background_snapshot(uint64_t id, std::string& json);

static void firefox_poll_job() {
    if (!g_app.firefox_job) return;
    const uint64_t job = g_app.firefox_job;
    std::string json;
    if (!firefox_background_snapshot(job, json)) {
        fcae_firefox_job_release(job);
        g_app.firefox_job = 0;
        set_firefox_status("Firefox account job is missing, invalid, or too large");
        return;
    }
    const std::string status = firefox_json_string(json, "status");
    if (status == "running") return;
    fcae_firefox_job_release(job);
    g_app.firefox_job = 0;
    if (status != "complete" && status != "error") {
        set_firefox_status("Firefox account job returned an invalid snapshot");
        return;
    }
    if (status == "error") {
        g_app.firefox_remove_in_flight = false;
        s_firefox_removing_account_id.clear();
        const std::string message = firefox_json_string(json, "message");
        set_firefox_status("%s",
                 message.empty() ? "Firefox account operation failed" : message.c_str());
        if (strcmp(g_app.firefox_operation, "login") == 0) {
            const bool reopen_add = s_firefox_unblock_required;
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
            s_firefox_unblock_required = false;
            s_firefox_email_link = false;
            if (reopen_add) {
                s_firefox_code_should_close = true;
                s_firefox_add_popup_open = true;
                s_firefox_add_should_close = false;
            }
        }
        return;
    }
    if (strcmp(g_app.firefox_operation, "locations") == 0) {
        std::vector<FirefoxLocationOption> options = firefox_parse_locations(json);
        if (!options.empty()) {
            std::vector<FirefoxLocationOption> unique;
            unique.reserve(options.size() + 1);
            unique.push_back({"", "Auto", ""});
            for (auto& option : options) {
                const bool duplicate = std::any_of(unique.begin(), unique.end(), [&](const FirefoxLocationOption& existing) {
                    return existing.value == option.value;
                });
                if (!duplicate) unique.push_back(std::move(option));
            }
            options = std::move(unique);
            s_firefox_location_options = std::move(options);
            s_firefox_has_locations = true;
            set_firefox_status("Mozilla region list updated");
        } else {
            set_firefox_status(
                     "No Mozilla regions are available; the saved location is preserved");
        }
        return;
    }
    if (strcmp(g_app.firefox_operation, "list") == 0) {
        s_firefox_account_options = firefox_parse_accounts(json);
        s_firefox_accounts_loaded = true;
        const auto selected = std::find_if(s_firefox_account_options.begin(), s_firefox_account_options.end(),
            [&](const FirefoxAccountOption& account) { return account.id == g_app.firefox_account_id; });
        if (selected == s_firefox_account_options.end()) {
            if (g_app.firefox_account_id[0]) {
                g_app.firefox_account_id[0] = 0;
                save_config();
            }
        } else {
            snprintf(g_app.firefox_email, sizeof(g_app.firefox_email), "%s", selected->email.c_str());
        }
        for (const auto& account : s_firefox_account_options) firefox_queue_usage(account.id);
        set_firefox_status("%s",
                 s_firefox_account_options.empty() ? "No saved Firefox accounts" : "Saved Firefox accounts loaded");
        return;
    }
    const std::string state = firefox_json_string(json, "state");
    if (state == "email_code" || state == "email_link" || state == "totp") {
        const std::string pending = firefox_json_string(json, "pending_id");
        snprintf(g_app.firefox_pending_id, sizeof(g_app.firefox_pending_id), "%s", pending.c_str());
        g_app.firefox_totp = state == "totp";
        g_app.firefox_password[0] = 0;
        g_app.firefox_code[0] = 0;
        s_firefox_unblock_required = false;
        s_firefox_email_link = state == "email_link";
        s_firefox_add_should_close = true;
        s_firefox_code_popup_open = true;
        s_firefox_code_should_close = false;
        set_firefox_status("%s",
                 g_app.firefox_totp ? "Enter the authenticator code"
                    : s_firefox_email_link ? "Open Mozilla's emailed confirmation link, then continue"
                    : "Enter the code sent to your email");
        return;
    }
    if (state == "unblock_code") {
        const std::string email = firefox_json_string(json, "email");
        if (!email.empty()) snprintf(g_app.firefox_email, sizeof(g_app.firefox_email), "%s", email.c_str());
        g_app.firefox_pending_id[0] = 0;
        g_app.firefox_totp = false;
        g_app.firefox_code[0] = 0;
        s_firefox_unblock_required = true;
        s_firefox_email_link = false;
        s_firefox_add_should_close = true;
        s_firefox_code_popup_open = true;
        s_firefox_code_should_close = false;
        set_firefox_status("%s",
                 json.find("\"sent\":true") != std::string::npos
                    ? "Mozilla emailed an unblock code. Enter it to continue sign-in."
                    : "That unblock code was not accepted. Check the latest email from Mozilla.");
        return;
    }
    if (state == "complete") {
        const size_t account = json.find("\"account\"");
        const std::string id = account == std::string::npos ? std::string() : firefox_json_string(json, "id", account);
        const std::string email = account == std::string::npos ? std::string() : firefox_json_string(json, "email", account);
        const std::string monthly_usage = account == std::string::npos ? std::string() : firefox_json_string(json, "monthly_usage", account);
        const bool usage_exhausted = account != std::string::npos && firefox_json_bool(json, "monthly_usage_exhausted", account);
        if (!id.empty()) {
            snprintf(g_app.firefox_account_id, sizeof(g_app.firefox_account_id), "%s", id.c_str());
            snprintf(g_app.firefox_email, sizeof(g_app.firefox_email), "%s", email.c_str());
            const auto existing = std::find_if(s_firefox_account_options.begin(), s_firefox_account_options.end(),
                [&](const FirefoxAccountOption& option) { return option.id == id; });
            if (existing == s_firefox_account_options.end()) {
                s_firefox_account_options.push_back({id, email, monthly_usage, usage_exhausted});
            } else {
                existing->email = email;
                existing->monthly_usage = monthly_usage;
                existing->usage_exhausted = usage_exhausted;
            }
            save_config();
            firefox_queue_usage(id);
        }
        g_app.firefox_password[0] = 0;
        g_app.firefox_code[0] = 0;
        g_app.firefox_pending_id[0] = 0;
        g_app.firefox_totp = false;
        s_firefox_unblock_required = false;
        s_firefox_email_link = false;
        s_firefox_add_should_close = true;
        s_firefox_code_should_close = true;
        set_firefox_status("Firefox account signed in and selected for connections");
        return;
    }
    if (g_app.firefox_remove_in_flight) {
        g_app.firefox_remove_in_flight = false;
        s_firefox_account_options.erase(std::remove_if(s_firefox_account_options.begin(), s_firefox_account_options.end(),
            [&](const FirefoxAccountOption& account) { return account.id == s_firefox_removing_account_id; }),
            s_firefox_account_options.end());
        if (s_firefox_removing_account_id == g_app.firefox_account_id) {
            g_app.firefox_account_id[0] = 0;
        }
        s_firefox_removing_account_id.clear();
        save_config();
    } else if (strcmp(g_app.firefox_operation, "cancel") == 0) {
        g_app.firefox_pending_id[0] = 0;
        g_app.firefox_totp = false;
        s_firefox_unblock_required = false;
        s_firefox_email_link = false;
        s_firefox_code_should_close = true;
    } else if (strcmp(g_app.firefox_operation, "reset") == 0) {
        g_app.firefox_password[0] = 0;
        g_app.firefox_code[0] = 0;
        g_app.firefox_pending_id[0] = 0;
        s_firefox_email_link = false;
        if (json.find("\"account_removed\":true") != std::string::npos) {
            g_app.firefox_account_id[0] = 0;
            s_firefox_account_options.erase(std::remove_if(s_firefox_account_options.begin(), s_firefox_account_options.end(),
                [&](const FirefoxAccountOption& account) { return account.email == g_app.firefox_email; }),
                s_firefox_account_options.end());
            save_config();
        }
    }
    set_firefox_status("%s",
             strcmp(g_app.firefox_operation, "cancel") == 0 ? "Sign-in verification cancelled" : "Firefox account operation completed");
}

static uint64_t s_firefox_region_job = 0;
static bool s_firefox_region_cached = false;
static uint64_t s_firefox_usage_job = 0;
static std::string s_firefox_usage_account;
static std::vector<std::string> s_firefox_usage_queue;

static void firefox_start_regions(bool cached) {
    if (s_firefox_region_job) return;
    const std::string request = "{\"op\":\"" + std::string(cached ? "locations_cached" : "locations")
        + "\",\"refresh\":true,\"data_dir\":\"" + firefox_json_escape(data_dir().c_str()) + "\"}";
    s_firefox_region_job = firefox_account_submit(request);
    s_firefox_region_cached = cached;
}

static void firefox_start_next_usage() {
    if (s_firefox_usage_job) return;
    while (!s_firefox_usage_queue.empty()) {
        std::string id = s_firefox_usage_queue.front();
        s_firefox_usage_queue.erase(s_firefox_usage_queue.begin());
        const auto account = std::find_if(s_firefox_account_options.begin(), s_firefox_account_options.end(),
            [&](const FirefoxAccountOption& item) { return item.id == id; });
        if (account == s_firefox_account_options.end()) continue;
        const std::string request = "{\"op\":\"usage\",\"data_dir\":\"" + firefox_json_escape(data_dir().c_str())
            + "\",\"account_id\":\"" + firefox_json_escape(id.c_str()) + "\"}";
        s_firefox_usage_job = firefox_account_submit(request);
        if (s_firefox_usage_job) { s_firefox_usage_account = std::move(id); break; }
    }
}

static void firefox_queue_usage(const std::string& id) {
    if (id.empty() || id == s_firefox_usage_account || std::find(s_firefox_usage_queue.begin(), s_firefox_usage_queue.end(), id) != s_firefox_usage_queue.end()) return;
    s_firefox_usage_queue.push_back(id);
    firefox_start_next_usage();
}

static void firefox_refresh_usage(double now) {
    if (!s_firefox_settings_visible || !s_ui_window_visible.load() || now < s_firefox_usage_refresh_at) return;
    s_firefox_usage_refresh_at = now + 60.0;
    for (const auto& account : s_firefox_account_options) firefox_queue_usage(account.id);
}

static bool firefox_background_snapshot(uint64_t id, std::string& json) {
    char small[512] = {};
    uint32_t needed = fcae_firefox_job_poll(id, small, sizeof(small));
    if (needed && needed < sizeof(small)) { json.assign(small, needed); return true; }
    for (int attempt = 0; attempt < 4 && needed && needed <= 1024 * 1024; ++attempt) {
        json.assign(needed + 1, '\0');
        const uint32_t written = fcae_firefox_job_poll(id, json.data(), (uint32_t)json.size());
        if (!written || written > 1024 * 1024) break;
        if (written <= needed) { json.resize(written); return true; }
        needed = written;
    }
    json.clear();
    return false;
}

static void firefox_poll_background() {
    if (s_firefox_region_job) {
        std::string json;
        const bool valid = firefox_background_snapshot(s_firefox_region_job, json);
        const std::string status = valid ? firefox_json_string(json, "status") : "error";
        if (status != "running") {
            fcae_firefox_job_release(s_firefox_region_job);
            s_firefox_region_job = 0;
            if (status == "complete") {
                auto options = firefox_parse_locations(json);
                if (!options.empty()) {
                    std::vector<FirefoxLocationOption> unique = {{"", "Auto", ""}};
                    for (auto& option : options) {
                        if (std::none_of(unique.begin(), unique.end(), [&](const FirefoxLocationOption& x) { return x.value == option.value; })) unique.push_back(std::move(option));
                    }
                    s_firefox_location_options = std::move(unique);
                    s_firefox_has_locations = true;
                }
            }
            if (s_firefox_region_cached) firefox_start_regions(false);
            else if (status != "complete") {
                std::string reason = firefox_json_string(json, "message");
                if (reason.empty()) reason = "Could not read the region refresh result";
                const std::string log = "[firefox] Mozilla regions refresh failed: " + reason;
                g_app.add_log(FCAE_LOG_WARN, log.c_str());
                if (!g_app.firefox_job) {
                    set_firefox_status("%s: %s",
                        s_firefox_has_locations ? "Region refresh failed; using previous regions" : "Region refresh failed",
                        reason.c_str());
                }
            }
            g_app.redraw_requested.store(true);
        }
    }
    if (s_firefox_usage_job) {
        std::string json;
        const bool valid = firefox_background_snapshot(s_firefox_usage_job, json);
        const std::string status = valid ? firefox_json_string(json, "status") : "error";
        if (status != "running") {
            fcae_firefox_job_release(s_firefox_usage_job);
            s_firefox_usage_job = 0;
            const size_t account_pos = json.find("\"account\"");
            const std::string usage = status == "complete" && account_pos != std::string::npos
                ? firefox_json_string(json, "monthly_usage", account_pos) : std::string();
            for (auto& account : s_firefox_account_options) {
                if (account.id == s_firefox_usage_account) {
                    if (!usage.empty()) {
                        account.monthly_usage = usage;
                        account.usage_exhausted = firefox_json_bool(json, "monthly_usage_exhausted", account_pos);
                    } else {
                        account.monthly_usage = "Usage unavailable";
                        account.usage_exhausted = false;
                    }
                    break;
                }
            }
            s_firefox_usage_account.clear();
            firefox_start_next_usage();
            g_app.redraw_requested.store(true);
        }
    }
}

static std::vector<uint8_t> s_firefox_captcha_rgba;
static uint32_t s_firefox_captcha_width = 0;
static uint32_t s_firefox_captcha_height = 0;
static bool s_firefox_captcha_embedded = false;

static void firefox_poll_captcha() {
    const uint64_t id = fcae_firefox_captcha_pending();
    if (id == g_app.firefox_captcha_id) return;
    g_app.firefox_captcha_id = id;
    g_app.firefox_captcha_answer[0] = 0;
    s_firefox_captcha_rgba.clear();
    s_firefox_captcha_width = s_firefox_captcha_height = 0;
    if (id) {
        uint32_t width = 0, height = 0;
        const uint32_t size = fcae_firefox_captcha_rgba(id, nullptr, 0, &width, &height);
        if (size && size <= 16 * 1024 * 1024 && width && height &&
            (uint64_t)width * height * 4 == size) {
            s_firefox_captcha_rgba.resize(size);
            uint32_t actual_width = 0, actual_height = 0;
            if (fcae_firefox_captcha_rgba(id, s_firefox_captcha_rgba.data(), size,
                    &actual_width, &actual_height) == size && width == actual_width && height == actual_height) {
                s_firefox_captcha_width = width;
                s_firefox_captcha_height = height;
            } else {
                s_firefox_captcha_rgba.clear();
            }
        }
        set_firefox_status(s_firefox_captcha_rgba.empty()
            ? "The Firefox CAPTCHA image could not be decoded."
            : "Enter the CAPTCHA shown in the app to continue.");
    }
    g_app.redraw_requested.store(true);
}

static void render_firefox_captcha_content() {
    if (!g_app.firefox_captcha_id) return;
    ImGui::TextColored(ImVec4(1.0f, 0.72f, 0.3f, 1.0f), "Firefox account CAPTCHA");
    if (!s_firefox_captcha_rgba.empty()) {
        const ImTextureID texture = sponsor_texture_update(s_firefox_captcha_rgba.data(),
            (int)s_firefox_captcha_width, (int)s_firefox_captcha_height, g_app.firefox_captcha_id, 2);
        if (texture) {
            const float scale = std::min(1.0f, std::min(
                std::max(1.0f, ImGui::GetContentRegionAvail().x) / s_firefox_captcha_width,
                220.0f / s_firefox_captcha_height));
            ImGui::Image(texture, ImVec2(s_firefox_captcha_width * scale, s_firefox_captcha_height * scale));
        } else {
            ImGui::TextWrapped("Could not display the CAPTCHA image.");
        }
    } else {
        ImGui::TextWrapped("The CAPTCHA image is unavailable or uses an unsupported format.");
    }
    ImGui::InputText("CAPTCHA answer", g_app.firefox_captcha_answer, sizeof(g_app.firefox_captcha_answer));
    if (ImGui::Button("Submit CAPTCHA answer")) {
        if (fcae_firefox_captcha_answer(g_app.firefox_captcha_id, g_app.firefox_captcha_answer)) {
            g_app.firefox_captcha_answer[0] = 0;
            set_firefox_status("CAPTCHA answer submitted; continuing Firefox account sign-in");
        } else {
            set_firefox_status("CAPTCHA answer is empty, expired, or already submitted");
        }
    }
    ImGui::Spacing();
}

/// Width for a dialog, from the widest line it must show *unbroken*.
///
/// Pass the structural lines -- endpoint readouts, labels, group headers -- not
/// sentences. Prose is meant to wrap and TextWrapped() does it; sizing a dialog
/// to its longest sentence makes a 900 px window for one paragraph. The result
/// is capped so a dialog never takes over the screen.
///
/// These dialogs used to be given fixed widths (480, 520, 500, 560, 440) when
/// the font was 13 px. At the current base size the connection dialog's longest
/// listener line is ~617 px, so a 480 px window wrapped it at a point nobody
/// chose -- which is the "spacing is not automatic" report.
static ImVec2 dialog_width_for(const char* const* widest_lines, int count, float min_w) {
    float content_w = min_w;
    for (int i = 0; i < count; ++i) {
        if (!widest_lines[i]) continue;
        const float w = ImGui::CalcTextSize(widest_lines[i]).x;
        if (w > content_w) content_w = w;
    }
    // Both horizontal paddings, plus a scrollbar's worth so a long line does not
    // sit flush against the bar when one appears.
    content_w += ImGui::GetStyle().WindowPadding.x * 2.0f
               + ImGui::GetStyle().ScrollbarSize
               + 8.0f;
    // Never wider than 70% of the screen, and never wider than the work area
    // less a margin: beyond that a dialog stops reading as a dialog.
    const ImVec2 work = ImGui::GetMainViewport()->WorkSize;
    const float cap = (std::min)(work.x * 0.70f, work.x - 48.0f);
    if (content_w > cap) content_w = cap;
    if (content_w < min_w) content_w = min_w;
    return ImVec2(content_w, 0.0f);
}

static void constrain_modal();

static void render_firefox_captcha_popup() {
    const char* name = "Firefox account CAPTCHA";
    const bool open = ImGui::IsPopupOpen(name);
    if (g_app.firefox_captcha_id && !s_firefox_captcha_embedded && !open &&
        !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
        ImGui::OpenPopup(name);
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    // This dialog is prose: its body is TextWrapped(), so it is meant to wrap.
    // The width only has to be a readable measure, not the length of the
    // longest sentence -- sizing to prose here produced a 885 px window.
    ImGui::SetNextWindowSize(ImVec2(480, 0), ImGuiCond_Appearing);
    constrain_modal();
    if (!ImGui::BeginPopupModal(name, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
    if (!g_app.firefox_captcha_id) {
        ImGui::CloseCurrentPopup();
    } else {
        render_firefox_captcha_content();
    }
    ImGui::EndPopup();
}

static const char* const kTransportNames[kCoreTransportBase] = {
    "MASQUE (HTTP/3)",
    "MASQUE (HTTP/2)",
    "WireGuard",
    "WARP-in-WARP (Gool)",
    "Tor",
    "Psiphon",
    "MASQUE-in-MASQUE (HTTP/3)",
    "MASQUE-in-MASQUE (HTTP/2)",
    "WARP-in-MASQUE (HTTP/3)",
    "WARP-in-MASQUE (HTTP/2)",
    "Firefox IP Protection",
};

/// The core a saved-config row is tagged with, lower case and unparenthesised:
/// it is a label, not a sentence. A built-in transport answers nullptr.
static const char* transport_tag(int transport) {
    const AppState::CoreConfigEntry* entry = g_app.core_config_at(transport);
    if (!entry) return nullptr;
    return entry->backend == 1 ? "sing-box" : "xray";
}

/// The colour the tag is drawn in: distinct from the row's white name, and the
/// same for both cores so the list stays quiet.
static const ImVec4 kCoreTagColor(0.55f, 0.72f, 0.98f, 1.0f);
/// Space between a saved config's name and its tag.
static constexpr float kCoreTagGap = 8.0f;

/// The protocol list as the user sees it: the built-in transports followed by
/// one entry per saved core config, named after it.
///
/// The name is the whole row. Which core runs a saved config is what the
/// settings dialog that manages them says, where the choice between Xray and
/// sing-box is being made; a protocol chooser offers a route, and a row that
/// carried its core there would read as a different protocol per entry.
struct TransportLabels {
    std::vector<std::string> names;
    std::vector<const char*> pointers;
};

static void transport_labels(TransportLabels& labels) {
    const size_t count = (size_t)kCoreTransportBase + g_app.core_configs.size();
    labels.names.clear();
    labels.names.reserve(count);
    for (const char* name : kTransportNames) {
        labels.names.emplace_back(name);
    }
    for (size_t i = 0; i < g_app.core_configs.size(); ++i) {
        const std::string& name = g_app.core_configs[i].name;
        labels.names.push_back(name.empty() ? "Saved config " + std::to_string(i + 1) : name);
    }
    labels.pointers.clear();
    labels.pointers.reserve(labels.names.size());
    for (const std::string& name : labels.names) labels.pointers.push_back(name.c_str());
}

static int transport_count() {
    return kCoreTransportBase + (int)g_app.core_configs.size();
}

static bool transport_is_core(int transport) {
    return transport >= kCoreTransportBase;
}

static int current_transport() {
    // A saved config is the main protocol exactly when core_selected names one.
    if (g_app.backend >= 3) {
        if (g_app.core_selected >= 0 && g_app.core_selected < (int)g_app.core_configs.size())
            return kCoreTransportBase + g_app.core_selected;
        return 0;
    }
    if (g_app.backend == 2) return 10;
    if (g_app.backend == 1) return 5;
    if (g_app.protocol == 6) return g_app.h2_enabled ? 9 : 8;
    if (g_app.protocol == 5) return g_app.h2_enabled ? 7 : 6;
    if (g_app.protocol == 4) return 4;
    if (g_app.protocol == 0) return g_app.h2_enabled ? 1 : 0;
    return g_app.protocol == 1 ? 2 : 3;
}

/// The FcaeBackend an app-level id ends at. Saved configs answer with their own
/// core, which is why they chain like a built-in hop.
static int transport_carrier(int transport) {
    if (const AppState::CoreConfigEntry* entry = g_app.core_config_at(transport))
        return entry->backend == 1 ? 4 : 3;
    if (transport == 5) return 1;
    if (transport == 10) return 2;
    return 0;
}

static void apply_transport(int transport) {
    if (transport_is_core(transport)) {
        const int index = transport - kCoreTransportBase;
        if (index >= 0 && index < (int)g_app.core_configs.size()) {
            g_app.core_selected = index;
            g_app.backend = g_app.core_configs[(size_t)index].backend == 1 ? 4 : 3;
            // A saved config has no transport of its own: the profile carries it.
            g_app.protocol = 3;
            return;
        }
        transport = 0;
    }
    g_app.core_selected = -1;
    g_app.backend = transport_carrier(transport);
    switch (transport) {
        case 0: g_app.protocol = 0; g_app.h2_enabled = false; break;
        case 1: g_app.protocol = 0; g_app.h2_enabled = true; break;
        case 2: g_app.protocol = 1; break;
        case 3: g_app.protocol = 2; break;
        case 4: g_app.protocol = 4; break;
        case 5: case 10: g_app.protocol = 3; break;
        case 6: g_app.protocol = 5; g_app.h2_enabled = false; break;
        case 7: g_app.protocol = 5; g_app.h2_enabled = true; break;
        case 8: g_app.protocol = 6; g_app.h2_enabled = false; break;
        case 9: g_app.protocol = 6; g_app.h2_enabled = true; break;
        default: g_app.protocol = 2; g_app.backend = 0; break;
    }
}

static ImVec2 modal_size(float width, float height) {
    const ImVec2 work = ImGui::GetMainViewport()->WorkSize;
    return ImVec2(std::max(1.0f, std::min(width, work.x - 24.0f)),
                  std::max(1.0f, std::min(height, work.y - 24.0f)));
}

static void constrain_modal() {
    ImGui::SetNextWindowSizeConstraints(ImVec2(1, 1), modal_size(10000.0f, 10000.0f));
}

static void open_protocol_editor() {
    s_protocol_draft = current_transport();
    s_chain_draft = g_app.chain_transports;
    s_chain_editor_popup_open = true;
}

// ---- Saved Xray / sing-box configs ----------------------------------------
//
// The editor writes AppState::core_configs. The engine only ever sees the
// resulting library document (FcaeCore::library), and a protocol-list position
// >= kCoreTransportBase names an entry by position, so a saved config is
// pickable as the main protocol and as a chain hop with no extra plumbing.

static bool s_core_configs_popup_open = false;
/// The saved-config editor, a modal of its own. Adding and editing are the same
/// act — a name, a core and a config — so they are the same dialog:
/// `s_core_editor_row` is the row it rewrites, or -1 while a new one is added.
static bool s_core_editor_open = false;
static int s_core_editor_row = -1;
/// Set when the editor was opened, so the first frame it draws validates what
/// it was filled with instead of waiting for the first keystroke.
static bool s_core_editor_fresh = false;
static char s_core_name_buf[64] = {};
static int s_core_backend_buf = 0;
static std::vector<char> s_core_text_buf;
static char s_core_status[256] = {};
static bool s_core_status_error = false;

static void open_core_configs() {
    s_core_configs_popup_open = true;
    s_core_editor_open = false;
    s_core_editor_row = -1;
    s_core_status[0] = 0;
}

/// Open the editor on `row`, or on a config that does not exist yet (`-1`).
static void open_core_editor(int row) {
    const AppState::CoreConfigEntry* entry =
        (row >= 0 && row < (int)g_app.core_configs.size())
            ? &g_app.core_configs[(size_t)row] : nullptr;
    s_core_editor_row = entry ? row : -1;
    snprintf(s_core_name_buf, sizeof(s_core_name_buf), "%s", entry ? entry->name.c_str() : "");
    s_core_backend_buf = entry && entry->backend == 1 ? 1 : 0;
    // One spare byte for the terminator past the largest accepted config.
    if (s_core_text_buf.size() < kMaxCoreConfigText + 1)
        s_core_text_buf.assign(kMaxCoreConfigText + 1, '\0');
    snprintf(s_core_text_buf.data(), s_core_text_buf.size(), "%s", entry ? entry->text.c_str() : "");
    s_core_status[0] = 0;
    s_core_status_error = false;
    s_core_editor_fresh = true;
    s_core_editor_open = true;
}

/// Keep every reference into `core_configs` pointing at the same config after
/// one was removed. A chain exit whose config is gone is dropped rather than
/// silently re-pointed at a different one.
static void core_configs_forget(int removed) {
    if (g_app.core_selected == removed) {
        // The config the session ran is gone, so the whole choice goes with it:
        // leaving `protocol` at Auto with nothing behind it is a state neither
        // the settings panel nor the engine can read, and it would keep the
        // profile the user had picked before this config ever existed.
        apply_transport(0);
    } else if (g_app.core_selected > removed) {
        g_app.core_selected--;
    }
    std::vector<int> rebuilt;
    rebuilt.reserve(g_app.chain_transports.size());
    for (int transport : g_app.chain_transports) {
        if (!transport_is_core(transport)) {
            rebuilt.push_back(transport);
            continue;
        }
        const int index = transport - kCoreTransportBase;
        if (index == removed) continue;
        rebuilt.push_back(kCoreTransportBase + (index > removed ? index - 1 : index));
    }
    g_app.chain_transports.swap(rebuilt);
    // The editor follows the rows it can name, so opening it on a row that moved
    // still rewrites the config the user pointed at.
    if (s_core_editor_row == removed) {
        s_core_editor_row = -1;
        s_core_editor_open = false;
    } else if (s_core_editor_row > removed) {
        s_core_editor_row--;
    }
}

/// Whether `name` is free for row `row` (-1 = a row that does not exist yet).
/// A name identifies a config in the library the engine parses, so a duplicate
/// makes that document ambiguous and gets the later entry dropped.
static bool core_config_name_free(const char* name, int row) {
    const size_t length = strlen(name);
    if (length == 0 || length > kMaxCoreConfigName) return false;
    for (int i = 0; i < (int)g_app.core_configs.size(); ++i) {
        if (i == row) continue;
        const std::string& other = g_app.core_configs[(size_t)i].name;
        const bool same = other.size() == length
            && std::equal(other.begin(), other.end(), name, [](char a, char b) {
                   return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
               });
        if (same) return false;
    }
    return true;
}

/// Validate the editor's buffers against the rules the engine parses the
/// library with, so a config that saves is a config that runs: the name is a
/// reference in that document and must be unique, the profile has to parse for
/// the core it is stored under, and every field is bounded in bytes.
///
/// `row` is the entry being rewritten, or -1 for one that does not exist yet.
static void core_config_check(int row) {
    s_core_status_error = true;
    const std::string name = s_core_name_buf;
    const bool empty_text = s_core_text_buf.empty() || s_core_text_buf[0] == 0;
    if (name.empty() && empty_text) {
        // A form nobody has filled in yet is not a mistake to paint red: the
        // Save button stays disabled and the status stays silent.
        s_core_status[0] = 0;
        return;
    }
    if (name.empty()) {
        snprintf(s_core_status, sizeof(s_core_status), "Give the config a name.");
        return;
    }
    if (name.size() > kMaxCoreConfigName) {
        snprintf(s_core_status, sizeof(s_core_status), "Names are limited to %d bytes.",
                 (int)kMaxCoreConfigName);
        return;
    }
    if (std::any_of(name.begin(), name.end(),
                    [](char c) { return std::iscntrl((unsigned char)c) != 0; })) {
        snprintf(s_core_status, sizeof(s_core_status), "Names cannot contain control characters.");
        return;
    }
    if (!core_config_name_free(name.c_str(), row)) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Another config is already called \"%s\".", name.c_str());
        return;
    }
    if (empty_text) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Paste a share link or the core's own config JSON.");
        return;
    }
    const size_t length = strlen(s_core_text_buf.data());
    if (length > kMaxCoreConfigText) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Configs are limited to %d KiB.", (int)(kMaxCoreConfigText / 1024));
        return;
    }
    char reason[224] = {};
    const int32_t backend = s_core_backend_buf == 1 ? FCAE_BACKEND_SINGBOX : FCAE_BACKEND_XRAY;
    if (!fcae_core_check_profile(s_core_text_buf.data(), backend, reason, sizeof(reason))) {
        snprintf(s_core_status, sizeof(s_core_status), "%s", reason);
        return;
    }
    // Every session dialect dials its listener through SOCKS5 — TUN mode, a
    // chained hop, the Psiphon egress — but that is a fact about running the
    // config, not about it being one. An HTTP-only config is valid and stays
    // saved; the status says what it cannot do instead of failing the row.
    uint32_t socks_port = 0;
    uint32_t http_port = 0;
    const uint32_t kinds = fcae_core_listeners(s_core_text_buf.data(), backend, &socks_port, &http_port);
    const char* core = s_core_backend_buf == 1 ? "sing-box" : "Xray";
    if ((kinds & FCAE_CORE_LISTENER_SOCKS) == 0) {
        s_core_status_error = false;
        snprintf(s_core_status, sizeof(s_core_status),
                 "Valid %s config. It declares no SOCKS5 inbound, so TUN mode and a chained "
                 "hop cannot run it.", core);
        return;
    }
    s_core_status_error = false;
    snprintf(s_core_status, sizeof(s_core_status), "Valid %s config.", core);
}

/// Store the editor's buffers as the row it was opened on, or as a new one.
/// Only called with a validated form, so the entry it writes always parses.
static void apply_core_editor() {
    AppState::CoreConfigEntry entry;
    entry.name = s_core_name_buf;
    entry.backend = s_core_backend_buf == 1 ? 1 : 0;
    entry.text = s_core_text_buf.data();
    if (s_core_editor_row >= 0 && s_core_editor_row < (int)g_app.core_configs.size())
        g_app.core_configs[(size_t)s_core_editor_row] = std::move(entry);
    else
        g_app.core_configs.push_back(std::move(entry));
    // What a listener can answer on is a property of the config, so the cache
    // the settings and the protocol list read is rebuilt from what was stored.
    g_app.refresh_core_listeners();
}

/// `text` shortened with an ellipsis when it does not fit `width`, so the core
/// tag beside it keeps its place on the row.
static std::string fit_core_name(const std::string& text, float width) {
    if (ImGui::CalcTextSize(text.c_str()).x <= width) return text;
    static const char kEllipsis[] = "...";
    const float room = width - ImGui::CalcTextSize(kEllipsis).x;
    std::string out = text;
    while (!out.empty() && ImGui::CalcTextSize(out.c_str()).x > room) {
        size_t cut = out.size() - 1;
        // Never cut a UTF-8 sequence in half: its tail bytes are 10xxxxxx.
        while (cut > 0 && ((unsigned char)out[cut] & 0xC0) == 0x80) --cut;
        out.resize(cut);
    }
    out += kEllipsis;
    return out;
}

/// One core's listener: the same switches and ports Aether and Firefox have.
/// Every control stays live whatever the library holds — a switch that greys out
/// because no saved config declares that inbound is one the user cannot set
/// before saving the config that needs it, and what a listener actually answers
/// on is the engine's call at start time.
static void core_listener_block(int backend) {
    const char* label = backend == 1 ? "sing-box" : "Xray";
    bool& socks_enabled = backend == 1 ? g_app.singbox_socks_enabled : g_app.xray_socks_enabled;
    bool& http_enabled  = backend == 1 ? g_app.singbox_http_enabled : g_app.xray_http_enabled;
    uint16_t& socks_port = backend == 1 ? g_app.singbox_socks_port : g_app.xray_socks_port;
    uint16_t& http_port  = backend == 1 ? g_app.singbox_http_port : g_app.xray_http_port;

    // Both pairs stay live whatever the library holds. The switch is a stored
    // preference and the port is a stored value either way; what a listener can
    // answer on is decided at start time, by the config the session runs.
    ImGui::Spacing();
    ImGui::TextDisabled("%s listener", label);
    listener_row(backend == 1 ? "sing-box SOCKS5" : "Xray SOCKS5", &socks_enabled, &socks_port, 1, 65535);
    listener_row(backend == 1 ? "sing-box HTTP" : "Xray HTTP", &http_enabled, &http_port, 1, 65535);
}

/// The saved-config editor: the name the user gives a config, the core that runs
/// it and the config itself. It writes the row it was opened on, or a new one,
/// and nothing is stored before Save -- the same dialog for both acts, because
/// they are the same three fields.
static void render_core_editor() {
    static const char* const kTitle = "##core-config-editor";
    if (s_core_editor_open) {
        ImGui::OpenPopup(kTitle);
        s_core_editor_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(680.0f, 620.0f), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoResize)) return;

    ImGui::TextColored(ImVec4(0.38f, 0.65f, 0.98f, 1.0f),
                       s_core_editor_row < 0 ? "Add config" : "Edit config");
    ImGui::Separator();

    // This frame's edits have to be validated whether or not anything was typed:
    // an entry can be pre-filled (an edit) and a name can collide with a row the
    // user added meanwhile.
    bool changed = s_core_editor_fresh;
    s_core_editor_fresh = false;
    // A caption over its control, the way every other setting in the app is
    // laid out: a label and its field on one line collide as soon as one of them
    // grows, and the field gets the width the caption does not need. The Android
    // dialog does the same, so the two editors read alike.
    ImGui::TextDisabled("Name");
    ImGui::PushItemWidth(-FLT_MIN);
    // The engine's limit plus the terminator: typing past it does nothing.
    changed |= ImGui::InputTextWithHint("##core_name", "a name for this config",
                                        s_core_name_buf, kMaxCoreConfigName + 1);
    ImGui::PopItemWidth();
    // Two cores, so both stay on screen: radio circles like Outbound IP version,
    // not a dropdown that hides half the choice behind a click.
    ImGui::TextDisabled("Core");
    {
        // The circles take the colour the saved-configs list gives the same
        // core, so the row being saved already looks like the row it becomes.
        ImGui::PushStyleColor(ImGuiCol_CheckMark, kCoreTagColor);
        if (ImGui::RadioButton("xray", s_core_backend_buf == 0)) {
            s_core_backend_buf = 0;
            changed = true;
        }
        ImGui::SameLine();
        if (ImGui::RadioButton("sing-box", s_core_backend_buf == 1)) {
            s_core_backend_buf = 1;
            changed = true;
        }
        ImGui::PopStyleColor();
    }
    ImGui::Spacing();
    ImGui::TextDisabled("Config (a share link or the core's own JSON)");
    float text_height = ImGui::GetContentRegionAvail().y
        - ImGui::GetTextLineHeightWithSpacing() - ImGui::GetFrameHeightWithSpacing() - 8.0f;
    if (text_height < 160.0f) text_height = 160.0f;
    changed |= ImGui::InputTextMultiline("##core_text", s_core_text_buf.data(),
                                         s_core_text_buf.size(), ImVec2(-FLT_MIN, text_height));
    if (changed) core_config_check(s_core_editor_row);
    ImGui::TextColored(s_core_status_error ? ImVec4(0.95f, 0.38f, 0.38f, 1.0f)
                                           : ImVec4(0.3f, 0.9f, 0.4f, 1.0f),
                       "%s", s_core_status);
    ImGui::Spacing();
    // Save only commits a config that validated, so the library never holds one
    // the engine would refuse -- that rejection takes the whole session with it.
    ImGui::BeginDisabled(s_core_status_error);
    // Widths from the labels: 120 was comfortably wide for "Save" and
    // "Cancel" at 13 px, and measuring keeps that true at any size instead of
    // by luck.
    const float dlg_btn_w = (std::max)(ImGui::CalcTextSize("Save").x,
                                       ImGui::CalcTextSize("Cancel").x)
                          + ImGui::GetStyle().FramePadding.x * 2.0f + 24.0f;
    if (ImGui::Button("Save", ImVec2(dlg_btn_w, 0))) {
        apply_core_editor();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(dlg_btn_w, 0))) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

static void render_core_configs() {
    static const char* const kTitle = "Xray & sing-box settings";
    if (s_core_configs_popup_open) {
        ImGui::OpenPopup(kTitle);
        s_core_configs_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(760.0f, 720.0f), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoResize)) return;

    // The library first: one list of configs, because that is what both cores
    // run. A row is the name the user gave the config, the core that runs it and
    // the two things that can be done to it -- the same `name  core` row the
    // Android dialog shows. Buttons are the only items in a row that take input,
    // so nothing can swallow their clicks: a full-width Selectable claimed the
    // whole row, which is why Remove never fired.
    ImGui::TextColored(ImVec4(0.38f, 0.65f, 0.98f, 1.0f), "Saved configs");
    // The list takes whatever the listeners, the log level and Close leave.
    // The 340 px reserve was counted in the old font's rows; the footer it
    // leaves room for is now built from frames and text lines, so the reserve
    // is expressed the same way. Too small a reserve and the log-level row
    // below the list is pushed off the bottom of a NoResize window, where it
    // cannot be scrolled to.
    const float list_reserve = ImGui::GetFrameHeightWithSpacing() * 6.0f
                             + ImGui::GetTextLineHeightWithSpacing() * 2.0f
                             + ImGui::GetStyle().ItemSpacing.y * 4.0f
                             + 40.0f;
    const float list_height = (std::max)(146.0f, ImGui::GetContentRegionAvail().y - list_reserve);
    ImGui::BeginChild("##core_list", ImVec2(0, list_height), ImGuiChildFlags_Borders);
    int edit_row = -1;
    int remove_row = -1;
    // The same on every row, so it is measured once.
    const ImGuiStyle& style = ImGui::GetStyle();
    const float buttons_width = ImGui::CalcTextSize("Edit").x + ImGui::CalcTextSize("Remove").x
        + 4.0f * style.FramePadding.x + style.ItemSpacing.x;
    for (int i = 0; i < (int)g_app.core_configs.size(); ++i) {
        const AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)i];
        const char* tag = transport_tag(kCoreTransportBase + i);
        // Measured before the row draws anything: what the name may take is the
        // row less the buttons and the tag beside it, so the tag and the buttons
        // sit in the same place on every row and a long name cannot reach them.
        const float row_x = ImGui::GetCursorPosX();
        const float row_avail = ImGui::GetContentRegionAvail().x;
        const float tag_width = tag ? ImGui::CalcTextSize(tag).x + kCoreTagGap : 0.0f;
        const std::string label = entry.name.empty() ? "(unnamed)" : entry.name;
        const float name_width = std::max(0.0f, row_avail - buttons_width
            - 2.0f * style.ItemSpacing.x - tag_width);
        ImGui::PushID(i);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(fit_core_name(label, name_width).c_str());
        if (tag) {
            ImGui::SameLine(0.0f, kCoreTagGap);
            ImGui::TextColored(kCoreTagColor, "%s", tag);
        }
        ImGui::SameLine(row_x + row_avail - buttons_width);
        if (ImGui::SmallButton("Edit")) edit_row = i;
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove")) remove_row = i;
        ImGui::PopID();
    }
    if (g_app.core_configs.empty()) ImGui::TextDisabled("No saved configs.");
    ImGui::EndChild();

    // Nothing is stored until Save: a config the engine cannot parse is one
    // library that does not start, and a draft is not a config yet. The count
    // beside it is the list's place in the library the engine accepts, and
    // nothing gates on it: the limit is there to be read, not to be hit.
    if (ImGui::Button("+ Add config")) open_core_editor(-1);
    ImGui::SameLine();
    ImGui::TextDisabled("%d/%d", (int)g_app.core_configs.size(), kMaxCoreConfigs);
    ImGui::Separator();

    // After the loop, so it never reads a vector whose size changed under it.
    if (edit_row >= 0) open_core_editor(edit_row);
    if (remove_row >= 0) {
        g_app.core_configs.erase(g_app.core_configs.begin() + remove_row);
        // Re-points the protocol choice and the chain, and drops the editor's
        // own row number with the config it named.
        core_configs_forget(remove_row);
        g_app.refresh_core_listeners();
    }
    // The editor is a modal of its own, opened from the buttons above and drawn
    // inside this one so it stays scoped to the dialog that owns it.
    render_core_editor();
    core_listener_block(0);
    core_listener_block(1);
    ImGui::Spacing();
    ImGui::Separator();
    // The dropdown has to be wide enough for its own longest option, or the
    // arrow crowds the text at a larger font. 200 was sized for 13 px type;
    // this measures the options instead, with 200 kept as the floor.
    {
        static const char* const kCoreLogs[] = { "Silent", "Error", "Warn", "Info", "Debug", "Trace" };
        float log_combo_w = 200.0f;
        for (const char* level : kCoreLogs) {
            const float w = ImGui::CalcTextSize(level).x;
            if (w > log_combo_w) log_combo_w = w;
        }
        log_combo_w += ImGui::GetStyle().FramePadding.x * 2.0f
                     + ImGui::GetFrameHeight() * 0.9f;   // room for the arrow
        ImGui::PushItemWidth(log_combo_w);
        ImGui::Combo("Xray & sing-box log level", &g_app.core_log, kCoreLogs, 6);
        ImGui::PopItemWidth();
    }
    ImGui::Spacing();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

static void render_protocol_editor() {
    if (s_chain_editor_popup_open) {
        ImGui::OpenPopup("##protocol-editor");
        s_chain_editor_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(600.0f, 650.0f), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("##protocol-editor", nullptr, ImGuiWindowFlags_NoResize)) return;

    bool changed = false;
    const float footer_width = ImGui::CalcTextSize("+ Add exit").x + ImGui::CalcTextSize("Close").x
        + 4.0f * ImGui::GetStyle().FramePadding.x + ImGui::GetStyle().ItemSpacing.x;
    const bool compact_footer = ImGui::GetContentRegionAvail().x < footer_width;
    const float footer_height = ImGui::GetFrameHeightWithSpacing() * (compact_footer ? 2.0f : 1.0f) + 8.0f;
    ImGui::BeginChild("##protocol-scroll", ImVec2(0, -footer_height),
                      ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
    TransportLabels labels;
    transport_labels(labels);
    const char* const* names = labels.pointers.data();
    const int transport_choices = (int)labels.pointers.size();
    if (s_protocol_draft < 0 || s_protocol_draft >= transport_choices) s_protocol_draft = 0;
    const int protocol_before = s_protocol_draft;
    for (int i = 0; i < transport_choices; ++i) {
        // The position is the row's identity here: two saved configs may well
        // share a name, and a radio button's own id is its label.
        ImGui::PushID(i);
        changed |= ImGui::RadioButton(labels.names[(size_t)i].c_str(), &s_protocol_draft, i);
        ImGui::PopID();
    }
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::Text("Additional exits (optional)");
    int remove_index = -1;
    for (size_t i = 0; i < s_chain_draft.size(); ++i) {
        ImGui::PushID((int)i);
        ImGui::Text("Exit %d", (int)i + 1);
        const float remove_width = ImGui::CalcTextSize("Remove").x + 2.0f * ImGui::GetStyle().FramePadding.x;
        ImGui::SetNextItemWidth(std::max(1.0f, ImGui::GetContentRegionAvail().x - remove_width - ImGui::GetStyle().ItemSpacing.x));
        if (s_chain_draft[i] < 0 || s_chain_draft[i] >= transport_choices) s_chain_draft[i] = 0;
        changed |= ImGui::Combo("##transport", &s_chain_draft[i], names, transport_choices);
        ImGui::SameLine();
        if (ImGui::Button("Remove")) remove_index = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (remove_index >= 0) { s_chain_draft.erase(s_chain_draft.begin() + remove_index); changed = true; }
    if (ImGui::Button("+ Add exit")) { s_chain_draft.push_back(0); changed = true; }
    if (!compact_footer) ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
    if (changed) {
        apply_transport(s_protocol_draft);
        // A carrier of Tor or Psiphon has to carry something: picking one for an
        // otherwise empty route adds the WARP transport as its exit rather than
        // leaving a session that is only the hop. Any exit can be swapped or
        // removed afterwards, so this is a default and not a rule.
        if (s_protocol_draft != protocol_before
            && (s_protocol_draft == kTorTransport || s_protocol_draft == kPsiphonTransport)
            && s_chain_draft.empty()) {
            s_chain_draft.push_back(0);
        }
        g_app.chain_transports = s_chain_draft;
    }
    ImGui::EndPopup();
}

static char s_firefox_relay_url[4097] = {};
static bool s_firefox_relay_error = false;

static void open_firefox_settings() {
    s_firefox_relay_url[0] = 0;
    const uint32_t size = fcae_firefox_relay_get(data_dir().c_str(), s_firefox_relay_url, sizeof(s_firefox_relay_url));
    s_firefox_relay_error = size == UINT32_MAX || size >= sizeof(s_firefox_relay_url);
    if (s_firefox_relay_error) s_firefox_relay_url[0] = 0;
    s_firefox_settings_popup_open = true;
    s_firefox_usage_refresh_at = ui_now_seconds() + 60.0;
    firefox_start_regions(true);
    if (!g_app.firefox_job) {
        firefox_submit("{\"op\":\"list\",\"data_dir\":\"" + firefox_json_escape(data_dir().c_str()) + "\"}",
                       "Loading saved Firefox accounts…");
    }
}

static void render_firefox_settings() {
    if (s_firefox_settings_popup_open) {
        ImGui::OpenPopup("Firefox IP Protection settings");
        s_firefox_settings_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(680.0f, 620.0f), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Firefox IP Protection settings", nullptr, ImGuiWindowFlags_NoResize)) {
        s_firefox_settings_visible = false;
        return;
    }
    s_firefox_settings_visible = true;
    s_firefox_captcha_embedded = true;
    render_firefox_captcha_content();
    ImGui::BeginChild("##firefox_scroll",
        ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8.0f),
        ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
    const std::string root = firefox_json_escape(data_dir().c_str());
    firefox_location_combo();
    ImGui::Spacing();
    ImGui::InputTextWithHint("Firefox relay URL", "Optional HTTP or HTTPS URL", s_firefox_relay_url,
        sizeof(s_firefox_relay_url));
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        s_firefox_relay_error = !fcae_firefox_relay_set(data_dir().c_str(), s_firefox_relay_url);
    }
    if (s_firefox_relay_error)
        ImGui::TextWrapped("Could not save or load the relay URL. Use a valid HTTP or HTTPS URL; the previous setting may still be active.");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    firefox_account_rows(root);
    if (g_app.firefox_job) ImGui::TextDisabled("Account operation in progress…");
    if (g_app.firefox_status[0]) ImGui::TextWrapped("%s", g_app.firefox_status);
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    listener_row("Firefox SOCKS5", &g_app.firefox_socks_enabled, &g_app.firefox_socks_port, 1, 65535);
    listener_row("Firefox HTTP", &g_app.firefox_http_enabled, &g_app.firefox_http_port, 1, 65535);
    ImGui::InputTextWithHint("Server override", "Optional proxy host[:port]", g_app.firefox_server, sizeof(g_app.firefox_server));
    static const char* const firefox_transports[] = {"Auto (H2 with H1 fallback)", "HTTP/2", "HTTP/1.1"};
    ImGui::Combo("Firefox transport", &g_app.firefox_transport, firefox_transports, 3);
    ImGui::EndChild();
    if (ImGui::Button("Close")) {
        if (!g_app.firefox_job && !s_firefox_unblock_required) {
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
        }
        s_firefox_settings_visible = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

static void render_firefox_add_account() {
    if (s_firefox_add_popup_open) {
        ImGui::OpenPopup("Add Firefox account");
        s_firefox_add_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    // Prose dialog: wraps, so the width is a readable measure rather than the
    // length of its longest sentence.
    ImGui::SetNextWindowSize(ImVec2(520, 0), ImGuiCond_Appearing);
    constrain_modal();
    if (!ImGui::BeginPopupModal("Add Firefox account", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) return;
    if (s_firefox_add_should_close) {
        s_firefox_add_should_close = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    s_firefox_captcha_embedded = true;
    render_firefox_captcha_content();
    ImGui::InputText("Email", g_app.firefox_email, sizeof(g_app.firefox_email));
    ImGui::InputText("Password", g_app.firefox_password, sizeof(g_app.firefox_password), ImGuiInputTextFlags_Password);
    ImGui::BeginDisabled(g_app.firefox_job != 0 || !g_app.firefox_email[0] || !g_app.firefox_password[0]);
    if (ImGui::Button("Sign in")) {
        const std::string root = firefox_json_escape(data_dir().c_str());
        const std::string request = "{\"op\":\"login\",\"data_dir\":\"" + root
            + "\",\"email\":\"" + firefox_json_escape(g_app.firefox_email)
            + "\",\"password\":\"" + firefox_json_escape(g_app.firefox_password) + "\"}";
        g_app.firefox_pending_id[0] = 0;
        g_app.firefox_totp = false;
        s_firefox_unblock_required = false;
        firefox_submit(request, "Signing in to Firefox Accounts…");
    }
    ImGui::EndDisabled();
    if (g_app.firefox_job) ImGui::TextDisabled("Account operation in progress…");
    if (g_app.firefox_status[0]) ImGui::TextWrapped("%s", g_app.firefox_status);
    if (ImGui::Button("Close")) {
        if (!g_app.firefox_job && !s_firefox_unblock_required) {
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

static void render_firefox_code_prompt() {
    const bool verification = g_app.firefox_pending_id[0] != 0;
    if (!verification && !s_firefox_unblock_required && !s_firefox_code_should_close) return;
    if (s_firefox_code_popup_open) {
        ImGui::OpenPopup("Firefox account security code");
        s_firefox_code_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    // Prose dialog: see above.
    ImGui::SetNextWindowSize(ImVec2(500, 0), ImGuiCond_Appearing);
    constrain_modal();
    if (!ImGui::BeginPopupModal("Firefox account security code", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) return;
    if (s_firefox_code_should_close) {
        s_firefox_code_should_close = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    s_firefox_captcha_embedded = true;
    render_firefox_captcha_content();
    const std::string root = firefox_json_escape(data_dir().c_str());
    const bool email_link = verification && s_firefox_email_link;
    if (verification) {
        ImGui::TextWrapped("%s", g_app.firefox_totp
            ? "Enter the six-digit code from your authenticator app."
            : email_link ? "Mozilla sent a confirmation link to your email. Open that link, then continue here. No code is required."
            : "Mozilla sent a verification code to your email. Enter it to finish adding the account.");
    } else {
        ImGui::TextWrapped("Mozilla blocked this direct sign-in as unusual and sent an unblock code to %s.", g_app.firefox_email);
    }
    if (!email_link) {
        ImGui::InputText(verification ? "Verification code" : "Unblock code", g_app.firefox_code, sizeof(g_app.firefox_code));
    }
    if (g_app.firefox_status[0]) ImGui::TextWrapped("%s", g_app.firefox_status);
    ImGui::BeginDisabled(g_app.firefox_job != 0 || (!email_link && !g_app.firefox_code[0]));
    if (verification && ImGui::Button(email_link ? "Continue after opening link" : "Verify")) {
        const char* operation = g_app.firefox_totp ? "verify_totp" : email_link ? "confirm_email_link" : "verify_email";
        std::string request = std::string("{\"op\":\"") + operation + "\",\"data_dir\":\"" + root
            + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"";
        if (!email_link) request += ",\"code\":\"" + firefox_json_escape(g_app.firefox_code) + "\"";
        request += "}";
        firefox_submit(request, "Checking Firefox account verification…");
    }
    if (!verification && ImGui::Button("Sign in with code")) {
        if (!g_app.firefox_password[0]) {
            set_firefox_status("Restart direct sign-in to enter the password again");
            s_firefox_unblock_required = false;
            ImGui::CloseCurrentPopup();
        } else {
            firefox_submit("{\"op\":\"login\",\"data_dir\":\"" + root
                + "\",\"email\":\"" + firefox_json_escape(g_app.firefox_email)
                + "\",\"password\":\"" + firefox_json_escape(g_app.firefox_password)
                + "\",\"unblock_code\":\"" + firefox_json_escape(g_app.firefox_code) + "\"}",
                "Signing in with the emailed unblock code…");
        }
    }
    ImGui::EndDisabled();
    ImGui::BeginDisabled(g_app.firefox_job != 0);
    if (verification && !g_app.firefox_totp && !email_link) {
        ImGui::SameLine();
        if (ImGui::Button("Resend email")) {
            firefox_submit("{\"op\":\"resend\",\"data_dir\":\"" + root
                + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"}",
                "Resending verification code…");
        }
    }
    if (!verification) {
        ImGui::SameLine();
        if (ImGui::Button("Resend unblock code")) {
            firefox_submit("{\"op\":\"unblock\",\"data_dir\":\"" + root
                + "\",\"email\":\"" + firefox_json_escape(g_app.firefox_email) + "\"}",
                "Requesting another unblock code…");
        }
    }
    ImGui::EndDisabled();
    if (verification) {
        ImGui::BeginDisabled(g_app.firefox_job != 0);
        if (ImGui::Button("Cancel verification")) {
            firefox_submit("{\"op\":\"cancel\",\"data_dir\":\"" + root
                + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"}",
                "Cancelling sign-in verification…");
        }
        ImGui::EndDisabled();
    } else {
        ImGui::BeginDisabled(g_app.firefox_job != 0);
        if (ImGui::Button("Cancel sign-in")) {
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
            s_firefox_unblock_required = false;
            s_firefox_email_link = false;
            set_firefox_status("Direct sign-in cancelled");
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
    }
    ImGui::SameLine();
    if (ImGui::Button("Later")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void render_ui() {
    const ImGuiIO& io = ImGui::GetIO();
    const bool narrow = io.DisplaySize.x < 720.0f;

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(narrow ? 12.0f : 20.0f, narrow ? 10.0f : 16.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // Throttle telemetry FFI (~4 Hz while live, 1 Hz when idle) — the same
    // poll the render gate (ui_should_render) uses, so it never double-polls.
    const double now = ui_now_seconds();
    ui_poll_telemetry(now);
    const FcaeTelemetry& telem = g_app.telem;

    FcaeState cur = (FcaeState)telem.state;
    bool connected  = (cur == FCAE_STATE_CONNECTED || cur == FCAE_STATE_RECONNECTING);
    bool busy       = (cur == FCAE_STATE_PROVISIONING || cur == FCAE_STATE_SCANNING
                       || cur == FCAE_STATE_CONNECTING || cur == FCAE_STATE_RECONNECTING)
                      || g_app.start_busy.load();
    bool errored    = (cur == FCAE_STATE_ERROR);
    // Until the runtime reports Ready the window paints these fields as
    // defaults; the state label and the engine-dependent buttons say so
    // instead of pretending we're already connected (or usable).
    const bool startup = (s_runtime_init.load(std::memory_order_acquire) != RuntimeInitState::Ready);

    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 10));

        const float title_right_x = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
        ImVec4 sc = startup ? ImVec4(0.55f, 0.58f, 0.65f, 1.0f) : state_color(cur);
        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        ImGui::Text("FCAE VPN");
        ImGui::PopStyleColor();

        ImGui::SameLine(0, 10);
        ImGui::TextColored(build_is_prerelease() ? ImVec4(1.0f, 0.72f, 0.20f, 1.0f)
                                                : ImVec4(0.62f, 0.66f, 0.74f, 1.0f),
                           "%s  |  %s", fcae_display_version(),
                           build_is_prerelease() ? "pre-release" : "release");

        const float icon_size = icon_button_size();
        same_line_right_aligned(title_right_x, icon_size, 8.0f);
        // Centred on the text line either way: the offset goes negative when
        // the icon is the taller of the two, which is the case at this type size.
        ImGui::SetCursorPosY(ImGui::GetCursorPosY()
            + std::floor((ImGui::GetTextLineHeight() - icon_size) * 0.5f));
        if (round_icon_button("##about_btn", UiIcon::Info, false, "About FCAE VPN"))
            s_about_popup_open = true;

        {
            if (s_update_popup_open) {
                ImGui::OpenPopup("##update_popup");
                s_update_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            constrain_modal();
            if (ImGui::BeginPopupModal("##update_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGui::Text("Update Available");
                ImGui::Spacing();
                ImGui::Text("Current: %s  (%s)", fcae_display_version(),
                            build_is_prerelease() ? "pre-release" : "release");
                ImGui::Text("Latest:  %s", s_update_latest);
                if (s_update_date[0]) {
                    ImGui::Text("Date: %s", s_update_date);
                }
                ImGui::Spacing();
                if (s_update_notes[0]) {
                    ImGui::Text("Notes:");
                    ImGui::TextWrapped("%s", s_update_notes);
                }
                ImGui::Spacing();
                if (s_update_dl_url[0]) {
                    const std::string url = s_update_dl_url;
                    const bool looks_safe =
                        url.rfind("https://github.com/FCFlenkchy/FCAE_VPN/releases/tag/", 0) == 0
                        && url.find('\'') == std::string::npos
                        && url.find('"') == std::string::npos
                        && url.find('`') == std::string::npos
                        && url.find('\\') == std::string::npos
                        && url.find('\n') == std::string::npos
                        && url.find('\r') == std::string::npos;
                    if (looks_safe) {
                        ImGui::Text("Download:");
                        ImGui::SameLine(0, 6);
                        if (ImGui::TextLink(url.c_str()))
                            open_link(url.c_str());
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("%s", url.c_str());
                    } else {
                        ImGui::Text("Download: %s", s_update_dl_url);
                    }
                    ImGui::Spacing();
                    if (ImGui::Button("Open")) {
                        if (!looks_safe)
                            g_app.add_log(FCAE_LOG_WARN,
                                "[ui] refusing to open an update URL with unsafe characters");
                        else
                            open_link(url.c_str());
                    }
                }
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                    ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }

            if (s_update_decode_popup_open) {
                ImGui::OpenPopup("##update_decode_popup");
                s_update_decode_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            // Prose dialog: the release notes wrap, so a fixed readable width
            // is right here. 560 was sized for the old font and is still a good
            // measure at this one.
            ImGui::SetNextWindowSize(ImVec2(560, 0), ImGuiCond_Appearing);
            constrain_modal();
            if (ImGui::BeginPopupModal("##update_decode_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "JSON DECODING FAILED");
                ImGui::Spacing();
                ImGui::TextWrapped("The update manifest could not be decoded, so no version could be compared.");
                static const char kPrefix[] = "Update check failed: ";
                const char* detail = s_update_status;
                if (strncmp(detail, kPrefix, sizeof(kPrefix) - 1) == 0) detail += sizeof(kPrefix) - 1;
                ImGui::TextWrapped("%s", detail);
                ImGui::Spacing();
                ImGui::Text("Raw response:");
                if (s_update_raw_body[0]) {
                    ImGui::InputTextMultiline("##update_raw_body", s_update_raw_body,
                        sizeof(s_update_raw_body), ImVec2(540, 220), ImGuiInputTextFlags_ReadOnly);
                } else {
                    ImGui::TextDisabled("(empty body)");
                }
                ImGui::Spacing();
                if (ImGui::Button("Copy"))
                    ImGui::SetClipboardText(s_update_raw_body);
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                    ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }

            if (s_update_error_popup_open) {
                ImGui::OpenPopup("##update_error_popup");
                s_update_error_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            // Prose dialog: see above.
            ImGui::SetNextWindowSize(ImVec2(440, 0), ImGuiCond_Appearing);
            constrain_modal();
            if (ImGui::BeginPopupModal("##update_error_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "Update Check Failed");
                ImGui::Spacing();
                ImGui::TextWrapped("%s", s_update_status[0]
                    ? s_update_status : "The update check could not be completed.");
                ImGui::Spacing();
                if (ImGui::Button("Retry")) {
                    ImGui::CloseCurrentPopup();
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_update_available = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                    ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }

        }


        const bool tun_paused = s_tun_paused;
        // Height of the control row that holds CONNECT/DISCONNECT, the TUN
        // pause pair and the state label, so all three share one centre line.
        // The row is as tall as the text needs, never less than the 32 px it
        // is designed at: a raised text scale has to grow the button rather
        // than let the label run past its edge.
        const float kActionRowHeight = (ImGui::GetFrameHeight() > 32.0f)
                                     ? ImGui::GetFrameHeight() : 32.0f;

        // Where the row begins, so the status column can be placed at an
        // absolute offset from it instead of after whatever widget ran last.
        const float row_start_x = ImGui::GetCursorPosX();
        const float row_start_y = ImGui::GetCursorPosY();
        ImVec4 btn = (connected || busy) ? ImVec4(0.70f, 0.18f, 0.18f, 1.0f) : ImVec4(0.12f, 0.55f, 0.18f, 1.0f);
        ImVec4 btn_h(btn.x + 0.08f, btn.y + 0.08f, btn.z + 0.08f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, btn_h);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(btn.x - 0.05f, btn.y - 0.05f, btn.z - 0.05f, 1.0f));

        // Wide enough for whichever label this row shows. This MUST be a hard
        // minimum, not a value 130 is then compared against: DISCONNECT is 141 px
        // of text at the 26 px base font, 161 with padding, and clamping it to
        // 130 ran the label straight out of the button's edges -- which is the
        // "text is not centred in its background" report.
        const float action_btn_pad = ImGui::GetStyle().FramePadding.x * 2.0f;
        const float action_btn_min = std::max(ImGui::CalcTextSize("CONNECT").x,
                                              ImGui::CalcTextSize("DISCONNECT").x) + action_btn_pad;
        const float stop_btn_w = std::max(ImGui::CalcTextSize("START").x,
                                          ImGui::CalcTextSize("STOP").x) + action_btn_pad;
        const bool show_tun_control = g_app.mode == 1 && (connected || tun_paused);
        const float pair_reserve = show_tun_control ? stop_btn_w + 6.0f : 0.0f;
        float btn_w = narrow ? (std::max)(action_btn_min, ImGui::GetContentRegionAvail().x - pair_reserve)
                             : action_btn_min;
        bool show_disconnect = connected || busy || tun_paused;
        if (startup) ImGui::BeginDisabled();
        if (ImGui::Button(show_disconnect ? "DISCONNECT" : "CONNECT", ImVec2(btn_w, kActionRowHeight))) {
            if (connected || busy || errored || tun_paused) {
                g_app.start_busy.store(false);
                // Cut the data plane on this click before thread scheduling can
                // delay it. Full route/DNS/backend cleanup remains asynchronous.
                if (fcae_stop_begin() != FCAE_OK) {
                    g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                }
                std::thread([] {
                    if (fcae_stop() != FCAE_OK) {
                        g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                    }
                    g_app.ffi_state.store(FCAE_STATE_DISCONNECTED);
                    ui_request_redraw();
                }).detach();
            } else if (!g_app.start_busy.load()) {
                fcae_ui_diagnostic(1, (uint32_t(g_app.mode) << 16) | uint32_t(g_app.tun_engine));
                const auto has_hop = [](int transport) {
                    return std::find(g_app.chain_transports.begin(), g_app.chain_transports.end(), transport) != g_app.chain_transports.end();
                };
                const bool uses_tor = (g_app.backend == 0 && g_app.protocol == 4) || has_hop(4);
                const bool uses_psi = g_app.backend == 1 || has_hop(5);
                const bool uses_firefox = g_app.backend == 2 || has_hop(10);
                // Every hop above the exit has to hand the one below it a SOCKS5
                // endpoint, and the exit has to answer on a listener the session
                // actually opened. The runtime refuses the session for the same
                // reasons -- this says which switch before anything is torn down.
                const bool core_final = g_app.final_listener_is_core();
                const std::string core_socks_name =
                    std::string(g_app.final_listener_core() == 4 ? "sing-box" : "Xray") + " SOCKS5";
                const std::string core_listener_name = core_socks_name + " or HTTP";
                const bool psi_carrier = !g_app.chain_transports.empty() &&
                    (g_app.backend == 1 || std::find(g_app.chain_transports.begin(), g_app.chain_transports.end() - 1, 5) != g_app.chain_transports.end() - 1);
                const bool firefox_carrier = !g_app.chain_transports.empty() &&
                    (g_app.backend == 2 || std::find(g_app.chain_transports.begin(), g_app.chain_transports.end() - 1, 10) != g_app.chain_transports.end() - 1);
                bool uses_aether = g_app.backend == 0 && g_app.protocol != 4;
                for (int t : g_app.chain_transports)
                    if (t != 4 && t != 5 && t != 10 && !transport_is_core(t)) uses_aether = true;
                const char* disabled = uses_tor && !g_app.tor_socks_enabled ? "Tor SOCKS5" :
                    psi_carrier && !g_app.psiphon_socks_enabled ? "Psiphon SOCKS5" :
                    firefox_carrier && !g_app.firefox_socks_enabled ? "Firefox SOCKS5" :
                    uses_psi && !g_app.psiphon_socks_enabled && !g_app.psiphon_http_enabled ? "Psiphon SOCKS5 or HTTP" :
                    uses_psi && g_app.mode == 1 && (g_app.chain_transports.empty() ? g_app.backend == 1 : g_app.chain_transports.back() == 5) && !g_app.psiphon_socks_enabled ? "Psiphon SOCKS5" :
                    uses_firefox && !g_app.firefox_socks_enabled && g_app.mode == 1 && g_app.final_listener_is_firefox() ? "Firefox SOCKS5" :
                    core_final && g_app.mode == 1 && !g_app.listener_socks_enabled() ? core_socks_name.c_str() :
                    core_final && !g_app.listener_socks_enabled() && !g_app.listener_http_enabled() ? core_listener_name.c_str() :
                    uses_aether && !g_app.socks_enabled ? "Aether SOCKS5" : nullptr;
                if (disabled) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Cannot start: enable %s for this session.", disabled);
                    g_app.add_log(FCAE_LOG_ERROR, msg);
                    set_save_status_error("%s", msg);
                    ImGui::PopStyleColor(3);
                    ImGui::PopStyleVar(2);
                    ImGui::PopStyleVar(2);
                    ImGui::End();
                    return;
                }
                // TUN mode requires admin privileges on Windows
                if (g_app.mode == 1 && !fcae_is_privileged()) {
#ifdef _WIN32
                    // Save config then relaunch self as administrator.
                    // The elevated instance will start fresh — user clicks CONNECT manually.
                    //
                    // ShellExecuteExW with "runas" does not answer until the user
                    // has dealt with the UAC prompt, so it runs on a worker: the
                    // window thread stays in its frame loop and neither the
                    // handoff window nor the consent dialog freezes the app.
                    save_config();
                    wchar_t exe_path[MAX_PATH] = {};
                    GetModuleFileNameW(NULL, exe_path, MAX_PATH);
                    set_save_status("Waiting for administrator consent…");
                    fcae_ui_diagnostic(2, 0);
                    // The decision to exit is published here and acted on by
                    // the window thread: PostQuitMessage only affects the thread
                    // that calls it, so a worker cannot end this process.
                    std::thread([exe_path = std::wstring(exe_path)] {
                        SHELLEXECUTEINFOW sei = {};
                        sei.cbSize = sizeof(sei);
                        sei.lpVerb = L"runas";
                        sei.lpFile = exe_path.c_str();
                        wchar_t handoff_args[64];
                        std::swprintf(handoff_args, 64, L"--fcae-wait-parent %lu",
                                      static_cast<unsigned long>(GetCurrentProcessId()));
                        sei.lpParameters = handoff_args;
                        sei.nShow = SW_NORMAL;
                        // SEE_MASK_NOASYNC keeps the shell from failing a caller
                        // that is not pumping messages, which this thread is not.
                        sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
                        if (ShellExecuteExW(&sei)) {
                            DWORD child_pid = sei.hProcess ? GetProcessId(sei.hProcess) : 0;
                            fcae_ui_diagnostic(3, child_pid);
                            if (sei.hProcess) CloseHandle(sei.hProcess);
                            char msg[160];
                            snprintf(msg, sizeof(msg),
                                "[ui] TUN mode needs elevation -- relaunched elevated (PID %lu). "
                                "This copy will exit in ~1s.",
                                static_cast<unsigned long>(child_pid));
                            g_app.add_log(FCAE_LOG_INFO, msg);
                            set_save_status("Restarting elevated -- this copy will close");
                            // Hand-off window: the elevated copy waits for this
                            // process to exit (--fcae-wait-parent), so the delay
                            // only needs to let UAC dismiss and the new instance
                            // take the single-instance slot.
                            s_elevation_handoff_at.store(GetTickCount(), std::memory_order_relaxed);
                        } else {
                            // Say what happened rather than leaving TUN silently
                            // "not working": the usual cause is a declined UAC
                            // prompt, where GetLastError() is ERROR_CANCELLED.
                            DWORD err = GetLastError();
                            fcae_ui_diagnostic(4, err);
                            const char* why =
                                err == ERROR_CANCELLED ? "UAC consent was cancelled"
                                : err == ERROR_ACCESS_DENIED ? "access was denied"
                                : err == ERROR_FILE_NOT_FOUND ? "the executable path is missing"
                                : "ShellExecuteExW failed";
                            char msg[192];
                            snprintf(msg, sizeof(msg),
                                "[ui] TUN mode requires Administrator privileges (%s, Win32 error %lu). "
                                "Click CONNECT again, accept the UAC prompt, or restart FCAE VPN "
                                "elevated once and the elevated copy will handle every future start.",
                                why, static_cast<unsigned long>(err));
                            g_app.add_log(FCAE_LOG_ERROR, msg);
                            set_save_status_error(
                                "TUN needs Admin (error %lu) -- click CONNECT to retry UAC",
                                static_cast<unsigned long>(err));
                        }
                    }).detach();
                    ImGui::PopStyleColor(3);  // button colors
                    ImGui::PopStyleVar(2);    // status bar FrameRounding/FramePadding
                    ImGui::PopStyleVar(2);    // window WindowPadding/WindowRounding
                    ImGui::End();
                    ui_handoff_tick();
                    return;
#else
                    g_app.add_log(FCAE_LOG_ERROR,
                        "[ui] TUN mode requires root privileges on this platform. "
                        "Restart the app with sudo (or as Administrator via pkexec/polkit) and try again.");
                    set_save_status_error(
                        "TUN needs root -- restart with sudo");
                    ImGui::PopStyleColor(3);  // button colors
                    ImGui::PopStyleVar(2);    // status bar FrameRounding/FramePadding
                    ImGui::PopStyleVar(2);    // window WindowPadding/WindowRounding
                    ImGui::End();
                    return;
#endif
                }
                g_app.start_busy.store(true);
                // Snapshot config + own string storage for the worker thread.
                struct Owned {
                    std::string noize, peer, path, sni, team, token, email, routes, routes_inline;
                    std::string ech_dns, ech_domain, gool_inner, tls_ciphers, api_address, api_host, api_sni, exit_loc;
                    std::string tls_groups, tls13_ciphers, tls_key_shares, tls_sigalgs, tls_cert_compression;
                    std::string tls_alps, tls_trust_anchors, tls_server_padding;
                    std::string psi_json, psi_embedded, psi_dir, upstream;
                    std::string root, firefox_account, firefox_location, firefox_server;
                    // The saved-configs document and the chain hops that
                    // reference it are rebuilt on every to_config(), so the
                    // worker gets its own copy: the UI thread can open the
                    // config editor while a start is in flight.
                    std::string core_library, core_ref;
                    std::vector<std::string> chain_refs;
                    std::vector<FcaeChainHop> chain_hops;
                    FcaeConfig c{};
                };
                // Use unique_ptr with a custom deleter that handles the
                // case where fcae_start throws or the thread is killed.
                auto o = std::unique_ptr<Owned, void(*)(Owned*)>(
                    new Owned(),
                    [](Owned* p) {
                        g_app.start_busy.store(false);
                        delete p;
                    }
                );
                o->noize = g_app.noize_profile;
                o->peer  = g_app.force_peer;
                o->path  = resolve_data_path(g_app.config_path);
                o->sni   = g_app.sni;
                o->team  = g_app.team_name;
                o->token = g_app.access_token;
                o->email = g_app.access_email;
                o->routes = resolve_data_path(g_app.routes_file);
                o->psi_dir = resolve_data_path(g_app.psiphon_data_dir);
                o->upstream = g_app.upstream_proxy;
                o->root = data_dir();
                o->firefox_account = g_app.firefox_account_id;
                o->firefox_location = g_app.firefox_location;
                o->firefox_server = g_app.firefox_server;
                o->routes_inline = g_app.routes_inline;
                o->ech_dns = g_app.ech_dns;
                o->ech_domain = g_app.ech_domain;
                o->gool_inner = g_app.gool_inner;
                o->tls_ciphers = g_app.tls_ciphers;
                o->api_address = g_app.api_address;
                o->api_host = g_app.api_host;
                o->api_sni = g_app.api_sni;
                o->exit_loc = g_app.exit_loc;
                o->tls_groups = g_app.tls_groups;
                o->tls13_ciphers = g_app.tls13_ciphers;
                o->tls_key_shares = g_app.tls_key_shares;
                o->tls_sigalgs = g_app.tls_sigalgs;
                o->tls_cert_compression = g_app.tls_cert_compression;
                o->tls_alps = g_app.tls_alps;
                o->tls_trust_anchors = g_app.tls_trust_anchors;
                o->tls_server_padding = g_app.tls_server_padding;
                o->c = g_app.to_config();
                // to_config() built the JSON (with the server-entry fields
                // merged in) into a g_app buffer; snapshot it, and read the
                // embedded server entry list, so fcae_start only ever sees
                // pointers owned by this worker.
                o->psi_json = g_app.psiphon_config_json_built;
                {
                    // Auto-load psiphon_servers.txt
                    // from the data folder when it exists and has
                    // content: the drop-in bundled-entries slot. Put entries
                    // you are ENTITLED to distribute there (your own servers
                    // or Psiphon-Labs provisioning) — never entries extracted
                    // from other clients; redistributing the Psiphon
                    // network's server addresses unprovisioned is what gets
                    // repositories taken down.
                    std::string bundled = join_path(data_dir(), "psiphon_servers.txt");
                    if (FILE* f = open_cfg(bundled, "rb")) {
                        char chunk[16384];
                        size_t n;
                        while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
                            o->psi_embedded.append(chunk, n);
                        fclose(f);
                        if (!o->psi_embedded.empty()) {
                            g_app.add_log(3, ("[ui] psiphon embedded server list: " +
                                              std::to_string(o->psi_embedded.size()) +
                                              " bytes from " + bundled).c_str());
                        }
                    }
                    if (o->psi_embedded.empty()) {
                        g_app.add_log(3,
                            "[ui] psiphon has no embedded server entries; the core will "
                            "fall back to its built-in legacy public remote server list");
                    }
                }
                o->c.obfuscation.noize_profile = o->noize.c_str();
                o->c.force_peer                = o->peer.empty() ? nullptr : o->peer.c_str();
                o->c.config_path               = o->path.c_str();
                o->c.data_dir                  = o->root.c_str();
                o->c.firefox.account_id         = o->firefox_account.empty() ? nullptr : o->firefox_account.c_str();
                o->c.firefox.location           = o->firefox_location.empty() ? nullptr : o->firefox_location.c_str();
                o->c.firefox.server             = o->firefox_server.empty() ? nullptr : o->firefox_server.c_str();
                o->c.dns.sni                   = o->sni.empty() ? nullptr : o->sni.c_str();
                o->c.zero_trust.team_name      = o->team.empty() ? nullptr : o->team.c_str();
                o->c.zero_trust.access_token   = o->token.empty() ? nullptr : o->token.c_str();
                o->c.zero_trust.access_email   = o->email.empty() ? nullptr : o->email.c_str();
                o->c.routing.rules_file        = o->routes.empty() ? nullptr : o->routes.c_str();
                o->c.routing.rules_inline      = o->routes_inline.empty() ? nullptr : o->routes_inline.c_str();
                o->c.aether.ech_dns            = o->ech_dns.empty() ? nullptr : o->ech_dns.c_str();
                o->c.aether.ech_domain         = o->ech_domain.empty() ? nullptr : o->ech_domain.c_str();
                o->c.aether.gool_inner         = o->gool_inner.empty() ? nullptr : o->gool_inner.c_str();
                o->c.aether.tls_ciphers        = o->tls_ciphers.empty() ? nullptr : o->tls_ciphers.c_str();
                o->c.aether.api_address        = o->api_address.empty() ? nullptr : o->api_address.c_str();
                o->c.aether.api_host           = o->api_host.empty() ? nullptr : o->api_host.c_str();
                o->c.aether.api_sni            = o->api_sni.empty() ? nullptr : o->api_sni.c_str();
                o->c.aether.exit_loc           = o->exit_loc.empty() ? nullptr : o->exit_loc.c_str();
                o->c.dns.tls_groups            = o->tls_groups.empty() ? nullptr : o->tls_groups.c_str();
                o->c.aether.tls13_ciphers      = o->tls13_ciphers.empty() ? nullptr : o->tls13_ciphers.c_str();
                o->c.aether.tls_key_shares     = o->tls_key_shares.empty() ? nullptr : o->tls_key_shares.c_str();
                o->c.aether.tls_sigalgs        = o->tls_sigalgs.empty() ? nullptr : o->tls_sigalgs.c_str();
                o->c.aether.tls_cert_compression = o->tls_cert_compression.empty() ? nullptr : o->tls_cert_compression.c_str();
                o->c.aether.tls_alps           = o->tls_alps.empty() ? nullptr : o->tls_alps.c_str();
                o->c.aether.tls_trust_anchors  = o->tls_trust_anchors.empty() ? nullptr : o->tls_trust_anchors.c_str();
                o->c.aether.tls_server_padding = o->tls_server_padding.empty() ? nullptr : o->tls_server_padding.c_str();
                o->c.psiphon.config_json          = o->psi_json.c_str();
                o->c.psiphon.data_root_dir        = o->psi_dir.empty() ? nullptr : o->psi_dir.c_str();
                o->c.upstream_proxy               = o->upstream.empty() ? nullptr : o->upstream.c_str();
                o->c.psiphon.embedded_server_list =
                    o->psi_embedded.empty() ? nullptr : o->psi_embedded.c_str();
                o->core_library = g_app.core_library_built;
                o->core_ref = g_app.core_ref_built;
                o->chain_refs = g_app.chain_core_refs_built;
                o->chain_hops = g_app.chain_hops_built;
                o->c.core.library = o->core_library.empty() ? nullptr : o->core_library.c_str();
                o->c.core.config_ref = o->core_ref.empty() ? nullptr : o->core_ref.c_str();
                {
                    // Re-point each saved-config hop at the snapshot's own copy
                    // of its reference, in the order they were built.
                    size_t ref = 0;
                    for (FcaeChainHop& hop : o->chain_hops) {
                        hop.config_ref = hop.config_ref && ref < o->chain_refs.size()
                            ? o->chain_refs[ref++].c_str() : nullptr;
                    }
                }
                o->c.chain.hops = o->chain_hops.empty() ? nullptr : o->chain_hops.data();
                auto* raw = o.release(); // transfer ownership to the thread
                std::thread([raw] {
                    // Wrap in a unique_ptr again so the custom deleter
                    // fires on scope exit (even if fcae_start throws).
                    std::unique_ptr<Owned, void(*)(Owned*)> guard(
                        raw, [](Owned* p) {
                            g_app.start_busy.store(false);
                            delete p;
                        }
                    );
                    // Every failure mode now has a specific, user-facing
                    // reason instead of a bare false.
                    if (fcae_start(&guard->c) != FCAE_OK) {
                        g_app.add_log(FCAE_LOG_ERROR, fcae_last_error());
                        ui_request_redraw();
                    }
                }).detach();
            }
        }
        if (startup) {
            ImGui::EndDisabled();
            ImGui::SetItemTooltip("Finishing initialization...");
        }
        ImGui::PopStyleColor(3);

        if (show_tun_control) {
            ImGui::SameLine(0, 6);
            ImGui::SetCursorPosY(row_start_y);
            if (tun_paused) {
                ImVec4 start_col(0.18f, 0.35f, 0.85f, 1.0f);
                ImVec4 start_h(0.26f, 0.45f, 0.95f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, start_col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, start_h);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(start_col.x - 0.05f, start_col.y - 0.05f, start_col.z - 0.05f, 1.0f));
                if (ImGui::Button("START", ImVec2(stop_btn_w, kActionRowHeight))) {
                    std::thread([] {
                        if (fcae_resume_tun() != FCAE_OK) {
                            g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                        }
                        ui_request_redraw();
                    }).detach();
                }
                ImGui::PopStyleColor(3);
            } else {
                ImVec4 stop_col(0.85f, 0.55f, 0.15f, 1.0f);
                ImVec4 stop_h(0.95f, 0.65f, 0.25f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, stop_col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, stop_h);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(stop_col.x - 0.05f, stop_col.y - 0.05f, stop_col.z - 0.05f, 1.0f));
                if (ImGui::Button("STOP", ImVec2(stop_btn_w, kActionRowHeight))) {
                    std::thread([] {
                        if (fcae_pause_tun() != FCAE_OK) {
                            g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                        }
                        ui_request_redraw();
                    }).detach();
                }
                ImGui::PopStyleColor(3);
            }
        }

        const float status_x = btn_w + pair_reserve + 12.0f;
        if (!narrow) ImGui::SameLine();
        const float status_y = narrow ? ImGui::GetCursorPosY() : row_start_y;
        if (!narrow) ImGui::SetCursorPosX(row_start_x + status_x);
        ImGui::SetCursorPosY(status_y + (kActionRowHeight - ImGui::GetFrameHeight()) * 0.5f);
        ImGui::BeginGroup();
        ImGui::AlignTextToFramePadding();
        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        if (startup) {
            ImGui::TextUnformatted("INITIALIZING...");
        } else if (errored && telem.last_error[0] && s_error_detail_visible) {
            ImGui::Text("ERROR: %s", telem.last_error);
        } else {
            ImGui::Text("%s", state_label(cur));
        }
        ImGui::PopStyleColor();
        ImGui::EndGroup();

        if (busy) {
            ImGui::SameLine(0, 8);
            constexpr float kRingRadius = 7.0f;
            const float ring_box = (kRingRadius * 2.0f + 4.0f) > ImGui::GetTextLineHeight()
                                 ? (kRingRadius * 2.0f + 4.0f) : ImGui::GetTextLineHeight();
            ImGui::SetCursorPosY(status_y + (kActionRowHeight - ring_box) * 0.5f);
            draw_spinner(kRingRadius, 7.0f);
        }

        if (g_app.save_status[0]) {
            ImGui::SameLine(0, 8);
            ImGui::SetCursorPosY(status_y + (kActionRowHeight - ImGui::GetFrameHeight()) * 0.5f);
            ImGui::BeginGroup();
            ImGui::AlignTextToFramePadding();
            ImGui::TextColored(s_save_status_error ? ImVec4(0.95f, 0.38f, 0.38f, 1.0f)
                                                   : ImVec4(0.3f, 0.9f, 0.4f, 1.0f),
                               "%s", g_app.save_status);
            ImGui::EndGroup();
            s_save_status_painted_revision = s_save_status_revision;
        }

        // "Check for Updates" rides in the CONNECT row, pinned as far right
        // as the window allows; on narrow windows it drops to its own line,
        // still flush right. Gated until the runtime is live.
        if (startup) ImGui::BeginDisabled();
        if (!narrow) {
            ImGui::SameLine(0, 10);
            ImGui::SetCursorPosY(row_start_y);
        }
        {
            // Sized from the longest label this button ever shows, not from a
            // constant. At the old 13 px font the widest was "Check for Updates"
            // at 119 px, which fitted a hard-coded 136 -- but at the doubled
            // base size that same label is 239 px, so it ran past the button's
            // edges and read as "not centred in its background". Measuring keeps
            // the label centred whatever the font size is.
            const float btn_pad   = ImGui::GetStyle().FramePadding.x * 2.0f;
            // The widest label is used for all states, so the button keeps one
            // width instead of twitching whenever the label changes: a button
            // that resizes while it is pinned to the right edge also drags its
            // own text around, which reads as the label jumping off-centre.
            float btn_width = std::max(ImGui::CalcTextSize("Check for Updates").x,
                              std::max(ImGui::CalcTextSize("Check Timed Out").x,
                                       ImGui::CalcTextSize("Checking... 999s").x)) + btn_pad;
            // Only if the window is too narrow to hold it does it give ground.
            {
                const float room = ImGui::GetWindowContentRegionMax().x - 260.0f;
                if (room > 60.0f && btn_width > room) btn_width = room;
            }
            // The button height follows the text: at 32 px exactly, a raised
            // text scale would push the label past the button's edge. The
            // designed 32 px stays the floor.
            const float update_btn_h = (ImGui::GetFrameHeight() > 32.0f)
                                     ? ImGui::GetFrameHeight() : 32.0f;
            {
                const float right_x = ImGui::GetWindowContentRegionMax().x - btn_width;
                if (ImGui::GetCursorPosX() < right_x)
                    ImGui::SetCursorPosX(right_x);
            }
            FcaeUpdateInfo info = {};
            info.struct_size = sizeof(info);
            info.abi_version = FCAE_ABI_VERSION;
            bool done = (fcae_poll_update(&info) == FCAE_OK);
            s_update_in_progress = info.check_in_progress;
            snprintf(s_update_date, sizeof(s_update_date), "%s", info.release_date);

            if (info.check_in_progress) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_check_start_time).count();
                if (elapsed > 15) {
                    const bool new_result = !s_update_checked;
                    s_update_checked = true;
                    if (new_result) s_update_error_popup_open = true;
                    s_update_available = false;
                    s_update_error_kind = FCAE_UPDATE_ERROR_NETWORK;
                    snprintf(s_update_status, sizeof(s_update_status), "Check timed out (network unreachable?)");
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.62f, 0.14f, 0.14f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.76f, 0.19f, 0.19f, 1.0f));
                    if (ImGui::Button("Check Timed Out", ImVec2(btn_width, update_btn_h)))
                        s_update_error_popup_open = true;
                    ImGui::PopStyleColor(2);
                } else {
                    char checking_label[32];
                    // Padded to two digits so the button does not change width
                    // when the counter rolls from 9 to 10.
                    snprintf(checking_label, sizeof(checking_label), "Checking... %2llds", (long long)elapsed);
                    ImGui::BeginDisabled();
                    ImGui::Button(checking_label, ImVec2(btn_width, update_btn_h));
                    ImGui::EndDisabled();
                }
            } else if (done && info.update_available) {
                const bool new_result = !s_update_checked;
                s_update_available = true;
                s_update_checked = true;
                if (new_result) s_update_popup_open = true;
                snprintf(s_update_latest, sizeof(s_update_latest), "%s", info.latest_version);
                snprintf(s_update_notes, sizeof(s_update_notes), "%s", info.release_notes);
                snprintf(s_update_dl_url, sizeof(s_update_dl_url), "%s", info.download_url);
                snprintf(s_update_status, sizeof(s_update_status), "%s", info.status_message);
                s_update_error_kind = FCAE_UPDATE_ERROR_NONE;

                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.55f, 0.0f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.65f, 0.1f, 1.0f));
                if (ImGui::Button("Update Available!", ImVec2(btn_width, update_btn_h))) {
                    s_update_popup_open = true;
                }
                ImGui::PopStyleColor(2);
            } else if (done && !info.update_available) {
                const bool new_result = !s_update_checked;
                s_update_available = false;
                s_update_checked = true;
                s_update_error_kind = info.error_kind;
                snprintf(s_update_status, sizeof(s_update_status), "%s", info.status_message);
                snprintf(s_update_raw_body, sizeof(s_update_raw_body), "%s", info.raw_body);
                if (s_update_error_kind == FCAE_UPDATE_ERROR_DECODE) {
                    if (new_result) s_update_decode_popup_open = true;
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.78f, 0.16f, 0.16f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.90f, 0.22f, 0.22f, 1.0f));
                    if (ImGui::Button("ATTENTION!", ImVec2(btn_width, update_btn_h)))
                        s_update_decode_popup_open = true;
                    ImGui::PopStyleColor(2);
                } else {
                    const bool failed = s_update_error_kind != FCAE_UPDATE_ERROR_NONE;
                    if (new_result && failed) s_update_error_popup_open = true;
                    ImGui::PushStyleColor(ImGuiCol_Button,
                        failed ? ImVec4(0.62f, 0.14f, 0.14f, 1.0f)
                               : ImVec4(0.12f, 0.48f, 0.20f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                        failed ? ImVec4(0.76f, 0.19f, 0.19f, 1.0f)
                               : ImVec4(0.16f, 0.60f, 0.26f, 1.0f));
                    if (ImGui::Button(failed ? "Check Failed" : "Up to Date", ImVec2(btn_width, update_btn_h))) {
                        if (failed) {
                            s_update_error_popup_open = true;
                        } else {
                            fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                            s_update_checked = false;
                            s_update_available = false;
                            s_check_start_time = std::chrono::steady_clock::now();
                        }
                    }
                    ImGui::PopStyleColor(2);
                }
            } else {
                if (ImGui::Button("Check for Updates", ImVec2(btn_width, update_btn_h))) {
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_update_available = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
            }
        }
        if (startup) ImGui::EndDisabled();

        {
            if (s_about_popup_open) {
                ImGui::OpenPopup("##about_popup");
                s_about_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            constrain_modal();
            if (ImGui::BeginPopupModal("##about_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGui::TextUnformatted("FCAE VPN");
                ImGui::TextColored(build_is_prerelease() ? ImVec4(1.0f, 0.72f, 0.20f, 1.0f)
                                                         : ImVec4(0.62f, 0.66f, 0.74f, 1.0f),
                                   "%s  |  %s", fcae_display_version(),
                                   build_is_prerelease() ? "pre-release" : "release");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();
                for (const CommunityLink& link : kCommunityLinks) {
                    ImGui::PushID(link.url);
                    if (ImGui::TextLink(link.label))
                        open_link(link.url);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s", link.url);
                    // A second column: the label, then the address it points
                    // at. Measured rather than a flat 96 px, which the doubled
                    // font size left too narrow for the link text.
                    ImGui::SameLine(ImGui::CalcTextSize("Telegram").x + 24.0f);
                    ImGui::TextDisabled("%s", link.shown);
                    ImGui::PopID();
                }
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::TextUnformatted("Support the developer with GRAM (The Open Network):");
                ImGui::TextUnformatted(kGramAddress);
                if (ImGui::Button("Copy GRAM address")) ImGui::SetClipboardText(kGramAddress);
                ImGui::Spacing();
                ImGui::TextDisabled("%s", build_is_prerelease()
                    ? "Pre-released under the" : "Released under the");
                ImGui::SameLine(0, 4);
                if (ImGui::TextLink("LICENSE"))
                    open_link(kLinkLicense.c_str());
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", kLinkLicense.c_str());
                ImGui::TextDisabled("Credits are listed in the");
                ImGui::SameLine(0, 4);
                if (ImGui::TextLink("GitHub repository"))
                    open_link(kLinkCredits.c_str());
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", kLinkCredits.c_str());
                ImGui::Spacing();
                if (ImGui::Button("Telegram##about_telegram_button")) open_link(kCommunityLinks[0].url);
                ImGui::SameLine();
                if (ImGui::Button("GitHub##about_github_button")) open_link(kCommunityLinks[1].url);
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                    ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
        }

        ImGui::PopStyleVar(2);
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    {
        const float avail_w = ImGui::GetContentRegionAvail().x;
        // The footer is two columns once there is room for both: the transfer
        // statistics on the left, the sponsor card on the right.
        //
        // The left column's width is measured from the widest line it actually
        // draws, rather than from the old flat 230. At the doubled font size a
        // download figure with its rate beside it is wider than 230, so the old
        // constant let the telemetry run underneath the sponsor card.
        float left_column_w = ImGui::CalcTextSize("Upload:  ").x;
        {
            // A byte total and its rate on one line, at the widest they get:
            // "1023.99 MB" and a rate beside it, joined by a small gap.
            const float stats_w = std::max(ImGui::CalcTextSize("Download:").x,
                                           ImGui::CalcTextSize("Upload:").x)
                                + 6.0f + ImGui::CalcTextSize("1023.99 GB").x
                                + 6.0f + ImGui::CalcTextSize("(1023.99 GB/s)").x;
            left_column_w = (std::max)(left_column_w, stats_w);
            // The RTT readout and the INFO button that follows it.
            left_column_w = (std::max)(left_column_w,
                                       ImGui::CalcTextSize("9999ms").x + 10.0f
                                       + ImGui::CalcTextSize("INFO").x
                                       + ImGui::GetStyle().FramePadding.x * 2.0f);
        }
        left_column_w += 8.0f;
        // A floor so a narrow window still has a usable column rather than one
        // that collapses to the width of a word.
        const float min_left_w = 260.0f;
        if (left_column_w < min_left_w) left_column_w = min_left_w;
        // Space the card needs to be worth having.
        const float min_card_w = 320.0f;
        const float column_gap  = 24.0f;
        const bool use_columns  = (avail_w - (left_column_w + column_gap)) >= min_card_w;
        const float card_w = use_columns
            ? std::clamp(avail_w * 0.4f, min_card_w, avail_w - left_column_w - column_gap)
            : avail_w;
        const float sponsor_offset_x = ImGui::GetCursorPosX() + (use_columns ? avail_w - card_w : 0.0f);

        ImGui::BeginGroup(); // Left column: Stats
        {
            char total_buf[32], rate_buf[32];
            ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "Download:");
            ImGui::SameLine(0, 6);
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_rx);
            ImGui::Text("%s", total_buf);
            ImGui::SameLine(0, 6);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.rx_bytes_sec);
            ImGui::TextColored(ImVec4(0.50f, 0.50f, 0.55f, 1.0f), "(%s)", rate_buf);

            ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "Upload:  ");
            ImGui::SameLine(0, 6);
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_tx);
            ImGui::Text("%s", total_buf);
            ImGui::SameLine(0, 6);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.tx_bytes_sec);
            ImGui::TextColored(ImVec4(0.50f, 0.50f, 0.55f, 1.0f), "(%s)", rate_buf);

            ImGui::Spacing();
            char rtt_buf[24];
            if (telem.state == FCAE_STATE_CONNECTED && telem.rtt_ms > 0)
                snprintf(rtt_buf, sizeof(rtt_buf), "%ums", telem.rtt_ms);
            else
                snprintf(rtt_buf, sizeof(rtt_buf), "--");
            ImGui::TextColored(ImVec4(0.70f, 0.90f, 0.70f, 1.0f), "%s", rtt_buf);
            ImGui::SameLine(0, 10);
            // No vertical nudge needed: SmallButton() zeroes its own vertical
            // frame padding and passes ImGuiButtonFlags_AlignTextBaseLine, so it
            // already sits on the text baseline rather than the text's top edge.
            if (ImGui::SmallButton("INFO")) {
                s_connection_info_popup_open = true;
                ui_request_redraw();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Show connection details");
        }
        ImGui::EndGroup();

        if (use_columns) {
            ImGui::SameLine(sponsor_offset_x);
        } else {
            ImGui::Spacing();
        }

        ImGui::BeginGroup(); // Right column: Sponsor Section
        {
            const char* sponsor_policy = "https://github.com/FCFlenkchy/FCAE_VPN/blob/main/SPONSOR_POLICY.md";
            const bool sponsor_has_content = s_sponsor.available;
            const char* sponsor_destination = sponsor_has_content ? s_sponsor.destination_url : sponsor_policy;
            const char* sponsor_title = sponsor_has_content ? s_sponsor.title : "Become a sponsor";
            const char* sponsor_message = sponsor_has_content ? s_sponsor.message : "Click to learn more";

            // Mirrors Android's 38dp rounded_rectangle row: #171A26 fill,
            // 1px #292D3D border, 10/4 horizontal padding, 8px gap to the card.
            const float kHeaderPadV = 4.0f;
            // Follows the icon size, which follows the font: a fixed height here
            // would clip the buttons once the type grew.
            const float kHeaderHeight = icon_button_size() + kHeaderPadV * 2.0f;
            const float kHeaderRounding = kHeaderHeight * 12.0f / 38.0f;
            const ImVec2 cursor = ImGui::GetCursorScreenPos();
            const ImVec2 header_min(std::floor(cursor.x), std::floor(cursor.y));
            const ImVec2 header_max(header_min.x + card_w, header_min.y + kHeaderHeight);
            ImDrawList* const header_draw = ImGui::GetWindowDrawList();
            header_draw->AddRectFilled(header_min, header_max, IM_COL32(23, 26, 38, 255), kHeaderRounding);
            header_draw->AddRect(header_min, header_max, IM_COL32(41, 45, 61, 255), kHeaderRounding, 0, 1.0f);
            const float header_icon = icon_button_size();
            const float audio_x = header_max.x - 10.0f - header_icon;
            const float refresh_x = audio_x - 6.0f - header_icon;
            const float title_x = header_min.x + 10.0f;
            constexpr float text_gap = 8.0f;
            const char* const cta = "become a sponsor";
            const float natural_text_w = ImGui::CalcTextSize("SPONSORS").x
                + ImGui::CalcTextSize(cta).x;
            const float text_scale = std::clamp(
                (refresh_x - title_x - text_gap * 2.0f) / natural_text_w, 0.1f, 1.0f);
            ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * text_scale);
            const float title_w = ImGui::CalcTextSize("SPONSORS").x;
            const float cta_w = ImGui::CalcTextSize(cta).x;
            const float header_text_y = header_min.y
                + std::floor((kHeaderHeight - ImGui::GetTextLineHeight()) * 0.5f);
            header_draw->AddText(ImVec2(title_x, header_text_y),
                IM_COL32(140, 184, 255, 255), "SPONSORS");
            const float link_left = title_x + title_w + text_gap;
            const float link_right = refresh_x - text_gap;
            // NewLine clears the inherited text baseline before absolute placement.
            ImGui::NewLine();
            ImGui::SetCursorScreenPos(ImVec2(
                link_left + std::max(0.0f, (link_right - link_left - cta_w) * 0.5f), header_text_y));
            if (ImGui::TextLink(cta)) open_link(sponsor_policy);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", sponsor_policy);
            ImGui::PopFont();
            const float header_icon_y = header_min.y + kHeaderPadV;
            ImGui::SetCursorScreenPos(ImVec2(refresh_x, header_icon_y));
            if (round_icon_button("##sponsor_refresh", UiIcon::Refresh, false, "Refresh sponsor manifest")) {
                fcae_sponsor_refresh_manifest_now_async();
                ui_request_redraw();
            }
            const bool audio_enabled = fcae_sponsor_audio_enabled();
            ImGui::SetCursorScreenPos(ImVec2(audio_x, header_icon_y));
            if (round_icon_button("##sponsor_audio", audio_enabled ? UiIcon::SoundOn : UiIcon::SoundOff,
                                  audio_enabled,
                                  audio_enabled ? "Turn sponsor sound off" : "Turn sponsor sound on")) {
                fcae_sponsor_set_audio_enabled(!audio_enabled);
                ui_request_redraw();
            }
            ImGui::SetCursorScreenPos(ImVec2(header_min.x, header_max.y + 8.0f));

            ImTextureID texture = ImTextureID{};
            ImTextureID background_texture = ImTextureID{};
            if (!s_sponsor_rgba.empty() && s_sponsor.width > 0 && s_sponsor.height > 0
                    && s_sponsor_loaded_foreground_generation != 0) {
                texture = sponsor_texture_update(
                    s_sponsor_rgba.data(), (int)s_sponsor.width, (int)s_sponsor.height,
                    s_sponsor_loaded_foreground_generation & ~kSponsorBackgroundFrameMask, 0);
            }
            if (!s_sponsor_background_rgba.empty() && s_sponsor.background_width > 0
                    && s_sponsor.background_height > 0
                    && s_sponsor_loaded_background_generation != 0) {
                background_texture = sponsor_texture_update(
                    s_sponsor_background_rgba.data(), (int)s_sponsor.background_width,
                    (int)s_sponsor.background_height,
                    s_sponsor_loaded_background_generation & ~kSponsorForegroundFrameMask, 1);
            }
            const float icon_scale = std::clamp((float)s_sponsor.icon_scale / 100.0f, 0.5f, 1.6f);
            const float background_scale = std::clamp((float)s_sponsor.background_scale / 100.0f, 0.5f, 1.6f);
            const float title_scale = std::clamp((float)(s_sponsor.title_scale ? s_sponsor.title_scale : 100) / 100.0f, 0.5f, 2.0f);
            // Android's 16sp title / 14sp message hierarchy.
            constexpr float kSponsorMessageFontRatio = 14.0f / 16.0f;
            const float message_scale = kSponsorMessageFontRatio
                * std::clamp((float)(s_sponsor.message_scale ? s_sponsor.message_scale : 100) / 100.0f, 0.5f, 2.0f);
            constexpr float kSponsorTextInset = 8.0f;
            // Was a flat 80 px, sized for the old type. The icon band and the
            // two text lines inside are drawn relative to the message scale, so
            // the card is sized from the text it has to hold.
            const float sponsor_card_height = std::max(80.0f,
                ImGui::GetTextLineHeightWithSpacing() * 2.0f * message_scale
                + kSponsorTextInset * 3.0f + 8.0f);
            // Android's card: the icon band is 70 of 140dp, and media, icon and
            // text all span the whole card rather than a padded inner area.
            const float sponsor_media_height = sponsor_card_height * 70.0f / 140.0f;
            const ImVec4 card_color = sponsor_color(s_sponsor.card_color, ImVec4(0.08f, 0.13f, 0.22f, 1.0f),
                s_sponsor.background_color_opacity);
            ImGui::PushStyleColor(ImGuiCol_ChildBg, card_color);
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.28f, 0.49f, 0.76f, 1.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            ImGui::BeginChild("##sponsor_card", ImVec2(card_w, sponsor_card_height),
                ImGuiChildFlags_Borders, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

            if (background_texture) {
                const ImVec2 card_min = ImGui::GetCursorScreenPos();
                const ImVec2 card_size = ImGui::GetContentRegionAvail();
                const ImVec2 source((float)s_sponsor.background_width, (float)s_sponsor.background_height);
                const float cover = std::max(card_size.x / source.x, card_size.y / source.y) * background_scale;
                const ImVec2 drawn(source.x * cover, source.y * cover);
                // Overflow is cropped through the UVs rather than drawn past the
                // card, so a filling background shares the card's rounded corners.
                const ImVec2 visible(std::min(drawn.x, card_size.x), std::min(drawn.y, card_size.y));
                const ImVec2 uv_min((1.0f - visible.x / drawn.x) * 0.5f, (1.0f - visible.y / drawn.y) * 0.5f);
                const ImVec2 image_min(card_min.x + (card_size.x - visible.x) * 0.5f,
                                       card_min.y + (card_size.y - visible.y) * 0.5f);
                const bool fills_card = visible.x >= card_size.x && visible.y >= card_size.y;
                ImGui::GetWindowDrawList()->AddImageRounded(background_texture, image_min,
                    ImVec2(image_min.x + visible.x, image_min.y + visible.y),
                    uv_min, ImVec2(1.0f - uv_min.x, 1.0f - uv_min.y),
                    ImGui::GetColorU32(ImVec4(1, 1, 1, (float)s_sponsor.background_opacity / 100.0f)),
                    fills_card ? ImGui::GetStyle().ChildRounding : 0.0f);
            }

            if (texture) {
                const ImVec2 icon_origin = ImGui::GetCursorScreenPos();
                const ImVec2 icon_area = ImGui::GetContentRegionAvail();
                const ImVec2 band(icon_area.x, sponsor_media_height);
                const ImVec2 source((float)s_sponsor.width, (float)s_sponsor.height);
                ImVec2 size = band;
                ImVec2 uv0(0, 0);
                ImVec2 uv1(1, 1);
                if (s_sponsor.image_fit == 0) {
                    const float fit = std::min(band.x / source.x, band.y / source.y);
                    size = ImVec2(source.x * fit, source.y * fit);
                } else {
                    const float image_ratio = source.x / source.y;
                    const float band_ratio = band.x / band.y;
                    if (image_ratio > band_ratio) {
                        const float crop = (1.0f - band_ratio / image_ratio) * 0.5f;
                        uv0.x = crop;
                        uv1.x = 1.0f - crop;
                    } else {
                        const float crop = (1.0f - image_ratio / band_ratio) * 0.5f;
                        uv0.y = crop;
                        uv1.y = 1.0f - crop;
                    }
                }
                size.x *= icon_scale;
                size.y *= icon_scale;
                const auto sponsor_icon_center = [](float extent, float drawn, float percent) {
                    if (drawn >= extent) return extent * 0.5f;
                    return std::clamp(extent * percent, drawn * 0.5f, extent - drawn * 0.5f);
                };
                const ImVec2 icon_min(
                    icon_origin.x + sponsor_icon_center(icon_area.x, size.x,
                        std::clamp((float)s_sponsor.icon_x / 100.0f, 0.0f, 1.0f)) - size.x * 0.5f,
                    icon_origin.y + sponsor_icon_center(icon_area.y, size.y,
                        std::clamp((float)s_sponsor.icon_y / 100.0f, 0.0f, 1.0f)) - size.y * 0.5f);
                const ImVec2 icon_max(icon_min.x + size.x, icon_min.y + size.y);
                ImGui::GetWindowDrawList()->AddImage(texture, icon_min, icon_max, uv0, uv1,
                    ImGui::GetColorU32(ImVec4(1, 1, 1, (float)s_sponsor.icon_opacity / 100.0f)));
            }
            const ImVec2 card_origin = ImGui::GetWindowPos();
            ImGui::SetCursorScreenPos(card_origin);
            ImGui::InvisibleButton("##sponsor_card_touch", ImVec2(card_w, sponsor_card_height));
            static bool sponsor_dragged = false;
            if (ImGui::IsItemActivated()) sponsor_dragged = false;
            if (ImGui::IsItemActive() && s_sponsor.campaign_count > 1
                    && std::abs(ImGui::GetMouseDragDelta(ImGuiMouseButton_Left).x) >= 36.0f)
                sponsor_dragged = true;
            if (ImGui::IsItemDeactivated()) {
                if (sponsor_dragged) {
                    fcae_sponsor_next();
                    ui_request_redraw();
                } else if (ImGui::IsItemHovered()
                        && strncmp(sponsor_destination, "https://", 8) == 0) {
                    open_link(sponsor_destination);
                }
                sponsor_dragged = false;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip(s_sponsor.campaign_count > 1
                    ? "Click to open, drag to change sponsor"
                    : "Click to open sponsor website");

            const ImVec2 text_card(card_w, sponsor_card_height);
            const ImVec2 text_origin = ImGui::GetWindowPos();
            if (sponsor_has_content) {
                SponsorText title = layout_sponsor_text(sponsor_title, text_card, kSponsorTextInset,
                    s_sponsor.title_x, text_card.y * (float)s_sponsor.title_y / 100.0f, title_scale);
                SponsorText message = layout_sponsor_text(sponsor_message, text_card, kSponsorTextInset,
                    s_sponsor.message_x, text_card.y * (float)s_sponsor.message_y / 100.0f, message_scale);
                separate_sponsor_text(title, message, text_card.y, 2.0f);
                draw_sponsor_text(title, text_origin,
                    sponsor_color(s_sponsor.title_color, ImVec4(1.0f, 1.0f, 1.0f, 1.0f), s_sponsor.title_opacity));
                draw_sponsor_text(message, text_origin,
                    sponsor_color(s_sponsor.message_color, ImVec4(0.85f, 0.91f, 1.0f, 1.0f), s_sponsor.message_opacity));
            } else {
                const float line_h = ImGui::GetFontSize();
                const float top = (text_card.y - line_h * 3.0f) * 0.5f;
                draw_sponsor_text(layout_sponsor_text(sponsor_title, text_card, kSponsorTextInset, 50, top, 1.0f),
                    text_origin, ImVec4(0.80f, 0.90f, 1.0f, 1.0f));
                draw_sponsor_text(layout_sponsor_text(sponsor_message, text_card, kSponsorTextInset, 50,
                    top + line_h * 2.0f, kSponsorMessageFontRatio), text_origin, ImVec4(0.45f, 0.65f, 0.95f, 1.0f));
            }
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);
        }
        ImGui::EndGroup();
    }

    if (s_connection_info_popup_open) {
        ImGui::OpenPopup("##connection_info_popup");
        s_connection_info_popup_open = false;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    // Sized to the widest line this dialog can show rather than to a fixed 480.
    // Both shapes are represented: the live-core line ("SOCKS5 127.0.0.1:1819 |
    // LAN: 192.168.100.100:1819", the longest case) and the settings fallback.
    {
        static const char* const kWidest[] = {
            // The live listener lines, which are the structural content of this
            // dialog and must not wrap.
            "    HTTPS 127.0.0.1:65535 | LAN: 255.255.255.255:65535",
            "    SOCKS5 127.0.0.1:65535 | LAN: 255.255.255.255:65535",
            "1_ ROUTE HOP - sing-box",
            // The settings fallback, one endpoint per line.
            "sing-box local: SOCKS5 127.0.0.1:65535",
        };
        ImGui::SetNextWindowSize(
            dialog_width_for(kWidest, (int)(sizeof(kWidest) / sizeof(kWidest[0])), 480.0f),
            ImGuiCond_Always);
    }
    constrain_modal();
    if (ImGui::BeginPopupModal("##connection_info_popup", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_HorizontalScrollbar)) {
        // What the live cores are listening on, asked of the cores themselves.
        // The settings hold one port for a session that may run several
        // instances (a chained hop, a native config with more than one
        // inbound), so they are what the popup falls back to, not what it
        // shows when the cores can answer.
        static char live_listeners[4096] = {};
        static uint32_t live_len = 0;
        if (connected) {
            uint32_t needed = fcae_live_listeners(live_listeners, (uint32_t)sizeof(live_listeners));
            live_len = needed < sizeof(live_listeners) ? needed : 0;
            live_listeners[live_len] = '\0';
        } else {
            live_len = 0;
            live_listeners[0] = '\0';
        }
        // `core|position|name|protocol|port|scope;...`, grouped per instance:
        // one header naming the instance and one line per inbound it answers on.
        // The records arrive in route order and `position` counts across every
        // core in it, so a route of several hops reads 1_, 2_, 3_ whatever cores
        // they run. A listener bound to loopback alone offers no LAN address,
        // because a chained hop serves only the hop below it.
        struct LiveListener {
            std::string proto;
            std::string port;
            bool any;
        };
        struct LiveGroup {
            std::string core;
            /// The instance's place in the route, counted across every core the
            /// route runs: the exit is 1, each hop above it the next number.
            std::string position;
            /// The name the session started the instance under.
            std::string label;
            std::vector<LiveListener> lines;
        };
        std::vector<LiveGroup> live_groups;
        for (const char* cursor = live_listeners; *cursor; ) {
            const char* end = strchr(cursor, ';');
            const size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
            const char* bars[5] = {};
            const char* at = cursor;
            for (int slot = 0; slot < 5; ++slot) {
                const size_t room = len - (size_t)(at - cursor);
                const char* bar = (const char*)memchr(at, '|', room);
                if (!bar) break;
                bars[slot] = bar;
                at = bar + 1;
            }
            if (bars[4]) {
                auto field = [&](int index) {
                    const char* start = index == 0 ? cursor : bars[index - 1] + 1;
                    const char* stop = index < 5 ? bars[index] : cursor + len;
                    return std::string(start, (size_t)(stop - start));
                };
                LiveListener listener{field(3), field(4), field(5) == "any"};
                for (auto& c : listener.proto) c = (char)toupper((unsigned char)c);
                // The app calls its own listener SOCKS5 everywhere else, so a
                // core's `socks` inbound is named the same way here.
                if (listener.proto == "SOCKS") listener.proto = "SOCKS5";
                const std::string core = field(0);
                const std::string position = field(1);
                if (live_groups.empty() || live_groups.back().core != core
                        || live_groups.back().position != position) {
                    live_groups.push_back(LiveGroup{core, position, field(2), {}});
                }
                live_groups.back().lines.push_back(std::move(listener));
            }
            if (!end) break;
            cursor = end + 1;
        }

        ImGui::TextUnformatted("Connection info");
        ImGui::Spacing();
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.10f, 0.16f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.85f, 0.45f, 1.0f));
        // The pane is exactly as tall as the rows it printed.
        //
        // This was a flat 190 px, then "ten text lines" when the font doubled --
        // but the content is variable: one endpoint per listener the session
        // actually opened, plus a header and a line per inbound for every live
        // core instance. A count can only be right for one shape of session, and
        // a wrong one either clips the last rows or leaves a gap under them.
        // AutoResizeY makes the pane measure its own content instead: the height
        // follows what was drawn, and the width still fills the dialog.
        const float body_max_height = std::max(ImGui::GetTextLineHeightWithSpacing(),
            modal_size(10000.0f, 10000.0f).y - ImGui::GetCursorPosY()
            - ImGui::GetFrameHeightWithSpacing() - ImGui::GetStyle().WindowPadding.y * 2.0f);
        ImGui::SetNextWindowSizeConstraints(ImVec2(0.0f, 0.0f), ImVec2(FLT_MAX, body_max_height));
        ImGui::BeginChild("##connection_info_body", ImVec2(0, 0),
                          ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY);

        if (connected) {
            const char* lip = telem.lan_ip;
            const bool share = telem.lan_enabled && lip[0] && strcmp(lip, "127.0.0.1") != 0;
            auto endpoint = [&](const char* backend, const char* kind, unsigned port) {
                if (!port) return;
                if (share)
                    ImGui::TextWrapped("%s local: %s 127.0.0.1:%u | %s LAN: %s %s:%u", backend, kind, port, backend, kind, lip, port);
                else
                    ImGui::TextWrapped("%s local: %s 127.0.0.1:%u", backend, kind, port);
            };
            const int final_backend = !g_app.chain_transports.empty()
                ? transport_carrier(g_app.chain_transports.back()) : telem.backend;
            const char* final_name = final_backend == FCAE_BACKEND_FIREFOX ? "Firefox"
                : final_backend == FCAE_BACKEND_PSIPHON ? "Psiphon"
                : final_backend == FCAE_BACKEND_SINGBOX ? "sing-box"
                : final_backend == FCAE_BACKEND_XRAY ? "Xray" : "Aether";
            // A saved config is named by the user, so show that name.
            const AppState::CoreConfigEntry* final_core =
                g_app.chain_transports.empty() ? g_app.core_config_at(
                    g_app.core_selected >= 0 ? kCoreTransportBase + g_app.core_selected : -1)
                : g_app.core_config_at(g_app.chain_transports.back());
            if (final_core && !final_core->name.empty()) final_name = final_core->name.c_str();
            // Tor answers on its own listeners whenever it is anywhere in the
            // route — the protocol, or any hop of the chain.
            const bool tor_in_route = g_app.protocol == 4
                || std::find(g_app.chain_transports.begin(), g_app.chain_transports.end(), 4)
                       != g_app.chain_transports.end();
            // The core the route ends in answers for itself below, so its
            // settings' single port is never printed *instead* of what the
            // session is actually serving. A hop's listeners are additional:
            // only the exit may stand in for its own settings line.
            const char* exit_core = final_backend == FCAE_BACKEND_XRAY ? "Xray"
                : final_backend == FCAE_BACKEND_SINGBOX ? "sing-box" : nullptr;
            // The exit is the last instance of its core that started, so the
            // user's own name for its saved config belongs to the last group.
            size_t exit_group = live_groups.size();
            bool core_reports = false;
            if (exit_core) {
                for (size_t i = 0; i < live_groups.size(); ++i) {
                    if (live_groups[i].core != exit_core) continue;
                    core_reports = true;
                    exit_group = i;
                }
            }
            if (final_backend != FCAE_BACKEND_PSIPHON && !core_reports) {
                if (g_app.protocol != 4 && g_app.listener_socks_enabled())
                    endpoint(final_name, "SOCKS5",
                             g_app.listener_socks_port() ? g_app.listener_socks_port() : g_app.default_listener_socks_port());
                if (g_app.protocol != 4 && g_app.listener_http_enabled())
                    endpoint(final_name, "HTTP", g_app.listener_http_port());
            }
            // Tor listens on ports of its own wherever it sits in the route, so
            // a core that answers for its listeners never speaks for Tor's.
            if (g_app.tor_http_enabled && tor_in_route)
                endpoint("Tor", "HTTP", g_app.tor_http_port);
            if (tor_in_route)
                endpoint("Tor", "SOCKS5", g_app.tor_socks_port ? g_app.tor_socks_port : 1821);
            if (final_backend == FCAE_BACKEND_PSIPHON) {
                endpoint("Psiphon", "SOCKS5", fcae_psiphon_socks_port());
                endpoint("Psiphon", "HTTP", fcae_psiphon_http_port());
            }
            // Every live core instance, in route order: the header is the
            // instance's place in the route and the name the user gave the saved
            // config it runs -- `1_ Home` -- and the protocol is the core's name
            // for the inbound, never a guess made from the settings. The name
            // comes from the session that started the instance, which is what
            // knows which saved config each hop runs.
            for (size_t i = 0; i < live_groups.size(); ++i) {
                const LiveGroup& group = live_groups[i];
                const char* named = (i == exit_group && final_core && !final_core->name.empty())
                    ? final_core->name.c_str() : group.label.c_str();
                if (*named)
                    ImGui::TextWrapped("%s_ %s", group.position.c_str(), named);
                else
                    ImGui::TextWrapped("%s_", group.position.c_str());
                for (const LiveListener& line : group.lines) {
                    if (share && line.any)
                        ImGui::TextWrapped("    %s 127.0.0.1:%s | LAN: %s:%s",
                            line.proto.c_str(), line.port.c_str(), lip, line.port.c_str());
                    else
                        ImGui::TextWrapped("    %s 127.0.0.1:%s",
                            line.proto.c_str(), line.port.c_str());
                }
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();
        ImGui::Spacing();
        if (ImGui::Button("Close"))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    const float remain = std::max(1.0f, ImGui::GetContentRegionAvail().y);
    ImGui::BeginChild("##tabs_host", ImVec2(0, remain), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {

        if (ImGui::BeginTabItem("Connection")) {
            ImGui::BeginChild("##proto_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Spacing();
            if (ImGui::Button("Protocol")) open_protocol_editor();
            if (!narrow) ImGui::SameLine();
            if (ImGui::Button("Firefox settings")) open_firefox_settings();
            if (!narrow) ImGui::SameLine();
            if (ImGui::Button("Xray & sing-box settings")) open_core_configs();
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "APP SETTINGS");
            ImGui::Checkbox("Auto update check", &g_app.auto_update_check);
            if (ImGui::Checkbox("Also check for pre-releases", &g_app.check_prereleases)) {
                // Channel change takes effect immediately, like the Android
                // switch: without a re-check the panel keeps serving the
                // previous channel's cached result, and while an update is
                // available the "Check for Updates" button is replaced by the
                // result button — there would be no way to re-check without
                // a restart.
                if (!s_update_in_progress) {
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_update_available = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "SHARED SETTINGS");
            ImGui::Text("Mode");
            ImGui::RadioButton("Proxy", &g_app.mode, 0);
            ImGui::RadioButton("TUN",   &g_app.mode, 1);
            ImGui::Checkbox("LAN Sharing", &g_app.lan_sharing);
            bool logging_enabled = g_app.logging_enabled.load(std::memory_order_relaxed);
            if (ImGui::Checkbox("Enable logging##shared", &logging_enabled))
                g_app.logging_enabled.store(logging_enabled, std::memory_order_relaxed);
            ImGui::Spacing();
            ImGui::Text("Outbound IP version (Aether / Firefox)");
            ImGui::RadioButton("IPv4", &g_app.ip_version, 4);
            ImGui::SameLine();
            ImGui::RadioButton("IPv6", &g_app.ip_version, 6);
            ImGui::SameLine();
            ImGui::RadioButton("Dual-Stack", &g_app.ip_version, 10);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Upstream Proxy");
            ImGui::PushItemWidth(-FLT_MIN);
            ImGui::InputTextWithHint("##upstream_proxy", "socks5://host:port or http://host:port",
                                     g_app.upstream_proxy, sizeof(g_app.upstream_proxy));
            ImGui::PopItemWidth();
            {
                // The normalised URL and the message kept from it are the same
                // size, so the copy below cannot truncate; a smaller message
                // buffer would silently cut a long diagnostic in half (and GCC
                // flags exactly that with -Wformat-truncation).
                constexpr std::size_t kProxyUrlCap = 2048;
                static char checked[sizeof(g_app.upstream_proxy)] = {1};
                static char proxy_err[kProxyUrlCap];
                if (strcmp(checked, g_app.upstream_proxy) != 0) {
                    char canonical[kProxyUrlCap];
                    proxy_err[0] = 0;
                    if (!fcae_normalize_upstream_proxy(g_app.upstream_proxy, canonical, sizeof(canonical)))
                        snprintf(proxy_err, sizeof(proxy_err), "%s", canonical);
                    memcpy(checked, g_app.upstream_proxy, sizeof(checked));
                }
                if (proxy_err[0])
                    ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", proxy_err);
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            if (g_app.mode == 1 && ImGui::CollapsingHeader("TUN Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
                ImGui::Text("TUN engine");
                ImGui::SameLine(0, 8);
                FcaeTunEngineInfo tei[4];
                const char* te_names[4];
                uint32_t te_n = fcae_tun_engine_count();
                if (te_n > 4) te_n = 4;
                // The closed combo previews the selected entry, so it is sized to
                // the widest name: "hev-socks5-tunnel" was cut in half the moment
                // it was picked, the popup beside it having always been wide enough.
                float te_widest = 0.0f;
                for (uint32_t i = 0; i < te_n; ++i) {
                    memset(&tei[i], 0, sizeof(tei[i]));
                    tei[i].struct_size = sizeof(tei[i]);
                    tei[i].abi_version = FCAE_ABI_VERSION;
                    te_names[i] = fcae_tun_engine_info(i, &tei[i]) == FCAE_OK ? tei[i].display_name : "?";
                    const float te_name_w = ImGui::CalcTextSize(te_names[i]).x;
                    if (te_name_w > te_widest) te_widest = te_name_w;
                }
                float te_width = te_widest + ImGui::GetStyle().FramePadding.x * 2.0f + ImGui::GetFrameHeight();
                const float te_room = ImGui::GetContentRegionAvail().x;
                if (te_width > te_room) te_width = te_room;
                ImGui::PushItemWidth(te_width);
                int te_sel = (g_app.tun_engine >= 0 && g_app.tun_engine < (int)te_n) ? g_app.tun_engine : 0;
                if (ImGui::Combo("##tun_engine", &te_sel, te_names, (int)te_n)) {
                    g_app.tun_engine = te_sel;
                    fcae_ui_diagnostic(0, uint32_t(te_sel));
                }
                ImGui::PopItemWidth();
                if (te_sel < (int)te_n && !tei[te_sel].available)
                    ImGui::TextColored(ImVec4(1, 0.6f, 0.2f, 1), "%s", tei[te_sel].unavailable_reason);
                ImGui::Spacing();
                ImGui::PushItemWidth(160);
                ImGui::InputText("TUN MTU (bytes)", g_app.tun_mtu, sizeof(g_app.tun_mtu));
                ImGui::PopItemWidth();
                ImGui::Checkbox("Exclude private IPs", &g_app.tun_exclude_private);
                if (g_app.parsed_tun_mtu() == 0xffffffffu)
                    ImGui::TextColored(ImVec4(1, 0.4f, 0.3f, 1), "MTU: 1280..9000 bytes.");
                const char* t2s_logs[] = { "Silent", "Error", "Warn", "Info", "Debug" };
                int t2s_pos = g_app.t2s_log > 0 ? g_app.t2s_log - 1 : 0;
                if (t2s_pos > 4) t2s_pos = 4;
                if (ImGui::Combo("TUN engine log", &t2s_pos, t2s_logs, 5))
                    g_app.t2s_log = t2s_pos + 1;

                ImGui::Spacing();
                ImGui::Text("TUN DNS (comma-separated IP addresses)");
                ImGui::PushItemWidth(-1);
                ImGui::InputTextWithHint("##tun_dns4", "IPv4 DNS — e.g. 1.1.1.1,1.0.0.1", g_app.tun_dns4, sizeof(g_app.tun_dns4));
                ImGui::InputTextWithHint("##tun_dns6", "IPv6 DNS — e.g. 2606:4700:4700::1111", g_app.tun_dns6, sizeof(g_app.tun_dns6));
                ImGui::PopItemWidth();
                if (g_app.tun_engine == 0) {
                    ImGui::Spacing();
                    ImGui::Text("tun2socks TCP settings");
                    ImGui::PushItemWidth(160);
                    ImGui::InputText("TCP send buffer (bytes)", g_app.tun_tcp_sndbuf, sizeof(g_app.tun_tcp_sndbuf));
                    ImGui::InputText("TCP receive buffer (bytes)", g_app.tun_tcp_rcvbuf, sizeof(g_app.tun_tcp_rcvbuf));
                    ImGui::PopItemWidth();
                    ImGui::Checkbox("TCP auto-tuning", &g_app.tun_tcp_auto_tuning);
                    if (!fcae_parse_tcp_buffer_size(g_app.tun_tcp_sndbuf) || !fcae_parse_tcp_buffer_size(g_app.tun_tcp_rcvbuf))
                        ImGui::TextColored(ImVec4(1, 0.4f, 0.3f, 1), "Buffers: 4096..4194304 bytes.");
                }
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "AETHER SETTINGS");
            ImGui::Separator();
            listener_row("Aether SOCKS5", &g_app.socks_enabled, &g_app.socks_port, 1, 65535);
            listener_row("Aether HTTP", &g_app.http_enabled, &g_app.http_port, 1, 65535);
            ImGui::Text("Transport Options");
            ImGui::Checkbox("ECH", &g_app.ech_enabled);
            if (g_app.ech_enabled) {
                ImGui::PushItemWidth(260);
                ImGui::InputTextWithHint("ECH resolver", "udp://1.1.1.1 | tcp:// | https:// DoH",
                                         g_app.ech_dns, sizeof(g_app.ech_dns));
                ImGui::InputTextWithHint("ECH domain", "cloudflare-ech.com",
                                         g_app.ech_domain, sizeof(g_app.ech_domain));
                ImGui::PopItemWidth();
                ImGui::TextDisabled("Without a usable ECH key the tunnel does not start.");
            }
            ImGui::Checkbox("Quick Reconnect", &g_app.quick_reconnect);
            if (g_app.protocol == 6) {
                ImGui::PushItemWidth(260);
                ImGui::InputTextWithHint("Inner WireGuard endpoint", "auto (ip:port)",
                                         g_app.gool_inner, sizeof(g_app.gool_inner));
                ImGui::PopItemWidth();
            }
            ImGui::Spacing();
            ImGui::InputTextWithHint("Force peer (optional)", "ip:port", g_app.force_peer, sizeof(g_app.force_peer));
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            const char* sysprofiles[] = { "Auto", "Low", "Medium", "High" };
            ImGui::Combo("Performance profile", &g_app.sys_profile, sysprofiles, 4);

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            // Verbosity of the aether engine itself, not of this UI's log
            // pane -- the FFI always reports to the host at info.
            const char* engine_logs[] = {
                "Off", "Error", "Warn", "Info", "Debug", "Trace",
            };
            ImGui::Combo("Aether engine log level", &g_app.engine_log, engine_logs, 6);

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.65f, 0.55f, 1.0f, 1.0f), "PSIPHON SETTINGS");
            ImGui::Separator();

            // Region selection with human-readable country names and dynamic discovery
            {
                static char region_buf[2048];
                static std::vector<std::string> codes;
                static double last_poll = 0.0;
                static bool seeded = false;
                if (!seeded) {
                    seeded = true;
                    codes.push_back(""); // Auto
                    const char* q = g_app.psiphon_region_list;
                    while (*q) {
                        const char* comma = strchr(q, ',');
                        size_t len = comma ? (size_t)(comma - q) : strlen(q);
                        if (len > 0) {
                            std::string code(q, len);
                            for (auto& ch : code) ch = (char)toupper((unsigned char)ch);
                            bool found = false;
                            for (const auto& existing : codes) {
                                if (existing == code) { found = true; break; }
                            }
                            if (!found) codes.push_back(code);
                        }
                        if (!comma) break;
                        q = comma + 1;
                    }
                    std::sort(codes.begin() + 1, codes.end());
                }
                double now = ImGui::GetTime();
                if (now - last_poll > 2.0) {
                    last_poll = now;
                    region_buf[0] = '\0';
                    fcae_psiphon_regions(region_buf, (uint32_t)sizeof(region_buf));
                    if (region_buf[0]) {
                        bool changed = false;
                        const char* p = region_buf;
                        while (*p) {
                            const char* comma = strchr(p, ',');
                            size_t len = comma ? (size_t)(comma - p) : strlen(p);
                            if (len > 0) {
                                std::string code(p, len);
                                for (auto& ch : code) ch = (char)toupper((unsigned char)ch);
                                bool found = false;
                                for (const auto& existing : codes) {
                                    if (existing == code) { found = true; break; }
                                }
                                if (!found) {
                                    codes.push_back(code);
                                    changed = true;
                                }
                            }
                            if (!comma) break;
                            p = comma + 1;
                        }
                        if (changed) {
                            std::sort(codes.begin() + 1, codes.end());
                            std::string joined;
                            for (size_t i = 1; i < codes.size(); ++i) {
                                if (i > 1) joined += ",";
                                joined += codes[i];
                            }
                            snprintf(g_app.psiphon_region_list,
                                     sizeof(g_app.psiphon_region_list), "%s", joined.c_str());
                            save_config();
                        }
                    }
                }

                std::string wanted = g_app.psiphon_region;
                for (auto& ch : wanted) ch = (char)toupper((unsigned char)ch);
                int sel = 0;
                for (size_t i = 0; i < codes.size(); ++i) {
                    if (codes[i] == wanted) { sel = (int)i; break; }
                }

                std::vector<std::string> label_strs;
                label_strs.reserve(codes.size());
                for (const auto& c : codes) {
                    label_strs.push_back(psiphon_region_label(c));
                }
                std::vector<const char*> labels;
                labels.reserve(label_strs.size());
                for (const auto& s : label_strs) {
                    labels.push_back(s.c_str());
                }

                if (ImGui::Combo("Psiphon region", &sel, labels.data(), (int)labels.size())) {
                    snprintf(g_app.psiphon_region, sizeof(g_app.psiphon_region),
                             "%s", codes[(size_t)sel].c_str());
                    save_config();
                }
            }

            // Transport picker. Auto lets tunnel-core try its full default
            // set; every other entry restricts it to exactly one protocol.
            // Labels are display forms (-OSSH dropped from the meek/conjure
            // names, INPROXY-WEBRTC- shortened to INPROXY-) so nothing
            // ellipsizes; the config carries the verbatim constants.
            // Indexes match merge_psiphon_transport in ui_render.h.
            {
                static const char* kTransports[] = {
                    "Auto", "SSH", "OSSH", "TLS-OSSH", "SHADOWSOCKS-OSSH",
                    "QUIC-OSSH", "UNFRONTED-MEEK", "UNFRONTED-MEEK-HTTPS",
                    "UNFRONTED-MEEK-TICKET", "FRONTED-MEEK",
                    "FRONTED-MEEK-HTTP", "FRONTED-MEEK-QUIC",
                    "CONJURE", "INPROXY-SSH", "INPROXY-OSSH",
                    "INPROXY-TLS-OSSH", "INPROXY-SHADOWSOCKS",
                    "INPROXY-QUIC-OSSH",
                    "INPROXY-UNFRONTED-MEEK",
                    "INPROXY-UNFRONTED-HTTPS",
                    "INPROXY-UNFRONTED-TICKET",
                    "INPROXY-FRONTED-MEEK",
                    "INPROXY-FRONTED-HTTP",
                    "INPROXY-FRONTED-QUIC",
                };
                ImGui::Combo("Psiphon transport", &g_app.psiphon_transport,
                             kTransports, IM_ARRAYSIZE(kTransports));
            }

            // Psiphon's own listeners, kept off the engine's and Tor's ports.
            // These two carry an int because 0 means "use the built-in value".
            // The shared row works on u16 ports, so the int is bridged here and
            // 0 stays representable by leaving the switch's port field blank.
            {
                ImU16 socks_port = (ImU16)g_app.psiphon_socks_port;
                ImU16 http_port  = (ImU16)g_app.psiphon_http_port;
                listener_row("Psiphon SOCKS5", &g_app.psiphon_socks_enabled, &socks_port, 0, 65535);
                listener_row("Psiphon HTTP", &g_app.psiphon_http_enabled, &http_port, 0, 65535);
                g_app.psiphon_socks_port = socks_port;
                g_app.psiphon_http_port  = http_port;
            }
            ImGui::TextDisabled("0 restores the built-in value (fixed, never auto-picked).");

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.25f, 1.0f), "TOR SETTINGS (AETHER)");
            ImGui::Separator();
            // Tor is a hop, not a routing mode: an exit of the ordered chain is
            // what puts traffic on the Tor network, and the chain decides what
            // that Tor rides on. The engine's own routing modes are gone from
            // here for that reason. The paragraph that used to explain this in
            // the panel is gone: it restated what the chain editor above already
            // shows, and every settings page had one.
            // All Tor knobs stay editable; the engine ignores them when no Tor
            // is in play (to_config normalises).
            {
                ImU16 tor_socks_port = (ImU16)g_app.tor_socks_port;
                ImU16 tor_http_port  = (ImU16)g_app.tor_http_port;
                listener_row("Tor SOCKS5", &g_app.tor_socks_enabled, &tor_socks_port, 0, 65535);
                listener_row("Tor HTTP", &g_app.tor_http_enabled, &tor_http_port, 0, 65535);
                g_app.tor_socks_port = tor_socks_port;
                g_app.tor_http_port  = tor_http_port;
                if (g_app.tor_http_enabled && g_app.tor_http_port == 0) g_app.tor_http_port = 1822;
            }
            const char* tor_bridges[] = { "No bridges", "obfs4", "snowflake", "Custom lines" };
            ImGui::Combo("Bridges", &g_app.tor_bridges, tor_bridges, 4);
            // Writable even with "No bridges": pasted lines override the
            // built-in set once a bridge family is picked; empty = "auto".
            ImGui::InputTextMultiline("##tor_bridge_lines", g_app.tor_bridge_lines,
                                      sizeof(g_app.tor_bridge_lines), ImVec2(0, 60));
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Zero Trust")) {
            ImGui::BeginChild("##zt_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Cloudflare Zero Trust (Teams)");
            ImGui::InputTextWithHint("##team_name", "team-name", g_app.team_name, sizeof(g_app.team_name));
            ImGui::SameLine();
            ImGui::Text("Team");
            ImGui::Spacing();
            ImGui::Text("Authentication (choose one):");
            ImGui::InputTextWithHint("##access_token", "JWT token from enrolment page", g_app.access_token, sizeof(g_app.access_token));
            ImGui::TextDisabled("Access Token (copy token=... from login page)");
            ImGui::Spacing();
            ImGui::Text("--- or Service Token ---");
            ImGui::InputTextWithHint("##access_client_id", "Client ID", g_app.access_client_id, sizeof(g_app.access_client_id));
            ImGui::InputTextWithHint("##access_client_secret", "Client Secret", g_app.access_client_secret, sizeof(g_app.access_client_secret));
            ImGui::Spacing();
            ImGui::Text("--- or Email OTP ---");
            ImGui::InputTextWithHint("##access_email", "user@example.com", g_app.access_email, sizeof(g_app.access_email));
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Routes")) {
            ImGui::BeginChild("##routes_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Routing Rules File (Aether only)");
            ImGui::InputTextWithHint("##routes_file", "path/to/routes.txt", g_app.routes_file, sizeof(g_app.routes_file));
            ImGui::TextDisabled("Format: [block] / [direct] sections with domain, IP, CIDR, port rules.");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("Inline Routing Rules (Aether only; comma-separated)");
            ImGui::PushItemWidth(-1);
            ImGui::InputTextMultiline("##routes_inline", g_app.routes_inline, sizeof(g_app.routes_inline),
                ImVec2(0, 100), ImGuiInputTextFlags_AllowTabInput);
            ImGui::PopItemWidth();
            ImGui::TextDisabled("Format: [direct]ip:190.9.2.4,192.33.45.6:400,domain.com [block]gazo.com,10.0.0.0/8,...");
            ImGui::Spacing();
            ImGui::TextWrapped("Example:\n[block]\nads.example\nkeyword:tracker\n\n[direct]\nprivate\n10.0.0.0/8\nport:3000-3010");
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Obfuscation")) {
            ImGui::BeginChild("##obf_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Noize Profile");
            const char* profiles[] = { "off", "light", "balanced", "aggressive", "firewall", "gfw" };
            const int kNoizeCount = IM_ARRAYSIZE(profiles);
            int idx = 2; // balanced
            for (int i = 0; i < kNoizeCount; i++)
                if (strcmp(g_app.noize_profile, profiles[i]) == 0) { idx = i; break; }
            if (ImGui::Combo("Profile", &idx, profiles, kNoizeCount))
                snprintf(g_app.noize_profile, sizeof(g_app.noize_profile), "%s", profiles[idx]);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("TLS Fragmentation");
            ImGui::Checkbox("Enable", &g_app.fragment_enabled);
            if (g_app.fragment_enabled) {
                ImGui::PushItemWidth(180);
                ImGui::SliderInt("Chunk Min (B)", &g_app.frag_min_size, 8, 64);
                ImGui::SliderInt("Chunk Max (B)", &g_app.frag_max_size, 16, 128);
                ImGui::SliderInt("Delay Min (ms)", &g_app.frag_min_delay, 0, 20);
                ImGui::SliderInt("Delay Max (ms)", &g_app.frag_max_delay, 1, 50);
                ImGui::PopItemWidth();
                ImGui::Checkbox("Split inside SNI", &g_app.fragment_sni);
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("TLS Fingerprint");
            ImGui::Checkbox("Verify Aether TLS certificates", &g_app.tls_verify);
            ImGui::Checkbox("Disable GREASE", &g_app.disable_grease);
            ImGui::Checkbox("Enable GREASE signature algorithms", &g_app.enable_grease_sigalgs);
            ImGui::Checkbox("Enable ECH GREASE", &g_app.enable_ech_grease);
            ImGui::Checkbox("Disable OCSP stapling", &g_app.disable_ocsp_stapling);
            ImGui::Checkbox("Disable SCT", &g_app.disable_sct);
            ImGui::Checkbox("Disable session tickets", &g_app.disable_session_ticket);
            ImGui::Checkbox("Disable extension permutation", &g_app.disable_extension_permutation);
            ImGui::PushItemWidth(-1);
            ImGui::InputTextWithHint("##tls_ciphers", "TLS 1.2 ciphers (default: Chrome's)",
                                     g_app.tls_ciphers, sizeof(g_app.tls_ciphers));
            ImGui::InputTextWithHint("##tls13_ciphers", "TLS 1.3 ciphers", g_app.tls13_ciphers, sizeof(g_app.tls13_ciphers));
            ImGui::InputTextWithHint("##tls_groups", "TLS groups", g_app.tls_groups, sizeof(g_app.tls_groups));
            ImGui::InputTextWithHint("##tls_key_shares", "TLS key-share groups", g_app.tls_key_shares, sizeof(g_app.tls_key_shares));
            ImGui::InputTextWithHint("##tls_sigalgs", "TLS signature algorithms", g_app.tls_sigalgs, sizeof(g_app.tls_sigalgs));
            ImGui::InputTextWithHint("##tls_cert_compression", "Certificate compression (zlib:brotli:zstd)", g_app.tls_cert_compression, sizeof(g_app.tls_cert_compression));
            ImGui::InputTextWithHint("##tls_alps", "ALPS mode (new or old)", g_app.tls_alps, sizeof(g_app.tls_alps));
            ImGui::InputTextWithHint("##tls_trust_anchors", "Trust-anchor OIDs", g_app.tls_trust_anchors, sizeof(g_app.tls_trust_anchors));
            ImGui::InputTextWithHint("##tls_server_padding", "Server padding (0-65535)", g_app.tls_server_padding, sizeof(g_app.tls_server_padding));
            ImGui::PopItemWidth();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Scanner")) {
            ImGui::BeginChild("##scan_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Spacing();
            const char* modes[] = { "Turbo", "Balanced", "Thorough", "Verified", "Ironclad" };
            if (g_app.scan_mode > 4) g_app.scan_mode = 1;
            ImGui::Combo("Scan mode", &g_app.scan_mode, modes, 5);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("MASQUE SNI");
            ImGui::InputText("##sni", g_app.sni, sizeof(g_app.sni));
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("WARP API");
            ImGui::InputTextWithHint("##api_address", "Address (default: built-in)",
                                     g_app.api_address, sizeof(g_app.api_address));
            ImGui::InputTextWithHint("##api_host", "HTTP host (optional)",
                                     g_app.api_host, sizeof(g_app.api_host));
            ImGui::InputTextWithHint("##api_sni", "TLS SNI (optional)",
                                     g_app.api_sni, sizeof(g_app.api_sni));
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Exit Countries");
            ImGui::InputTextWithHint("##exit_loc", "any (DE,SE accepts / !IR,RU refuses)",
                                     g_app.exit_loc, sizeof(g_app.exit_loc));
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        s_log_scroll_pending = false;
        if (ImGui::BeginTabItem("Logs")) {
            static bool follow_tail = true;
            static bool manual_scroll_last_frame = false;
            static uint64_t rendered_revision = 0;
            if (ImGui::Checkbox("Auto-scroll", &g_app.auto_scroll))
                follow_tail = g_app.auto_scroll;
            ImGui::SameLine(0, 12);
            if (ImGui::Button("Clear")) {
                g_app.clear_logs();
                follow_tail = true;
            }
            ImGui::SameLine(0, 8);
            if (ImGui::Button("Copy All")) {
                std::string all = g_app.logs_as_text();
                ImGui::SetClipboardText(all.c_str());
                snprintf(g_app.copy_status, sizeof(g_app.copy_status), "Copied!");
            }
            if (g_app.copy_status[0]) {
                ImGui::SameLine(0, 8);
                ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", g_app.copy_status);
            }
            ImGui::Spacing();

            // Reserve a real footer below the log rows so the Latest control
            // never covers the newest lines, including on short desktop windows.
            const float log_footer_h = ImGui::GetFrameHeightWithSpacing()
                + 2.0f * ImGui::GetStyle().WindowPadding.y + 4.0f;
            const float log_height = std::max(1.0f, ImGui::GetContentRegionAvail().y
                - log_footer_h - ImGui::GetStyle().ItemSpacing.y);
            ImGui::BeginChild("##log", ImVec2(0, log_height), ImGuiChildFlags_Borders,
                              ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // Take a thread-safe snapshot of the logs for rendering.
            // This avoids a data race with the FFI callback thread which
            // calls add_log() concurrently.
            static uint64_t revision = ~0ULL;
            static std::vector<std::pair<int, std::string>> logs_snapshot;
            g_app.sync_logs(revision, logs_snapshot);

            const bool manual_scroll =
                (ImGui::IsWindowHovered() &&
                    (ImGui::GetIO().MouseWheel != 0.0f || ImGui::IsMouseDragging(0))) ||
                (ImGui::IsWindowFocused() &&
                    (ImGui::IsKeyPressed(ImGuiKey_PageUp) || ImGui::IsKeyPressed(ImGuiKey_PageDown) ||
                     ImGui::IsKeyPressed(ImGuiKey_Home) || ImGui::IsKeyPressed(ImGuiKey_End) ||
                     ImGui::IsKeyPressed(ImGuiKey_UpArrow) || ImGui::IsKeyPressed(ImGuiKey_DownArrow)));
            if (manual_scroll || manual_scroll_last_frame) {
                follow_tail = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f;
            }
            manual_scroll_last_frame = manual_scroll;
            const bool should_scroll = g_app.auto_scroll && follow_tail && !manual_scroll &&
                !ImGui::IsMouseDown(0) && !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId);
            if (manual_scroll || (should_scroll &&
                (revision != rendered_revision || ImGui::GetScrollY() < ImGui::GetScrollMaxY() - 1.0f))) {
                s_log_scroll_pending = true;
            }
            rendered_revision = revision;

            ImGuiListClipper clipper;
            clipper.Begin((int)logs_snapshot.size());
            // SetScrollHereY must refer to the actual final row, not whichever
            // row the clipper last happened to render in the old viewport.
            if (should_scroll && !logs_snapshot.empty())
                clipper.IncludeItemByIndex((int)logs_snapshot.size() - 1);
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    auto& [lvl, msg] = logs_snapshot[(size_t)i];
                    ImVec4 c;
                    switch (lvl) {
                        case 1:  c = ImVec4(1.0f, 0.35f, 0.35f, 1.0f); break;
                        case 2:  c = ImVec4(1.0f, 0.80f, 0.25f, 1.0f); break;
                        case 3:  c = ImVec4(0.40f, 0.75f, 1.00f, 1.0f); break;
                        default: c = ImVec4(0.75f, 0.75f, 0.78f, 1.0f); break;
                    }
                    ImGui::PushStyleColor(ImGuiCol_Text, c);
                    ImGui::PushID(i);
                    ImGui::TextUnformatted(msg.empty() ? " " : msg.c_str());
                    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                        ImGui::SetClipboardText(msg.c_str());
                        snprintf(g_app.copy_status, sizeof(g_app.copy_status), "Line copied");
                    }
                    if (ImGui::BeginPopupContextItem("log_ctx")) {
                        if (ImGui::MenuItem("Copy line")) {
                            ImGui::SetClipboardText(msg.c_str());
                            snprintf(g_app.copy_status, sizeof(g_app.copy_status), "Line copied");
                        }
                        if (ImGui::MenuItem("Copy all")) {
                            std::string all = g_app.logs_as_text();
                            ImGui::SetClipboardText(all.c_str());
                            snprintf(g_app.copy_status, sizeof(g_app.copy_status), "Copied!");
                        }
                        ImGui::EndPopup();
                    }
                    ImGui::PopID();
                    ImGui::PopStyleColor();
                    if (should_scroll && i == (int)logs_snapshot.size() - 1)
                        ImGui::SetScrollHereY(1.0f);
                }
            }
            ImGui::EndChild();
            // Fixed footer, below and outside the scrolled/clipped log rows.
            ImGui::BeginChild("##log_footer", ImVec2(0, log_footer_h), ImGuiChildFlags_None);
            if (ImGui::Button("Latest##logs")) {
                g_app.auto_scroll = true;
                follow_tail = true;
                manual_scroll_last_frame = false;
                s_log_scroll_pending = true;
            }
            ImGui::SameLine();
            ImGui::TextDisabled("Scroll up to pause; Latest resumes following");
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::EndChild();

    render_protocol_editor();
    s_firefox_captcha_embedded = false;
    render_core_configs();
    render_firefox_settings();
    render_firefox_add_account();
    render_firefox_code_prompt();
    render_firefox_captcha_popup();

    ImGui::PopStyleVar(2);
    ImGui::End();
}
