#include "ui_text_input.h"
#include "ui_media_fit.h"
#include "ui_render.h"
#include "account_request_status.h"
#if !defined(ANDROID)
#include "platform_app_routing_ui.h"
#endif
#if defined(FCAE_IOS)
#include "Platform.h"
#define fcae_start ios_start
#define fcae_stop ios_stop
#define fcae_stop_begin ios_stop
#define fcae_get_telemetry ios_telemetry
#define fcae_live_listeners ios_live_listeners
#define fcae_psiphon_regions ios_regions
#define fcae_tun_paused ios_tun_paused
#define fcae_pause_tun ios_tun_control
#define fcae_resume_tun ios_tun_control
#endif
#if !defined(ANDROID) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && !defined(FCAE_IOS)
#include "imgui_horizontal_drag.h"
#endif
#if defined(ANDROID)
#include "android_ui.h"
#include "imgui_internal.h"
#endif
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
#include <ctime>
#include <cwchar>
#include <utility>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <commdlg.h>
#include "windows_privilege.h"
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#else
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
extern "C" void fcae_backend_set_log_level(uint32_t backend, uint32_t level);
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
static void set_save_status_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(g_app.save_status, sizeof(g_app.save_status), format, args);
    va_end(args);
    ++s_save_status_revision;
    ui_request_redraw();
}
static bool s_loaded_chain_transports = false;
static int s_loaded_transport_base = 11;
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
static std::atomic<HANDLE> s_elevation_child{nullptr};
static std::atomic<bool> s_elevation_pending{false};
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
static uint64_t s_logs_revision = ~0ULL;
static std::vector<std::pair<int, std::string>> s_logs_snapshot;

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
    // Do not immediately repopulate frames if a hidden platform happens to
    // poll the UI. The service retains the current still for later restoration.
    if (!ui_active) {
        if (card_changed) ui_request_redraw();
        return;
    }
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
static uint64_t s_frame_log_revision = 0;
static bool s_log_scroll_pending = false;

// All visible UI hosts target 60 FPS, including idle and animations.
static constexpr unsigned kUiFrameIntervalMs = 17;

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
        h = fnv_value(h, entry.group);
    }
    h = fnv_value(h, (int)g_app.core_groups.size());
    for (const AppState::CoreGroupEntry& group : g_app.core_groups) {
        h = fnv_cstr(h, group.name.c_str());
        h = fnv_cstr(h, group.url.c_str());
        h = fnv_value(h, group.backend);
        h = fnv_value(h, group.updated);
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
    h = fnv_value(h, g_app.firefox_log);
    h = fnv_value(h, g_app.urnetwork_log);
    h = fnv_value(h, g_app.ur_socks_port);
    h = fnv_value(h, g_app.ur_http_port);
    h = fnv_value(h, g_app.ur_socks_enabled);
    h = fnv_value(h, g_app.ur_http_enabled);
    h = fnv_value(h, g_app.tor_socks_port);
    h = fnv_cstr(h, g_app.psiphon_region);
    h = fnv_cstr(h, g_app.psiphon_region_list);
    h = fnv_value(h, g_app.psiphon_transport);
    h = fnv_cstr(h, g_app.psiphon_data_dir);
    h = fnv_value(h, g_app.psiphon_socks_port);
    h = fnv_value(h, g_app.psiphon_http_port);
    h = fnv_value(h, g_app.mode);
    h = fnv_value(h, g_app.tun_engine);
    h = fnv_value(h, g_app.ios_app_draft_mode);
    for (const auto& id : g_app.ios_app_draft_ids) h = fnv_cstr(h, id.c_str());
    h = fnv_value(h, g_app.desktop_app_mode);
    h = fnv_cstr(h, g_app.desktop_app_platform.c_str());
    h = fnv_cstr(h, g_app.desktop_app_provider.c_str());
    for (const auto& path : g_app.desktop_app_paths) h = fnv_cstr(h, path.c_str());
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
    h = fnv_value(h, g_app.mihomo_socks_port);
    h = fnv_value(h, g_app.singbox_http_port);
    h = fnv_value(h, g_app.mihomo_http_port);
    h = fnv_value(h, g_app.tor_http_port);
    h = fnv_value(h, g_app.tor_http_enabled);
    h = fnv_value(h, g_app.socks_enabled);
    h = fnv_value(h, g_app.http_enabled);
    h = fnv_value(h, g_app.firefox_socks_enabled);
    h = fnv_value(h, g_app.firefox_http_enabled);
    h = fnv_value(h, g_app.xray_socks_enabled);
    h = fnv_value(h, g_app.xray_http_enabled);
    h = fnv_value(h, g_app.singbox_socks_enabled);
    h = fnv_value(h, g_app.mihomo_socks_enabled);
    h = fnv_value(h, g_app.singbox_http_enabled);
    h = fnv_value(h, g_app.mihomo_http_enabled);
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
    h = fnv_cstr(h, g_app.routes_inline);
    h = fnv_cstr(h, g_app.destination_rows);
    h = fnv_cstr(h, std::to_string(g_app.destination_mode).c_str());
    return h;
}

static bool s_error_detail_visible = false;



// Until this time the telemetry is read at the short pace below: a command was
// just given, and the state that answers it is what the user is looking for.
static double s_telemetry_soon_until = 0.0;

/// Pull telemetry from the FFI when due: once per second, matching the
/// engine's 1 s rate window — the published rates are bytes-per-second
/// measured over exactly that window, so faster polling would only repaint
/// the same numbers. Throttled by g_app.last_telem_t, so the in-frame poll
/// and this one never double-poll.
///
/// The state is not a rate. While a session is coming up, right after a
/// command, and for the first seconds of a session whose round trip is not
/// measured yet, it is read ten times a second: at one read a second
/// "connected" reached the screen up to a second after the engine had said so,
/// by which time the round trip was usually there as well.
static void ui_poll_telemetry(double now) {
    const FcaeState shown = g_app.telem.state;
    const bool arriving = shown == FCAE_STATE_PROVISIONING || shown == FCAE_STATE_SCANNING
                       || shown == FCAE_STATE_CONNECTING || shown == FCAE_STATE_RECONNECTING;
    const bool measuring = shown == FCAE_STATE_CONNECTED && g_app.telem.rtt_ms == 0
                        && g_app.telem.uptime_secs < 10;
    const bool commanded = now < s_telemetry_soon_until || g_app.start_busy.load();
    const double interval = (arriving || measuring || commanded) ? 0.1 : 1.0;
    const bool stop_refresh = g_app.ffi_state.load() == FCAE_STATE_DISCONNECTED
                            && g_app.telem.state != FCAE_STATE_DISCONNECTED;
    if (!stop_refresh && now - g_app.last_telem_t < interval) return;

    FcaeTelemetry telem = {};
    telem.struct_size = sizeof(telem);
    telem.abi_version = FCAE_ABI_VERSION;
    fcae_get_telemetry(&telem);
#if defined(ANDROID)
    android_ui_telemetry(telem);
#endif
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
#if defined(ANDROID)
    if (!g_app.redraw_requested.exchange(true)) android_ui_wake();
#else
    g_app.redraw_requested.store(true);
#endif
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

bool ui_runtime_ready() {
    return s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Ready;
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
    // The elevated child has presented its first frame before this is armed.
    if (GetTickCount() - at >= kHandoffWindowMs) {
        s_elevation_handoff_at.store(0, std::memory_order_relaxed);
        HANDLE child = s_elevation_child.exchange(nullptr, std::memory_order_acq_rel);
        if (child) {
            const DWORD state = WaitForSingleObject(child, 0);
            DWORD exit_code = 0;
            if (state != WAIT_TIMEOUT) {
                GetExitCodeProcess(child, &exit_code);
                CloseHandle(child);
                fcae_ui_diagnostic(10, exit_code);
                g_app.add_log(FCAE_LOG_ERROR, "[ui] Administrator copy exited during handoff; keeping this window open. Check deps/logs.txt.");
                s_elevation_pending.store(false, std::memory_order_release);
                return;
            }
            CloseHandle(child);
        }
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

// Visibility transitions are delivered on the UI/render thread. The sponsor
// service owns its media independently; these vectors are only UI copies.
void ui_set_window_visible(bool visible) {
    s_ui_window_visible.store(visible);
    fcae_sponsor_set_ui_active(visible);
    s_sponsor_ui_active_sent = visible ? 1 : 0;
    if (!visible) {
        // Release regenerable CPU-side frames without stopping a live session
        // or discarding editor/account state. poll_sponsor copies the current
        // frames again when the UI becomes visible.
        std::vector<uint8_t>{}.swap(s_sponsor_rgba);
        std::vector<uint8_t>{}.swap(s_sponsor_background_rgba);
        s_sponsor_loaded_foreground_generation = 0;
        s_sponsor_loaded_background_generation = 0;
    }
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
        deadline = 0.0;
    }
}

static void firefox_poll_captcha();
static void firefox_poll_job();
static void firefox_poll_background();
static void firefox_expire_status(double now);
static void expire_core_import_status(double now);
static bool firefox_requests_working();
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
        return true;
    }

    autosave_config(now);

    // Telemetry and locally animated sponsor frames change without input.
    ui_poll_telemetry(now);
    update_error_detail(now);
    expire_save_status(now);
    expire_core_import_status(now);
    poll_sponsor();
    firefox_poll_captcha();
    firefox_poll_job();
    firefox_poll_background();
    firefox_expire_status(now);
    firefox_refresh_usage(now);
#if defined(ANDROID)
    s_tun_paused = android_ui_paused();
#else
    s_tun_paused = fcae_tun_paused();
#endif
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

    // Keep processing ImGui even when app content is unchanged: deferred
    // input, caret, hover and animations all share the same 60 FPS cadence.
    return true;
}

unsigned ui_sleep_ms() {
    return kUiFrameIntervalMs;
}

void ui_note_frame_drawn() {
    // Preserve a wake if logs arrived while the frame was being built.
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
#if defined(FCAE_IOS)
    return ios_data_dir();
#elif defined(ANDROID)
    return android_ui_data_dir();
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
#if defined(FCAE_IOS)
    return ios_data_dir();
#elif defined(__APPLE__)
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
#if defined(FCAE_IOS)
    return ios_data_dir();
#elif defined(_WIN32)
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

// Where the background pictures the user added are kept.
static std::string background_dir() {
    return join_path(data_dir(), "backgrounds");
}

// `name` when it is a plain file name, "" otherwise. The settings file is text
// anyone can edit, and a name read from it is joined onto that folder.
static std::string background_file_name(const std::string& name) {
    if (name.empty() || name.size() > 96 || name == "." || name == "..") return {};
    for (unsigned char c : name)
        if (c < 0x20 || c == '/' || c == '\\' || c == ':') return {};
    return name;
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
/// Upper bound on subscription groups, for the same reason as kMaxCoreConfigs:
/// a corrupt file cannot ask for an unbounded resize.
static constexpr int kMaxCoreGroups = 64;

static bool transport_is_core(int transport);
static int current_transport();
static void apply_transport(int transport);

/// Tor can run alone or as a chain hop. Psiphon can run as a standalone backend
/// or as an exit behind another carrier.
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
    else if (key == "core_transport_base") s_loaded_transport_base = atoi(val.c_str());
    else if (key == "chain_transports") {
        g_app.chain_transports = parse_chain_transports(val);
        s_loaded_chain_transports = true;
    } else if (key == "chain_count") s_loaded_legacy_chain_count = atoi(val.c_str());
    else if (key == "chain_exit_0") s_loaded_legacy_chain_exits[0] = atoi(val.c_str());
    else if (key == "chain_exit_1") s_loaded_legacy_chain_exits[1] = atoi(val.c_str());
    else if (key == "chain_exit_2") s_loaded_legacy_chain_exits[2] = atoi(val.c_str());
    else if (key == "urnetwork_socks_port") g_app.ur_socks_port = (uint16_t)parse_port(val, g_app.ur_socks_port);
    else if (key == "urnetwork_http_port") g_app.ur_http_port = (uint16_t)parse_port(val, g_app.ur_http_port);
    else if (key == "urnetwork_socks_enabled") g_app.ur_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "urnetwork_http_enabled") g_app.ur_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "background_mode") {
        snprintf(g_app.background_mode, sizeof(g_app.background_mode), "%s",
            val == "none" ? "none" : val == "image" ? "image" : "mountain");
    }
    else if (key == "background_image") g_app.background_image = background_file_name(val);
    else if (key == "background_saved") {
        // One line per picture the user added.
        const std::string name = background_file_name(val);
        if (!name.empty() && std::find(g_app.background_images.begin(), g_app.background_images.end(), name)
                == g_app.background_images.end())
            g_app.background_images.push_back(name);
    }
    else if (key == "dns_firewall") g_app.dns_firewall = (val != "0");
    else if (key == "firefox_account_id") snprintf(g_app.firefox_account_id, sizeof(g_app.firefox_account_id), "%s", val.c_str());
    else if (key == "firefox_location") snprintf(g_app.firefox_location, sizeof(g_app.firefox_location), "%s", val.c_str());
    else if (key == "firefox_server") snprintf(g_app.firefox_server, sizeof(g_app.firefox_server), "%s", val.c_str());
    else if (key == "firefox_log") g_app.firefox_log = std::max(0, std::min(4, atoi(val.c_str())));
    else if (key == "urnetwork_log") g_app.urnetwork_log = std::max(0, std::min(4, atoi(val.c_str())));
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
    else if (key == "ios_app_draft_mode") g_app.ios_app_draft_mode = std::clamp(atoi(val.c_str()), 0, 2);
    else if (key == "ios_app_draft_id" && g_app.ios_app_draft_ids.size() < 8192) {
        auto id = core_text_decode(val);
        if (!id.empty() && id.size() <= 255) g_app.ios_app_draft_ids.push_back(std::move(id));
    }
    else if (key == "desktop_app_mode") g_app.desktop_app_mode = std::clamp(atoi(val.c_str()), 0, 2);
    else if (key == "desktop_app_provider" && val.size() <= 32) g_app.desktop_app_provider = val;
    else if (key == "desktop_app_platform" && val.size() <= 32) g_app.desktop_app_platform = val;
    else if (key == "desktop_app_path" && g_app.desktop_app_paths.size() < 8192) {
        auto path = core_text_decode(val);
        if (!path.empty() && path.size() <= 32768) g_app.desktop_app_paths.push_back(std::move(path));
    }
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
    else if (key == "mihomo_socks_port") g_app.mihomo_socks_port = (uint16_t)parse_port(val, g_app.mihomo_socks_port);
    else if (key == "singbox_http_port") g_app.singbox_http_port = (uint16_t)parse_port(val, g_app.singbox_http_port);
    else if (key == "mihomo_http_port") g_app.mihomo_http_port = (uint16_t)parse_port(val, g_app.mihomo_http_port);
    else if (key == "xray_socks_enabled") g_app.xray_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "xray_http_enabled") g_app.xray_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "singbox_socks_enabled") g_app.singbox_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "mihomo_socks_enabled") g_app.mihomo_socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "singbox_http_enabled") g_app.singbox_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "mihomo_http_enabled") g_app.mihomo_http_enabled = atoi(val.c_str()) != 0;
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
    else if (key == "destination_mode") { char* end=nullptr; long mode=strtol(val.c_str(),&end,10); g_app.destination_mode=end!=val.c_str() && *end==0 && mode>=0 && mode<=2 ? (int)mode : 0; }
    else if (key == "destination_rows_hex") decode_config_text(val,g_app.destination_rows,sizeof(g_app.destination_rows));
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
        else if (strcmp(end, "_backend") == 0) entry.backend = std::clamp(atoi(val.c_str()), 0, 2);
        else if (strcmp(end, "_group") == 0) entry.group = atoi(val.c_str());
        else if (strcmp(end, "_text") == 0) {
            std::string text = core_text_decode(val);
            if (text.size() <= kMaxCoreConfigText) entry.text = std::move(text);
        }
    }
    else if (key.rfind("core_group", 0) == 0) {
        // core_group<index>_<field>, read the way core_config<index>_<field> is.
        const char* cursor = key.c_str() + strlen("core_group");
        char* end = nullptr;
        const long index = strtol(cursor, &end, 10);
        if (!end || end == cursor || index < 0 || index >= kMaxCoreGroups) return;
        if (g_app.core_groups.size() < (size_t)index + 1)
            g_app.core_groups.resize((size_t)index + 1);
        AppState::CoreGroupEntry& group = g_app.core_groups[(size_t)index];
        if (strcmp(end, "_name") == 0 && val.size() <= kMaxCoreConfigName) group.name = val;
        else if (strcmp(end, "_backend") == 0) group.backend = std::clamp(atoi(val.c_str()), 0, 2);
        else if (strcmp(end, "_updated") == 0) group.updated = (int64_t)strtoll(val.c_str(), nullptr, 10);
        else if (strcmp(end, "_url") == 0) {
            std::string url = core_text_decode(val);
            if (url.size() <= 4096) group.url = std::move(url);
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
    fprintf(f, "background_mode=%s\n", g_app.background_mode);
    fprintf(f, "background_image=%s\n", g_app.background_image.c_str());
    for (const std::string& name : g_app.background_images) fprintf(f, "background_saved=%s\n", name.c_str());
    fprintf(f, "dns_firewall=%d\n", g_app.dns_firewall ? 1 : 0);
    fprintf(f, "backend=%d\n", g_app.backend);
    fprintf(f, "core_transport_base=%d\n", kCoreTransportBase);
    fprintf(f, "chain_transports=%s\n", join_chain_transports(g_app.chain_transports).c_str());
    fprintf(f, "core_selected=%d\n", g_app.core_selected);
    for (size_t i = 0; i < g_app.core_configs.size(); ++i) {
        const AppState::CoreConfigEntry& entry = g_app.core_configs[i];
        fprintf(f, "core_config%zu_name=%s\n", i, entry.name.c_str());
        fprintf(f, "core_config%zu_backend=%d\n", i, entry.backend);
        fprintf(f, "core_config%zu_text=%s\n", i, core_text_encode(entry.text).c_str());
        if (entry.group >= 0) fprintf(f, "core_config%zu_group=%d\n", i, entry.group);
    }
    for (size_t i = 0; i < g_app.core_groups.size(); ++i) {
        const AppState::CoreGroupEntry& group = g_app.core_groups[i];
        fprintf(f, "core_group%zu_name=%s\n", i, group.name.c_str());
        fprintf(f, "core_group%zu_url=%s\n", i, core_text_encode(group.url).c_str());
        fprintf(f, "core_group%zu_backend=%d\n", i, group.backend);
        fprintf(f, "core_group%zu_updated=%lld\n", i, (long long)group.updated);
    }
    fprintf(f, "firefox_account_id=%s\n", g_app.firefox_account_id);
    fprintf(f, "firefox_location=%s\n", g_app.firefox_location);
    fprintf(f, "firefox_server=%s\n", g_app.firefox_server);
    fprintf(f, "firefox_log=%d\n", g_app.firefox_log);
    fprintf(f, "urnetwork_log=%d\n", g_app.urnetwork_log);
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
    fprintf(f, "ios_app_draft_mode=%d\n", g_app.ios_app_draft_mode);
    for (const auto& id : g_app.ios_app_draft_ids) fprintf(f, "ios_app_draft_id=%s\n", core_text_encode(id).c_str());
    fprintf(f, "desktop_app_mode=%d\n", g_app.desktop_app_mode);
    fprintf(f, "desktop_app_platform=%s\n", g_app.desktop_app_platform.c_str());
    fprintf(f, "desktop_app_provider=%s\n", g_app.desktop_app_provider.c_str());
    for (const auto& path : g_app.desktop_app_paths) fprintf(f, "desktop_app_path=%s\n", core_text_encode(path).c_str());
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
    fprintf(f, "urnetwork_socks_port=%u\n", (unsigned)g_app.ur_socks_port);
    fprintf(f, "urnetwork_http_port=%u\n", (unsigned)g_app.ur_http_port);
    fprintf(f, "urnetwork_socks_enabled=%d\n", g_app.ur_socks_enabled ? 1 : 0);
    fprintf(f, "urnetwork_http_enabled=%d\n", g_app.ur_http_enabled ? 1 : 0);
    fprintf(f, "firefox_socks_port=%u\n", (unsigned)g_app.firefox_socks_port);
    fprintf(f, "firefox_http_port=%u\n", (unsigned)g_app.firefox_http_port);
    fprintf(f, "xray_socks_port=%u\n", (unsigned)g_app.xray_socks_port);
    fprintf(f, "xray_http_port=%u\n", (unsigned)g_app.xray_http_port);
    fprintf(f, "singbox_socks_port=%u\n", (unsigned)g_app.singbox_socks_port);
    fprintf(f, "mihomo_socks_port=%u\n", (unsigned)g_app.mihomo_socks_port);
    fprintf(f, "singbox_http_port=%u\n", (unsigned)g_app.singbox_http_port);
    fprintf(f, "mihomo_http_port=%u\n", (unsigned)g_app.mihomo_http_port);
    fprintf(f, "tor_http_port=%u\n", (unsigned)g_app.tor_http_port);
    fprintf(f, "tor_http_enabled=%d\n", g_app.tor_http_enabled ? 1 : 0);
    fprintf(f, "socks_enabled=%d\n", g_app.socks_enabled ? 1 : 0);
    fprintf(f, "aether_http_unified=%d\n", g_app.http_enabled ? 1 : 0);
    fprintf(f, "firefox_socks_enabled=%d\n", g_app.firefox_socks_enabled ? 1 : 0);
    fprintf(f, "firefox_http_unified=%d\n", g_app.firefox_http_enabled ? 1 : 0);
    fprintf(f, "xray_socks_enabled=%d\n", g_app.xray_socks_enabled ? 1 : 0);
    fprintf(f, "xray_http_enabled=%d\n", g_app.xray_http_enabled ? 1 : 0);
    fprintf(f, "singbox_socks_enabled=%d\n", g_app.singbox_socks_enabled ? 1 : 0);
    fprintf(f, "mihomo_socks_enabled=%d\n", g_app.mihomo_socks_enabled ? 1 : 0);
    fprintf(f, "singbox_http_enabled=%d\n", g_app.singbox_http_enabled ? 1 : 0);
    fprintf(f, "mihomo_http_enabled=%d\n", g_app.mihomo_http_enabled ? 1 : 0);
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
    fprintf(f, "routes_inline_hex=%s\n", encode_config_text(g_app.routes_inline).c_str());
    fprintf(f, "destination_mode=%d\n", g_app.destination_mode);
    fprintf(f, "destination_rows_hex=%s\n", encode_config_text(g_app.destination_rows).c_str());
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
#if defined(ANDROID)
    android_ui_save_session(false);
#endif
    if (!quiet) {
        g_app.add_log(4, ("[ui] config saved: " + path).c_str());
    }
    return true;
}

#if defined(ANDROID) || defined(FCAE_IOS)
#if defined(ANDROID)
void android_ui_flush_settings() {
#else
void ios_flush_settings() {
#endif
    if (s_runtime_init.load(std::memory_order_acquire) == RuntimeInitState::Ready)
        save_config(true);
}
#endif

static uint64_t s_config_observed = 0;
static uint64_t s_config_persisted = 0;
static double s_config_changed_at = 0;
static double s_config_retry_at = 0;
static bool s_config_tracking = false;

static void autosave_config(double now) {
    // Large pasted core configs otherwise get re-hashed at display refresh
    // rate, on top of rendering. Saving still has its existing 600ms debounce,
    // and explicit/background flushes still save immediately.
    static double next_observation = 0.0;
    if (s_config_tracking && now < next_observation) return;
    next_observation = now + 0.1;
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
    g_app.core_groups.clear();
    g_app.destination_mode=2;
    g_app.destination_rows[0]=0;
    g_app.ios_app_draft_ids.clear();
    g_app.ios_app_draft_mode = 0;
    g_app.desktop_app_paths.clear();
    g_app.desktop_app_mode = 0;
    g_app.desktop_app_platform.clear();
    g_app.desktop_app_provider="captured_flow";
    s_loaded_chain_transports = false;
    s_loaded_transport_base = 11;
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
    if (s_loaded_transport_base < kCoreTransportBase) {
        for (int& value : g_app.chain_transports)
            if (value >= s_loaded_transport_base) value += kCoreTransportBase - s_loaded_transport_base;
    }
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
    // it. Psiphon can also run directly with no chain. What used to be the
    // engine's Tor routing mode is rewritten once: 1 = Tor behind the tunnel,
    // 2 = the tunnel behind Tor, 3 = the Psiphon egress. The mode itself is no
    // longer written back.
    {
        const int stored = current_transport();
        const bool stored_is_hop = stored == kTorTransport || stored == kPsiphonTransport;
        bool repaired = false;
        // The hop the old mode added behind the carrier the profile keeps. Mode 2
        // is the one that moves the carrier itself: Tor carries there, so Tor is
        // the protocol and the transport the profile names is what rides it.
        int exit_hop = -1;
        if (!s_loaded_chain_transports && s_loaded_tor_mode == 2) {
            apply_transport(kTorTransport);
            // Preserve the old carrier only when it was a distinct transport;
            // never invent a MASQUE H3/Aether exit to replace a self-hop.
            exit_hop = stored_is_hop ? -1 : stored;
        } else if (!s_loaded_chain_transports && s_loaded_tor_mode == 1) {
            exit_hop = kTorTransport;
        } else if (!s_loaded_chain_transports && s_loaded_tor_mode == 3) {
            exit_hop = kPsiphonTransport;
        }
        if (exit_hop >= 0 && g_app.chain_transports.empty()
            && exit_hop != current_transport()) {
            g_app.chain_transports.push_back(exit_hop);
            repaired = true;
        }
        s_loaded_tor_mode = 0;
        if (repaired)
            g_app.add_log(4, "[ui] the saved legacy route was rewritten as an explicit chain");
    }
    // Saved config references are persistent positions. Keep incomplete slots
    // and dangling selections intact so a damaged file cannot shift a choice
    // onto a different config or silently replace a route with Aether.
    // A group reference is a position too; one that names no group is dropped,
    // which leaves a plain saved config rather than one tied to the wrong feed.
    for (AppState::CoreConfigEntry& entry : g_app.core_configs)
        if (entry.group < 0 || entry.group >= (int)g_app.core_groups.size()) entry.group = -1;
    g_app.refresh_core_listeners();
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
    UiText::ItemTooltip("%s", tooltip);

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

/// Whether a session is running, starting or paused: anything but idle.
static bool session_live() {
    const FcaeState state = (FcaeState)g_app.telem.state;
    return s_tun_paused || (state != FCAE_STATE_DISCONNECTED && state != FCAE_STATE_ERROR);
}

/// Whether the session that is running routes through the TUN device.
/// `g_app.mode` is the mode the next connection starts in and may be changed
/// while this one runs; what this one does was fixed when it started, and the
/// engine reports it. With no session it is the mode the next one would use.
static bool session_is_tun() {
    if (s_tun_paused) return true;
    return session_live() ? g_app.telem.active_mode == FCAE_MODE_TUN : g_app.mode == 1;
}

static const char* state_label(FcaeState s) {
    if (s == FCAE_STATE_CONNECTED)
        return session_is_tun() ? "CONNECTED - TUN" : "CONNECTED - PROXY";
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
                g_app.add_log(4, ("[ui] created default config: " + get_config_path()).c_str());
            }
        }
        fcae_backend_set_log_level(2, (uint32_t)g_app.firefox_log);
        fcae_backend_set_log_level(6, (uint32_t)g_app.urnetwork_log);
        // Data paths stay relative to data_dir() so the folder can move
        // between machines; resolve_data_path() anchors them at use.
        bool migrated = make_portable(g_app.config_path, sizeof(g_app.config_path));
        migrated |= make_portable(g_app.psiphon_data_dir, sizeof(g_app.psiphon_data_dir));
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
            if (argc >= 3 && std::wcscmp(argv[1], L"--fcae-wait-parent") == 0) {
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
#if defined(ANDROID)
        const FcaeStatus init_status = android_ui_initialize_runtime();
#else
        const FcaeStatus init_status = fcae_init(&opt);
#endif
        if (init_status != FCAE_OK) {
            g_app.add_log(FCAE_LOG_ERROR, fcae_last_error());
            runtime_ok = false;
        }
        if (runtime_ok && g_app.mode == 1)
            fcae_ui_diagnostic(0, uint32_t(g_app.tun_engine));

        // Auto-trigger update check once on startup if enabled and the FFI is live.
        if (runtime_ok && g_app.auto_update_check) {
            fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
        }
#if defined(ANDROID)
        if (runtime_ok) android_ui_save_session(false);
#endif
        s_runtime_init.store(
            runtime_ok ? RuntimeInitState::Ready : RuntimeInitState::Failed,
            std::memory_order_release);
        ui_request_redraw();
    });
}

#include "mountain_png.h"

// ---- Background pictures the user added -----------------------------------------
//
// "+ Add image..." in the Background setting opens the system's file picker.
// The picture chosen is copied into data_dir()/backgrounds, so it is still
// there when the original is moved or deleted, and the copies are what the
// setting lists after the built-in choices. Deleting an entry deletes the
// copy, never the file it was made from.

static constexpr size_t kMaxBackgroundImages = 16;
static constexpr size_t kMaxBackgroundFile = 64u * 1024u * 1024u;
// The longer side a picture is drawn from. A window is rarely wider, and a
// phone photo is several times this.
#if defined(ANDROID) || defined(FCAE_IOS)
static constexpr uint32_t kBackgroundMaxSide = 2048;
#else
static constexpr uint32_t kBackgroundMaxSide = 2560;
#endif

/// What the last add or delete has to say, shown under the setting.
static std::string s_background_note;

static void background_note(const char* text) {
    s_background_note = text;
    g_app.add_log(FCAE_LOG_WARN, (std::string("[ui] background: ") + text).c_str());
    ui_request_redraw();
}

static bool background_read_file(const std::string& path, std::vector<uint8_t>& bytes) {
    bytes.clear();
    FILE* f = open_cfg(path, "rb");
    if (!f) return false;
    std::vector<uint8_t> chunk(64 * 1024);
    bool ok = true;
    for (;;) {
        const size_t n = fread(chunk.data(), 1, chunk.size(), f);
        if (n == 0) break;
        if (bytes.size() + n > kMaxBackgroundFile) {
            ok = false;
            break;
        }
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + (ptrdiff_t)n);
    }
    if (ferror(f)) ok = false;
    fclose(f);
    return ok && !bytes.empty();
}

static void background_delete_file(const std::string& path) {
#if defined(_WIN32)
    _wremove(widen(path).c_str());
#else
    remove(path.c_str());
#endif
}

static bool background_is_saved(const std::string& name) {
    return std::find(g_app.background_images.begin(), g_app.background_images.end(), name)
        != g_app.background_images.end();
}

/// Whether the picture drawn is one the user added.
static bool background_custom_active() {
    return strcmp(g_app.background_mode, "image") == 0 && background_is_saved(g_app.background_image);
}

/// The chosen picture's pixels. `generation` is what tells the renderer that
/// the pixels in the background's texture changed; 1 is the built-in picture's.
struct CustomBackground {
    std::string name;
    std::vector<uint8_t> rgba;
    int w = 0;
    int h = 0;
    uint64_t generation = 1;
};
static CustomBackground s_custom_background;

/// Drop the decoded picture: another one is chosen, or none of them is.
static void background_forget_pixels() {
    s_custom_background.name.clear();
    std::vector<uint8_t>().swap(s_custom_background.rgba);
    s_custom_background.w = s_custom_background.h = 0;
}

/// Decode the chosen picture when the choice changed. A picture that cannot be
/// read is tried once, not on every frame.
static bool background_load_pixels() {
    CustomBackground& bg = s_custom_background;
    if (bg.name == g_app.background_image) return !bg.rgba.empty();
    background_forget_pixels();
    bg.name = g_app.background_image;
    std::vector<uint8_t> bytes;
    if (background_read_file(join_path(background_dir(), bg.name.c_str()), bytes)) {
        uint32_t w = 0, h = 0;
        const uint32_t size = fcae_decode_image_rgba(bytes.data(), (uint32_t)bytes.size(),
            kBackgroundMaxSide, nullptr, 0, &w, &h);
        if (size && w && h) {
            bg.rgba.resize(size);
            uint32_t aw = 0, ah = 0;
            if (fcae_decode_image_rgba(bytes.data(), (uint32_t)bytes.size(), kBackgroundMaxSide,
                    bg.rgba.data(), size, &aw, &ah) == size && aw == w && ah == h) {
                bg.w = (int)w;
                bg.h = (int)h;
                ++bg.generation;
            } else {
                std::vector<uint8_t>().swap(bg.rgba);
            }
        }
    }
    if (bg.rgba.empty())
        g_app.add_log(FCAE_LOG_WARN, ("[ui] background: " + bg.name
            + " could not be loaded; the built-in picture is shown").c_str());
    return !bg.rgba.empty();
}

/// What a picked file is saved as: its own name, reduced to what every file
/// system and the UI font can spell, and told apart from the ones already saved.
static std::string background_new_name(const std::string& source) {
    const size_t slash = source.find_last_of("/\\");
    std::string stem = slash == std::string::npos ? source : source.substr(slash + 1);
    std::string extension;
    const size_t dot = stem.find_last_of('.');
    if (dot != std::string::npos && dot > 0 && stem.size() - dot <= 6) {
        for (size_t i = dot + 1; i < stem.size(); ++i) {
            const unsigned char c = (unsigned char)stem[i];
            if (c < 0x80 && std::isalnum(c)) extension.push_back((char)std::tolower(c));
        }
        if (!extension.empty()) extension.insert(extension.begin(), '.');
        stem.erase(dot);
    }
    std::string plain;
    for (unsigned char c : stem) {
        const bool keep = (c < 0x80 && std::isalnum(c)) || c == '-' || c == '.' || c == ' ' || c == '(' || c == ')';
        if (keep) plain.push_back((char)c);
        else if (plain.empty() || plain.back() != '_') plain.push_back('_');
    }
    while (!plain.empty() && (plain.back() == '_' || plain.back() == ' ' || plain.back() == '.')) plain.pop_back();
    size_t first = 0;
    while (first < plain.size() && (plain[first] == '_' || plain[first] == ' ' || plain[first] == '.')) ++first;
    plain.erase(0, first);
    if (plain.empty()) plain = "image";
    if (plain.size() > 40) plain.resize(40);
    const auto taken = [](const std::string& name) {
        for (const std::string& saved : g_app.background_images) {
            if (saved.size() == name.size()
                && std::equal(saved.begin(), saved.end(), name.begin(), [](char a, char b) {
                       return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
                   }))
                return true;
        }
        return file_exists(join_path(background_dir(), name.c_str()));
    };
    std::string name = plain + extension;
    for (unsigned suffix = 2; taken(name) && suffix < 10000; ++suffix)
        name = plain + "-" + std::to_string(suffix) + extension;
    return name;
}

/// Copy the picture at `source` into the backgrounds folder and draw it.
static void background_add_image(const std::string& source) {
    std::vector<uint8_t> bytes;
    if (!background_read_file(source, bytes)) {
        background_note("That file could not be read, or it is larger than 64 MB.");
        return;
    }
    uint32_t w = 0, h = 0;
    if (!fcae_decode_image_rgba(bytes.data(), (uint32_t)bytes.size(), kBackgroundMaxSide, nullptr, 0, &w, &h)) {
        background_note("That file is not a PNG, JPEG, WebP, GIF or BMP image.");
        return;
    }
    if (g_app.background_images.size() >= kMaxBackgroundImages) {
        background_note("The list holds 16 pictures. Delete one to add another.");
        return;
    }
    const std::string dir = background_dir();
    const std::string name = background_new_name(source);
    const std::string path = join_path(dir, name.c_str());
    bool saved = make_dir(dir, false);
    if (saved) {
        FILE* f = open_cfg(path, "wb");
        saved = f && fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
        if (f && fclose(f) != 0) saved = false;
        if (!saved) background_delete_file(path);
    }
    if (!saved) {
        background_note("The picture could not be saved in the app's folder.");
        return;
    }
    background_forget_pixels();
    g_app.background_images.push_back(name);
    g_app.background_image = name;
    snprintf(g_app.background_mode, sizeof(g_app.background_mode), "image");
    s_background_note.clear();
    save_config();
    ui_request_redraw();
}

/// Delete a picture the user added. The built-in one takes its place when it
/// was the one drawn.
static void background_remove_image(size_t index) {
    if (index >= g_app.background_images.size()) return;
    const std::string name = g_app.background_images[index];
    background_delete_file(join_path(background_dir(), name.c_str()));
    g_app.background_images.erase(g_app.background_images.begin() + (ptrdiff_t)index);
    if (g_app.background_image == name) {
        g_app.background_image.clear();
        if (strcmp(g_app.background_mode, "image") == 0)
            snprintf(g_app.background_mode, sizeof(g_app.background_mode), "mountain");
    }
    background_forget_pixels();
    s_background_note.clear();
    save_config();
    ui_request_redraw();
}

// ---- The system's file picker ---------------------------------------------------

static std::mutex s_background_pick_mutex;
static std::string s_background_picked;
static bool s_background_pick_ready = false;
#if !defined(__APPLE__) && !defined(ANDROID)
// Set while this process runs the dialog itself: one at a time.
static std::atomic<bool> s_background_picking{false};
#endif

void ui_background_image_picked(const char* path) {
    {
        std::lock_guard<std::mutex> lock(s_background_pick_mutex);
        s_background_picked = path ? path : "";
        s_background_pick_ready = true;
    }
    ui_request_redraw();
}

/// Take in what the picker answered. Called on the UI thread, once a frame.
static void background_pick_poll() {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(s_background_pick_mutex);
        if (!s_background_pick_ready) return;
        s_background_pick_ready = false;
        path.swap(s_background_picked);
    }
    if (path.empty()) {
#if !defined(_WIN32) && !defined(__APPLE__) && !defined(ANDROID)
        background_note("No file dialog could be opened. Install zenity or kdialog.");
#else
        background_note("The picture could not be opened.");
#endif
        return;
    }
    background_add_image(path);
}

#if !defined(_WIN32) && !defined(__APPLE__) && !defined(ANDROID)
/// Run a desktop's own file dialog and read the path it prints. Returns its
/// exit status: 0 with a path, 1 when the user cancelled, 127 when the program
/// is not installed. The arguments are passed as they are, never through a
/// shell.
static int background_run_dialog(const char* const* argv, std::string& chosen) {
    chosen.clear();
    int out[2];
    if (pipe(out) != 0) return -1;
    const pid_t pid = fork();
    if (pid < 0) {
        close(out[0]);
        close(out[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(out[1], STDOUT_FILENO);
        close(out[0]);
        close(out[1]);
        const int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);
    }
    close(out[1]);
    char buffer[1024];
    for (;;) {
        const ssize_t n = read(out[0], buffer, sizeof(buffer));
        if (n > 0) {
            if (chosen.size() < 8192) chosen.append(buffer, (size_t)n);
        } else if (n == 0 || errno != EINTR) {
            break;
        }
    }
    close(out[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    while (!chosen.empty() && (chosen.back() == '\n' || chosen.back() == '\r')) chosen.pop_back();
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#endif

/// Open the system's picker for one image. It answers through
/// ui_background_image_picked(); the UI keeps drawing meanwhile. `from_files`
/// matters on iOS alone, where Photos and Files are two pickers.
static void background_pick_request(bool from_files = false) {
    (void)from_files;
#if defined(FCAE_IOS)
    ios_pick_background_image(from_files);
#elif defined(ANDROID)
    // The activity opens the system's document picker and copies the choice
    // somewhere this side can read: a picked document is a stream, not a path.
    android_ui_command("backgroundImage");
#elif defined(__APPLE__)
    mac_pick_background_image();
#else
    if (s_background_picking.exchange(true)) return;
#if defined(_WIN32)
    // On a thread of its own: the dialog runs a message loop, and this window's
    // procedure paints from inside one. The owner makes it modal to the window.
    const HWND owner = reinterpret_cast<HWND>(s_ui_window.load());
    std::thread([owner] {
        std::vector<wchar_t> file(32768, L'\0');
        OPENFILENAMEW dialog = {};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = owner;
        dialog.lpstrFilter = L"Images (*.png;*.jpg;*.jpeg;*.webp;*.gif;*.bmp)\0"
                             L"*.png;*.jpg;*.jpeg;*.webp;*.gif;*.bmp\0"
                             L"All files (*.*)\0*.*\0";
        dialog.lpstrFile = file.data();
        dialog.nMaxFile = (DWORD)file.size();
        dialog.lpstrTitle = L"Choose a background image";
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY
            | OFN_NOCHANGEDIR;
        if (GetOpenFileNameW(&dialog)) ui_background_image_picked(narrow(file.data()).c_str());
        s_background_picking.store(false);
    }).detach();
#else
    // GTK desktops ship zenity and KDE ships kdialog: each is that desktop's
    // own file dialog.
    std::thread([] {
        const std::string home = home_dir();
        const char* const zenity[] = {
            "zenity", "--file-selection", "--title=Choose a background image",
            "--file-filter=Images | *.png *.jpg *.jpeg *.webp *.gif *.bmp *.PNG *.JPG *.JPEG *.WEBP *.GIF *.BMP",
            "--file-filter=All files | *", nullptr,
        };
        const char* const kdialog[] = {
            "kdialog", "--title", "Choose a background image", "--getopenfilename",
            home.empty() ? "." : home.c_str(),
            "Images (*.png *.jpg *.jpeg *.webp *.gif *.bmp)", nullptr,
        };
        std::string chosen;
        int status = background_run_dialog(zenity, chosen);
        if (status == 127) status = background_run_dialog(kdialog, chosen);
        if (status == 0 && !chosen.empty()) ui_background_image_picked(chosen.c_str());
        else if (status == 127 || status < 0) ui_background_image_picked("");
        s_background_picking.store(false);
    }).detach();
#endif
#endif
}

/// `rgba` over the whole window: scaled to cover it, cropped around its centre.
static bool draw_background_picture(const ImGuiIO& io, const std::vector<uint8_t>& rgba, int w, int h,
                                    uint64_t generation) {
    if (rgba.empty() || w <= 0 || h <= 0 || io.DisplaySize.x <= 0.0f || io.DisplaySize.y <= 0.0f)
        return false;
    const ImTextureID tex = sponsor_texture_update(rgba.data(), w, h, generation, 3);
    if (!tex) return false;
    const float view_aspect = io.DisplaySize.x / io.DisplaySize.y;
    const float img_aspect = (float)w / (float)h;
    ImVec2 uv0(0.0f, 0.0f), uv1(1.0f, 1.0f);
    if (view_aspect > img_aspect) {
        const float h_frac = img_aspect / view_aspect;
        uv0.y = 0.5f - 0.5f * h_frac;
        uv1.y = 0.5f + 0.5f * h_frac;
    } else if (view_aspect < img_aspect) {
        const float w_frac = view_aspect / img_aspect;
        uv0.x = 0.5f - 0.5f * w_frac;
        uv1.x = 0.5f + 0.5f * w_frac;
    }
    ImGui::GetBackgroundDrawList()->AddImage(tex, ImVec2(0.0f, 0.0f), io.DisplaySize, uv0, uv1);
    return true;
}

/// Draw the background the setting names: the built-in picture, one the user
/// added, or nothing. Returns whether a picture is behind the window.
static bool draw_mountain_background(const ImGuiIO& io) {
    if (background_custom_active()) {
        if (background_load_pixels())
            return draw_background_picture(io, s_custom_background.rgba, s_custom_background.w,
                s_custom_background.h, s_custom_background.generation);
        // The file is gone or unreadable: the built-in picture, not nothing.
    } else {
        if (!s_custom_background.name.empty()) background_forget_pixels();
        if (strcmp(g_app.background_mode, "none") == 0) return false;
    }
    static std::vector<uint8_t> s_mountain_rgba;
    static int s_mountain_w = 0;
    static int s_mountain_h = 0;
    static bool s_mountain_tried = false;
    if (!s_mountain_tried) {
        s_mountain_tried = true;
        uint32_t w = 0, h = 0;
        const uint32_t size = fcae_decode_png_rgba(kMountainPng, kMountainPngSize, nullptr, 0, &w, &h);
        if (size && size <= 32 * 1024 * 1024 && w && h && (uint64_t)w * h * 4 == size) {
            s_mountain_rgba.resize(size);
            uint32_t aw = 0, ah = 0;
            if (fcae_decode_png_rgba(kMountainPng, kMountainPngSize, s_mountain_rgba.data(), size, &aw, &ah) == size) {
                s_mountain_w = (int)w;
                s_mountain_h = (int)h;
            } else {
                s_mountain_rgba.clear();
            }
        }
    }
    return draw_background_picture(io, s_mountain_rgba, s_mountain_w, s_mountain_h, 1);
}

static void render_startup_shell(bool failed) {
    const ImGuiIO& io = ImGui::GetIO();
    const bool has_bg = draw_mountain_background(io);
    if (has_bg) ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.06f, 0.08f, 0.12f, 0.55f));
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);
    if (has_bg) ImGui::PopStyleColor();
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
    const ImGuiIO& io = ImGui::GetIO();
    // An elevation hand-off is armed on a worker and has to be finished on this
    // thread. This is the only place that keeps running: the old single call
    // site was inside the CONNECT click handler, one instant after arming the
    // flag, so at the moment it ran the flag was still clear and the check
    // never fired again -- the relaunched elevated instance appeared while this
    // one went on living, which is the second window behind it.
    ui_handoff_tick();
    background_pick_poll();

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
        return;
    }
    if (init == RuntimeInitState::Failed) {
        render_startup_shell(true);
        s_busy_anim = false;
        return;
    }

    // The real UI from the first frame; engine-dependent actions gate
    // themselves on Ready inside render_ui() instead of blocking everything
    // behind the INITIALIZING shell.
    const bool has_background = draw_mountain_background(io);
    if (has_background) {
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.06f, 0.08f, 0.12f, 0.52f));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.06f, 0.08f, 0.13f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_TitleBg, ImVec4(0.06f, 0.08f, 0.12f, 0.62f));
        ImGui::PushStyleColor(ImGuiCol_TitleBgActive, ImVec4(0.08f, 0.10f, 0.16f, 0.68f));
        ImGui::PushStyleColor(ImGuiCol_TitleBgCollapsed, ImVec4(0.06f, 0.08f, 0.12f, 0.52f));
    }
    render_ui();
    if (has_background) ImGui::PopStyleColor(6);

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
#if !defined(ANDROID) && !defined(FCAE_IOS)
    // Give normal routing/DNS restoration time, but do not leave a headless
    // process forever if inventory, initialization or a core join is stuck.
    static std::atomic<bool> shutdown_finished{false};
    try {std::thread([] {
        for(int i=0;i<20;++i){std::this_thread::sleep_for(std::chrono::seconds(1));if(shutdown_finished.load())return;}
#if defined(_WIN32)
        TerminateProcess(GetCurrentProcess(),1);
#else
        std::_Exit(1);
#endif
    }).detach();} catch(...) {}
#endif
    // Request session cancellation before inventory/init joins so OS cleanup
    // can make progress even if one of those independent workers stalls.
    fcae_stop();
#if !defined(ANDROID)
    PlatformAppRouting::shutdown(); // Join inventory work before destroying UI/runtime state.
#endif
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
    // Avoid DLL-detach deadlocks in an embedded core after cleanup returned.
    TerminateProcess(GetCurrentProcess(),0);
    ExitProcess(0);
#endif
#if !defined(ANDROID) && !defined(FCAE_IOS)
    shutdown_finished.store(true);
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

static const char* const kLinkUrSignup = "https://ur.io/c?bonus=HZ0G13";

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
    if (!host_ok && strcmp(url, kLinkUrSignup) == 0) host_ok = true;
    if (!host_ok) return false;

    for (const char* c = url; *c; ++c) {
        if (*c == '\'' || *c == '"' || *c == '`' || *c == '\\' ||
            *c == '\n' || *c == '\r') return false;
    }
#if defined(FCAE_IOS)
    return ios_open_url(url);
#elif defined(_WIN32)
    return (INT_PTR)ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL) > 32;
#elif defined(ANDROID)
    android_ui_command("url", url);
    return true;
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
    { "Telegram:", kLinkTelegram, "t.me/FCAE_VPN" },
    { "GitHub:",   kLinkGithub,   "github.com/FCFlenkchy/FCAE_VPN" },
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
            firefox_json_string(object, "usage_gib"),
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
        ImGui::TextDisabled("Usage: %s", account.monthly_usage.empty() ? "Unavailable" : account.monthly_usage.c_str());
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
    ImGui::BeginDisabled(g_app.firefox_job != 0);
    if (ImGui::Button("Add new account")) {
        firefox_clear_login_form();
        s_firefox_add_popup_open = true;
        s_firefox_add_should_close = false;
    }
    ImGui::EndDisabled();
    ImGui::Spacing();
}

#include "shared_account_ui.h"

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
    std::vector<std::pair<std::string, std::string>> rows;
    for (const auto& option : options) rows.emplace_back(option.value, option.label);
    std::string value = options[(size_t)selected_index].value;
    if (account_region_combo("firefox", value, rows))
        snprintf(g_app.firefox_location, sizeof(g_app.firefox_location), "%s", value.c_str());
}

static uint64_t firefox_account_submit(const std::string& request) {
    static const char* const transports[] = {"auto", "h2", "h1", "h3"};
    const int selected = g_app.firefox_transport;
    const char* transport = transports[(selected >= 0 && selected <= 3) ? selected : 0];
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
    static AccountRequestStatusTimer timer;
    if (timer.expired(firefox_requests_working(), s_firefox_status_revision,
            g_app.firefox_status[0] != 0, now)) {
        g_app.firefox_status[0] = 0;
        ui_request_redraw();
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
        const std::string monthly_usage = account == std::string::npos ? std::string() : firefox_json_string(json, "usage_gib", account);
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

static bool firefox_requests_working() {
    return g_app.firefox_job || s_firefox_region_job || s_firefox_usage_job || !s_firefox_usage_queue.empty();
}
static void firefox_request_status() {
    if (firefox_requests_working()) ImGui::TextUnformatted("Working…");
    else if (g_app.firefox_status[0]) ImGui::TextWrapped("%s", g_app.firefox_status);
}

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
                ? firefox_json_string(json, "usage_gib", account_pos) : std::string();
            for (auto& account : s_firefox_account_options) {
                if (account.id == s_firefox_usage_account) {
                    if (!usage.empty()) {
                        account.monthly_usage = usage;
                        account.usage_exhausted = firefox_json_bool(json, "monthly_usage_exhausted", account_pos);
                    } else {
                        account.monthly_usage = "Unavailable";
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
    UiText::InputText("CAPTCHA answer", g_app.firefox_captcha_answer, sizeof(g_app.firefox_captcha_answer));
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
    "URnetwork",
};

/// The core a saved-config row is tagged with, lower case and unparenthesised:
/// it is a label, not a sentence. A built-in transport answers nullptr.
static const char* transport_tag(int transport) {
    const AppState::CoreConfigEntry* entry = g_app.core_config_at(transport);
    if (!entry) return nullptr;
    return entry->backend == 2 ? "Mihomo" : entry->backend == 1 ? "sing-box" : "xray";
}

/// The subscription group a saved config is listed under, or -1: one added by
/// hand, or one whose group is not there, which is then listed with those
/// rather than nowhere.
static int core_config_group(const AppState::CoreConfigEntry& entry) {
    return entry.group >= 0 && entry.group < (int)g_app.core_groups.size() ? entry.group : -1;
}

/// The colour the tag is drawn in: distinct from the row's white name, and the
/// same across all three cores so the list stays quiet.
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

static bool transport_is_core(int transport) {
    return transport >= kCoreTransportBase;
}

static int current_transport() {
    // A saved config is the main protocol exactly when core_selected names one.
    if ((g_app.backend >= 3 && g_app.backend <= 5)) {
        if (g_app.core_selected >= 0 && g_app.core_selected < (int)g_app.core_configs.size())
            return kCoreTransportBase + g_app.core_selected;
        return kCoreTransportBase + (int)g_app.core_configs.size();
    }
    if (g_app.backend == 6) return 11;
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
        return AppState::core_backend_id(entry->backend);
    if (transport == 5) return 1;
    if (transport == 10) return 2;
    if (transport == 11) return 6;
    return 0;
}

static void apply_transport(int transport) {
    if (transport_is_core(transport)) {
        const int index = transport - kCoreTransportBase;
        if (index >= 0 && index < (int)g_app.core_configs.size()) {
            g_app.core_selected = index;
            g_app.backend = AppState::core_backend_id(g_app.core_configs[(size_t)index].backend);
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
        case 5: case 10: case 11: g_app.protocol = 3; break;
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

// ---- Saved Xray / sing-box / Mihomo configs --------------------------------
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
/// The name the editor's config is saved under while its Name field is empty.
static std::string s_core_auto_name;

static bool s_core_import_popup_open = false;
static bool s_core_import_in_progress = false;
static char s_core_import_url[4097] = {};
static char s_core_import_name[kMaxCoreConfigName + 1] = {};
static char s_core_import_status[512] = {};
static bool s_core_import_status_error = false;
static bool s_core_import_status_warning = false;
/// Counts the messages written to it, so the one that is timed out is the one
/// that was timed: the same words said again are news again.
static uint64_t s_core_import_status_revision = 0;
/// The group the subscription dialog manages, or -1 while it imports a new one.
static int s_core_import_group = -1;
/// Set when an import succeeded: the dialog closes itself and the list shows
/// the new group, which is the answer the user was waiting for.
static bool s_core_import_should_close = false;
/// What the download in flight is for. Captured when it starts, so nothing
/// typed into the dialog meanwhile can redirect its result.
static int s_core_fetch_group = -1;
static std::string s_core_fetch_url;
static std::string s_core_fetch_name;
/// Where the download in flight was asked for. The list's Refresh fetches what
/// the group already says; the dialog fetches what its fields say, and those
/// become the group's only once the download has succeeded.
enum CoreFetchOrigin { kCoreFetchList, kCoreFetchManage, kCoreFetchImport };
static CoreFetchOrigin s_core_fetch_origin = kCoreFetchList;
/// Which groups the saved-configs list shows opened, by position.
static std::vector<char> s_core_group_open;
/// A group the list scrolls to the next time it is drawn, or -1: the one an
/// import just made, which may be below everything that was already there.
static int s_core_group_reveal = -1;
/// The same for a config added by hand: the first one a paste just added,
/// which goes under every row of its kind that was already there.
static int s_core_row_reveal = -1;
/// Set by "+ Paste" where the host reads its clipboard on a thread of its own:
/// the paste is carried out on the frame that text arrives.
static bool s_core_paste_pending = false;
/// UiText::clipboard_revision when that read was asked for.
static unsigned s_core_paste_revision = 0;
/// When to stop waiting for it.
static double s_core_paste_deadline = 0.0;
/// Whether the subscription dialog is on screen. It says how a download is
/// going itself, so the list behind it does not say it a second time.
static bool s_core_import_visible = false;
static std::mutex s_core_import_mutex;
static uint64_t s_core_import_request_id = 0;
static bool s_core_import_awaiting = false;
static bool s_core_import_result_ready = false;
static bool s_core_import_result_ok = false;
static std::string s_core_import_result;
static std::string s_core_import_result_title;
static std::string s_core_import_result_file_name;

static void ui_core_subscription_fetch_complete(uint64_t request_id, bool success,
                                                const std::string& response_or_error,
                                                const std::string& title,
                                                const std::string& file_name) {
    {
        std::lock_guard<std::mutex> lock(s_core_import_mutex);
        if (!s_core_import_awaiting || request_id != s_core_import_request_id) return;
        s_core_import_result_ok = success;
        s_core_import_result = response_or_error;
        s_core_import_result_title = title;
        s_core_import_result_file_name = file_name;
        s_core_import_result_ready = true;
    }
    ui_request_redraw();
}

/// Open the subscription dialog on `group`, or on a new import (`-1`).
static void open_core_subscription_import(int group = -1) {
    const AppState::CoreGroupEntry* entry =
        (group >= 0 && group < (int)g_app.core_groups.size()) ? &g_app.core_groups[(size_t)group] : nullptr;
    s_core_import_group = entry ? group : -1;
    s_core_import_popup_open = true;
    s_core_import_should_close = false;
    snprintf(s_core_import_url, sizeof(s_core_import_url), "%s", entry ? entry->url.c_str() : "");
    snprintf(s_core_import_name, sizeof(s_core_import_name), "%s", entry ? entry->name.c_str() : "");
    if (!s_core_import_in_progress) {
        s_core_import_status[0] = 0;
        s_core_import_status_error = false;
        s_core_import_status_warning = false;
    }
}

static void open_core_configs() {
    s_core_configs_popup_open = true;
    s_core_editor_open = false;
    s_core_editor_row = -1;
    s_core_status[0] = 0;
    // How a subscription download ended last time is not news any more.
    if (!s_core_import_in_progress) s_core_import_status[0] = 0;
    s_core_import_visible = false;
    // Neither is a clipboard nobody was there to see arrive.
    s_core_paste_pending = false;
}

/// Open the editor on `row`, or on a config that does not exist yet (`-1`).
static void open_core_editor(int row) {
    const AppState::CoreConfigEntry* entry =
        (row >= 0 && row < (int)g_app.core_configs.size())
            ? &g_app.core_configs[(size_t)row] : nullptr;
    s_core_editor_row = entry ? row : -1;
    snprintf(s_core_name_buf, sizeof(s_core_name_buf), "%s", entry ? entry->name.c_str() : "");
    s_core_backend_buf = entry ? entry->backend : 0;
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

static std::string trim_subscription_text(std::string text) {
    if (text.size() >= 3 && (unsigned char)text[0] == 0xef
        && (unsigned char)text[1] == 0xbb && (unsigned char)text[2] == 0xbf)
        text.erase(0, 3);
    size_t begin = 0;
    while (begin < text.size() && std::isspace((unsigned char)text[begin])) ++begin;
    size_t end = text.size();
    while (end > begin && std::isspace((unsigned char)text[end - 1])) --end;
    return text.substr(begin, end - begin);
}

static bool subscription_uri_line(const std::string& line) {
    if (line.size() >= 11) {
        static const char* const kAnyConnect = "anyconnect:";
        bool match = true;
        for (size_t i = 0; i < 11; ++i)
            if (std::tolower((unsigned char)line[i]) != kAnyConnect[i]) match = false;
        if (match) return true;
    }
    const size_t scheme_end = line.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) return false;
    for (size_t i = 0; i < scheme_end; ++i) {
        const unsigned char c = (unsigned char)line[i];
        if (!std::isalnum(c) && c != '+' && c != '.' && c != '-') return false;
    }
    return true;
}

/// Whether `line` opens with `key`, which is given in lower case.
static bool subscription_line_opens_with(const std::string& line, const char* key) {
    const size_t length = strlen(key);
    if (line.size() < length) return false;
    for (size_t i = 0; i < length; ++i)
        if (std::tolower((unsigned char)line[i]) != key[i]) return false;
    return true;
}

static bool subscription_metadata_line(const std::string& line) {
    // The two lines a Shadowrocket-style feed opens with: how much of the plan
    // is used, and what the feed is called.
    if (subscription_line_opens_with(line, "status=") || subscription_line_opens_with(line, "remarks="))
        return true;
    const size_t colon = line.find(':');
    if (colon == std::string::npos) return false;
    std::string key = line.substr(0, colon);
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    static const char* const keys[] = {
        "profile-title", "profile-update-interval", "profile-web-page-url",
        "subscription-userinfo", "support-url", "announce", "expire"
    };
    for (const char* known : keys) if (key == known) return true;
    return false;
}

static bool is_valid_subscription_utf8(const std::string& text);

static int subscription_base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/// Accept the standard and URL-safe base64 spellings used by proxy feeds,
/// with or without padding. Whitespace between encoded characters is ignored.
static bool decode_subscription_base64(const std::string& text, std::string& decoded) {
    uint32_t accumulator = 0;
    int bits = 0;
    size_t characters = 0;
    size_t padding = 0;
    bool saw_padding = false;
    decoded.clear();
    decoded.reserve(text.size() * 3 / 4);
    for (unsigned char c : text) {
        if (std::isspace(c)) continue;
        if (c == '=') {
            saw_padding = true;
            if (++padding > 2) return false;
            continue;
        }
        const int value = subscription_base64_value(c);
        if (value < 0 || saw_padding) return false;
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        ++characters;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back((char)((accumulator >> bits) & 0xff));
        }
    }
    if (characters == 0 || characters % 4 == 1) return false;
    if (padding && ((characters + padding) % 4 != 0
        || (padding == 1 && characters % 4 != 3)
        || (padding == 2 && characters % 4 != 2))) return false;
    if (bits && (accumulator & ((1u << bits) - 1u)) != 0) return false;
    return !decoded.empty() && decoded.find('\0') == std::string::npos
        && is_valid_subscription_utf8(decoded);
}

static std::vector<std::string> subscription_links(const std::string& text,
                                                    int& ignored, int& overflow) {
    std::vector<std::string> links;
    ignored = 0;
    overflow = 0;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find('\n', start);
        std::string line = trim_subscription_text(text.substr(start,
            end == std::string::npos ? std::string::npos : end - start));
        if (!line.empty() && line[0] != '#' && line.rfind("//", 0) != 0) {
            if (subscription_uri_line(line)) {
                if (links.size() < (size_t)kMaxCoreConfigs) links.push_back(std::move(line));
                else ++overflow;
            } else if (!subscription_metadata_line(line)) {
                ++ignored;
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return links;
}

static std::string valid_subscription_utf8(const std::string& text) {
    std::string valid;
    valid.reserve(text.size());
    for (size_t i = 0; i < text.size();) {
        const unsigned char first = (unsigned char)text[i];
        size_t length = 0;
        if (first <= 0x7f) length = 1;
        else if (first >= 0xc2 && first <= 0xdf) length = 2;
        else if (first >= 0xe0 && first <= 0xef) length = 3;
        else if (first >= 0xf0 && first <= 0xf4) length = 4;
        bool well_formed = length != 0 && i + length <= text.size();
        for (size_t j = 1; well_formed && j < length; ++j) {
            const unsigned char byte = (unsigned char)text[i + j];
            well_formed = (byte & 0xc0) == 0x80;
            if (j == 1 && ((first == 0xe0 && byte < 0xa0)
                || (first == 0xed && byte >= 0xa0)
                || (first == 0xf0 && byte < 0x90)
                || (first == 0xf4 && byte >= 0x90))) well_formed = false;
        }
        if (!well_formed) {
            valid.push_back('?');
            ++i;
            continue;
        }
        valid.append(text, i, length);
        i += length;
    }
    return valid;
}

static bool is_valid_subscription_utf8(const std::string& text) {
    return valid_subscription_utf8(text) == text;
}

static std::string utf8_prefix(std::string text, size_t max_bytes) {
    text = valid_subscription_utf8(text);
    if (text.size() <= max_bytes) return text;
    text.resize(max_bytes);
    while (!text.empty() && ((unsigned char)text.back() & 0xc0) == 0x80) text.pop_back();
    if (!text.empty() && (unsigned char)text.back() >= 0xc0) text.pop_back();
    return text;
}

// ---- Names --------------------------------------------------------------------
//
// A saved config is referenced by name in the library the engine parses, so a
// name is always present and always unique. The user may leave it out: the
// config then goes by the name it gives itself, or by one made up for it.

static bool core_names_equal(const std::string& a, const std::string& b) {
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower((unsigned char)x) == std::tolower((unsigned char)y);
           });
}

/// `name` as a list row can show it and the library accepts it: one line, no
/// surrounding space, whole UTF-8 characters, within the byte limit.
static std::string clean_core_name(std::string name) {
    std::replace_if(name.begin(), name.end(), [](unsigned char c) { return std::iscntrl(c) != 0; }, ' ');
    name = utf8_prefix(trim_subscription_text(std::move(name)), kMaxCoreConfigName);
    return trim_subscription_text(std::move(name));
}

/// `wanted`, or `wanted (2)`, `wanted (3)`, ... : the first that `taken` does
/// not already claim.
template <typename Taken>
static std::string unique_core_name(const std::string& wanted, const Taken& taken) {
    if (!taken(wanted)) return wanted;
    for (unsigned suffix = 2; suffix < 100000; ++suffix) {
        const std::string tail = " (" + std::to_string(suffix) + ")";
        // Cut to make room for the number, a name does not end in a space.
        const std::string candidate =
            trim_subscription_text(utf8_prefix(wanted, kMaxCoreConfigName - tail.size())) + tail;
        if (!taken(candidate)) return candidate;
    }
    return wanted;
}

static uint32_t core_text_hash(const std::string& text) {
    uint32_t hash = 2166136261u;
    for (unsigned char c : text) {
        hash ^= c;
        hash *= 16777619u;
    }
    return hash ^ (hash >> 15);
}

/// `<prefix>-<4 digits>`, for something that names itself nothing. The digits
/// are drawn from `seed`, not from a clock: the same config gets the same name
/// when its subscription is refreshed, so a selection that points at it holds.
template <typename Taken>
static std::string numbered_core_name(const char* prefix, const std::string& seed, const Taken& taken) {
    const uint32_t start = core_text_hash(seed);
    char name[40];
    for (uint32_t step = 0; step < 10000u; ++step) {
        snprintf(name, sizeof(name), "%s-%04u", prefix, (unsigned)((start + step) % 10000u));
        if (!taken(name)) break;
    }
    return name;
}

/// The name a config gives itself -- a share link's #fragment, a VMess `ps`, a
/// native config's own label -- or "" when it gives none.
static std::string core_profile_own_name(const std::string& text, int backend) {
    char name[4 * kMaxCoreConfigName + 1] = {};
    if (!fcae_core_profile_name(text.c_str(), AppState::core_backend_id(backend), name, sizeof(name)))
        return {};
    return clean_core_name(name);
}

/// `<core>-<digits>` for a config of `backend` that names itself nothing.
template <typename Taken>
static std::string numbered_config_name(const std::string& text, int backend, const Taken& taken) {
    return numbered_core_name(backend == 2 ? "mihomo" : backend == 1 ? "sing-box" : "xray", text, taken);
}

/// The name an unnamed config is saved under: its own, else `<core>-<digits>`.
template <typename Taken>
static std::string core_auto_name(const std::string& text, int backend, const Taken& taken) {
    const std::string own = core_profile_own_name(text, backend);
    if (!own.empty()) return unique_core_name(own, taken);
    return numbered_config_name(text, backend, taken);
}

// ---- Subscription groups --------------------------------------------------------
//
// An imported subscription is a group: the URL it came from and the configs it
// produced. The configs are ordinary saved configs -- pickable as the protocol
// and as chain exits like any other -- and the group is what lets them be
// refreshed from the URL, or removed, as one.

static int core_group_size(int group) {
    int count = 0;
    for (const AppState::CoreConfigEntry& entry : g_app.core_configs)
        if (entry.group == group) ++count;
    return count;
}

static bool core_group_name_taken(const std::string& name, int except_group) {
    for (int i = 0; i < (int)g_app.core_groups.size(); ++i)
        if (i != except_group && core_names_equal(g_app.core_groups[(size_t)i].name, name)) return true;
    return false;
}

/// The site a subscription URL belongs to, when its host is a name: what a
/// group is called if neither the user nor the feed names it. An address is not
/// a name, and neither is a bare label such as `localhost`.
static std::string subscription_site_name(const std::string& url) {
    const size_t scheme = url.find("://");
    if (scheme == std::string::npos) return {};
    const size_t begin = scheme + 3;
    const size_t end = url.find_first_of("/?#", begin);
    std::string host = url.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    const size_t at = host.rfind('@');
    if (at != std::string::npos) host.erase(0, at + 1);
    if (host.empty() || host[0] == '[') return {};
    const size_t port = host.rfind(':');
    if (port != std::string::npos) host.resize(port);
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    if (host.rfind("www.", 0) == 0) host.erase(0, 4);
    bool letter = false, dot = false;
    for (unsigned char c : host) {
        if (std::isalpha(c) || c >= 0x80) letter = true;
        else if (c == '.') dot = true;
        else if (!std::isdigit(c) && c != '-') return {};
    }
    if (!letter || !dot || host.back() == '.') return {};
    return clean_core_name(host);
}

/// What a group is called: the name the user typed, else the one the feed gives
/// itself, else its site, else `gp-<digits>`. Unique among the groups.
static std::string core_group_auto_name(const std::string& typed, const std::string& title,
                                        const std::string& url, int except_group) {
    const auto taken = [&](const std::string& name) { return core_group_name_taken(name, except_group); };
    for (std::string wanted : {clean_core_name(typed), clean_core_name(title), subscription_site_name(url)})
        if (!wanted.empty()) return unique_core_name(wanted, taken);
    return numbered_core_name("gp", url, taken);
}

/// The name a feed gives itself in its body rather than in a response header.
/// That is `profile-title` on a line of its own, usually commented out so that
/// link parsers skip it, and often base64-encoded; or, where the feed has no
/// such line, the `REMARKS=` line a Shadowrocket-style feed opens with.
static std::string subscription_body_title(const std::string& text) {
    static const char kKey[] = "profile-title:";
    static const char kRemarks[] = "remarks=";
    std::string remarks;
    size_t start = 0;
    for (int line_number = 0; start < text.size() && line_number < 64; ++line_number) {
        const size_t end = text.find('\n', start);
        std::string line = trim_subscription_text(text.substr(start,
            end == std::string::npos ? std::string::npos : end - start));
        start = end == std::string::npos ? text.size() : end + 1;
        if (remarks.empty() && subscription_line_opens_with(line, kRemarks)) {
            remarks = clean_core_name(trim_subscription_text(line.substr(sizeof(kRemarks) - 1)));
            continue;
        }
        size_t skip = 0;
        while (skip < line.size() && (line[skip] == '#' || line[skip] == '/' || line[skip] == ' ')) ++skip;
        line.erase(0, skip);
        if (line.size() <= sizeof(kKey) - 1 || !subscription_line_opens_with(line, kKey)) continue;
        std::string value = trim_subscription_text(line.substr(sizeof(kKey) - 1));
        if (value.rfind("base64:", 0) == 0) {
            std::string decoded;
            if (!decode_subscription_base64(value.substr(7), decoded)) return {};
            value = decoded;
        }
        return clean_core_name(value);
    }
    return remarks;
}

struct SubscriptionProfile {
    std::string text;
    /// The name the profile gives itself, or "" when it gives none.
    std::string name;
    /// The core it is stored under: 0 = Xray, 1 = sing-box, 2 = Mihomo.
    int backend = 0;
};

struct SubscriptionParse {
    /// Every profile the selected core accepts, in feed order.
    std::vector<SubscriptionProfile> profiles;
    int skipped = 0;
    std::string first_problem;
    /// The feed's own name, when its body carries one.
    std::string title;
};

static bool validate_subscription_profile(const std::string& text, int backend,
                                          std::string& reason) {
    if (text.empty()) {
        reason = "the profile is empty";
        return false;
    }
    if (text.size() > kMaxCoreConfigText) {
        reason = "the profile exceeds the 128 KiB saved-config limit";
        return false;
    }
    char error[224] = {};
    if (!fcae_core_check_profile(text.c_str(), AppState::core_backend_id(backend),
                                 error, sizeof(error))) {
        reason = error[0] ? error : "the selected core rejected this profile";
        return false;
    }
    return true;
}

/// Why configs past the end of the list were left out.
static std::string core_list_limit_text() {
    return "the saved-config list holds at most " + std::to_string(kMaxCoreConfigs) + " configs";
}

/// Whether `text` opens with a share link: the first line of it that says
/// anything is one. Comments and the feed's own header lines say nothing.
static bool subscription_starts_with_link(const std::string& text) {
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find('\n', start);
        const std::string line = trim_subscription_text(text.substr(start,
            end == std::string::npos ? std::string::npos : end - start));
        if (!line.empty() && line[0] != '#' && line.rfind("//", 0) != 0 && !subscription_metadata_line(line))
            return subscription_uri_line(line);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

/// The core a profile from a subscription is stored under: the first of Xray,
/// sing-box and Mihomo that accepts it, so a feed that mixes protocols is
/// imported whole and nobody has to know which core runs which. -1 when none
/// of them does, with `reason` saying why: what two cores agree on is the
/// profile's own fault, and otherwise the first core's answer stands.
static int subscription_profile_backend(const std::string& text, std::string& reason) {
    std::string reasons[3];
    for (int backend = 0; backend < 3; ++backend)
        if (validate_subscription_profile(text, backend, reasons[backend])) return backend;
    reason = reasons[1] == reasons[2] ? reasons[1] : reasons[0];
    return -1;
}

/// Read what a subscription offers: share links, one to a line, or one native
/// config, either of them possibly base64-encoded, each under the core that
/// takes it. Nothing is stored here; the caller decides what the profiles
/// replace.
static SubscriptionParse parse_core_subscription(const std::string& raw_body) {
    SubscriptionParse parsed;
    const std::string body = trim_subscription_text(raw_body);
    parsed.title = subscription_body_title(body);
    std::string validation_error;
    int ignored = 0, overflow = 0;
    std::vector<std::string> links;
    const auto read = [&](const std::string& text) {
        links = subscription_links(text, ignored, overflow);
        // Text that opens with a link is a list of links and is read line by
        // line, never as one profile. The engine reads a link's name on to the
        // end of the text, so a whole list checks out as its first link, named
        // after all the others: asked first, it made one config of a feed.
        if (!links.empty() && subscription_starts_with_link(text)) return true;
        std::string reason;
        const int backend = subscription_profile_backend(text, reason);
        if (backend >= 0) {
            links.clear();
            ignored = overflow = 0;
            parsed.profiles.push_back({text, core_profile_own_name(text, backend), backend});
            return true;
        }
        // Links under lines that are neither links nor a config.
        if (!links.empty()) return true;
        validation_error = std::move(reason);
        return false;
    };
    if (!read(body)) {
        std::string decoded;
        if (decode_subscription_base64(body, decoded) && decoded != body) {
            if (parsed.title.empty()) parsed.title = subscription_body_title(decoded);
            read(decoded);
        }
    }
    for (const std::string& link : links) {
        std::string reason;
        const int backend = subscription_profile_backend(link, reason);
        if (backend >= 0) {
            parsed.profiles.push_back({link, core_profile_own_name(link, backend), backend});
        } else {
            ++parsed.skipped;
            if (parsed.first_problem.empty()) parsed.first_problem = std::move(reason);
        }
    }
    if (links.empty()) {
        if (parsed.profiles.empty())
            parsed.first_problem = "no share links were found, and the text is not a native Xray, "
                "sing-box or Mihomo config"
                + (validation_error.empty() ? std::string() : " (" + validation_error + ")");
        return parsed;
    }
    parsed.skipped += overflow + ignored;
    if (parsed.first_problem.empty() && overflow) parsed.first_problem = core_list_limit_text();
    if (parsed.first_problem.empty() && ignored)
        parsed.first_problem = "some lines are not share links or recognized subscription headers";
    return parsed;
}

/// Re-point everything that names a saved config by position after the list was
/// rebuilt. `moved[i]` is where old row `i` went, or -1 when it is gone. A
/// selection whose config is gone is given up rather than handed to whichever
/// config now sits in its place, and one that already pointed past the list
/// keeps pointing past it.
static void core_configs_remap(const std::vector<int>& moved) {
    const int old_count = (int)moved.size();
    const int new_count = (int)g_app.core_configs.size();
    const auto remap = [&](int index, bool& gone) {
        gone = false;
        if (index < 0) return index;
        if (index >= old_count) return new_count + (index - old_count);
        gone = moved[(size_t)index] < 0;
        return moved[(size_t)index];
    };
    bool gone = false;
    if (g_app.core_selected >= 0) {
        const int to = remap(g_app.core_selected, gone);
        if (gone) apply_transport(0);
        else g_app.core_selected = to;
    }
    std::vector<int> rebuilt;
    rebuilt.reserve(g_app.chain_transports.size());
    for (int transport : g_app.chain_transports) {
        if (!transport_is_core(transport)) {
            rebuilt.push_back(transport);
            continue;
        }
        const int to = remap(transport - kCoreTransportBase, gone);
        if (!gone) rebuilt.push_back(kCoreTransportBase + to);
    }
    g_app.chain_transports.swap(rebuilt);
    if (s_core_editor_row >= 0) {
        const int to = remap(s_core_editor_row, gone);
        if (gone) {
            s_core_editor_row = -1;
            s_core_editor_open = false;
        } else {
            s_core_editor_row = to;
        }
    }
}

struct CoreGroupChange {
    int total = 0;
    int added = 0;
    int removed = 0;
    /// The config the main protocol ran is no longer in the subscription.
    bool lost_selection = false;
};

/// Put what a subscription now offers into `group`, in place of what it held.
/// A config the feed still lists under the same name stays the same row as far
/// as the protocol choice and the chain are concerned. Returns false and leaves
/// the group alone when nothing usable came back: a feed that is down must not
/// empty the list the user connects with.
static bool core_group_apply(int group, const std::string& group_name,
                             SubscriptionParse& parsed, CoreGroupChange& change) {
    const int old_count = (int)g_app.core_configs.size();
    int outside = 0;
    for (const AppState::CoreConfigEntry& entry : g_app.core_configs)
        if (entry.group != group) ++outside;

    std::vector<AppState::CoreConfigEntry> fresh;
    fresh.reserve(parsed.profiles.size());
    const auto taken = [&](const std::string& name) {
        for (const AppState::CoreConfigEntry& entry : g_app.core_configs)
            if (entry.group != group && core_names_equal(entry.name, name)) return true;
        for (const AppState::CoreConfigEntry& entry : fresh)
            if (core_names_equal(entry.name, name)) return true;
        return false;
    };
    const bool lone = parsed.profiles.size() == 1;
    for (SubscriptionProfile& profile : parsed.profiles) {
        if (outside + (int)fresh.size() >= kMaxCoreConfigs) {
            ++parsed.skipped;
            if (parsed.first_problem.empty()) parsed.first_problem = core_list_limit_text();
            continue;
        }
        AppState::CoreConfigEntry entry;
        entry.backend = profile.backend;
        entry.group = group;
        // A feed that is one unnamed config is what the group is: it goes by
        // the group's name instead of a made-up one.
        if (!profile.name.empty()) entry.name = unique_core_name(profile.name, taken);
        else if (lone && !group_name.empty()) entry.name = unique_core_name(group_name, taken);
        else entry.name = numbered_config_name(profile.text, profile.backend, taken);
        entry.text = std::move(profile.text);
        AppState::refresh_core_listeners(entry);
        fresh.push_back(std::move(entry));
    }
    if (fresh.empty()) return false;

    // The group keeps its place in the list: its new configs go where its first
    // old one was, or at the end when it held none.
    int insert_at = outside;
    {
        int before = 0;
        for (const AppState::CoreConfigEntry& entry : g_app.core_configs) {
            if (entry.group == group) {
                insert_at = before;
                break;
            }
            ++before;
        }
    }
    std::vector<int> moved((size_t)old_count, -1);
    std::vector<AppState::CoreConfigEntry> rebuilt;
    rebuilt.reserve((size_t)outside + fresh.size());
    const int fresh_count = (int)fresh.size();
    int kept = 0;
    for (int i = 0, others = 0; i < old_count; ++i) {
        const AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)i];
        if (entry.group != group) {
            moved[(size_t)i] = others < insert_at ? others : others + fresh_count;
            ++others;
            continue;
        }
        for (int j = 0; j < fresh_count; ++j) {
            if (core_names_equal(fresh[(size_t)j].name, entry.name)) {
                moved[(size_t)i] = insert_at + j;
                ++kept;
                break;
            }
        }
    }
    change.total = fresh_count;
    change.added = fresh_count - kept;
    change.removed = (old_count - outside) - kept;
    change.lost_selection = g_app.core_selected >= 0 && g_app.core_selected < old_count
        && moved[(size_t)g_app.core_selected] < 0;

    bool inserted = false;
    const auto insert_fresh = [&] {
        for (AppState::CoreConfigEntry& entry : fresh) rebuilt.push_back(std::move(entry));
        inserted = true;
    };
    for (int i = 0, others = 0; i < old_count; ++i) {
        AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)i];
        if (entry.group == group) continue;
        if (!inserted && others == insert_at) insert_fresh();
        rebuilt.push_back(std::move(entry));
        ++others;
    }
    if (!inserted) insert_fresh();
    g_app.core_configs.swap(rebuilt);
    core_configs_remap(moved);
    return true;
}

/// Remove a group and every config it holds.
static void core_group_remove(int group) {
    if (group < 0 || group >= (int)g_app.core_groups.size()) return;
    const int old_count = (int)g_app.core_configs.size();
    std::vector<int> moved((size_t)old_count, -1);
    std::vector<AppState::CoreConfigEntry> rebuilt;
    rebuilt.reserve(g_app.core_configs.size());
    for (int i = 0; i < old_count; ++i) {
        AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)i];
        if (entry.group == group) continue;
        if (entry.group > group) --entry.group;
        moved[(size_t)i] = (int)rebuilt.size();
        rebuilt.push_back(std::move(entry));
    }
    g_app.core_configs.swap(rebuilt);
    g_app.core_groups.erase(g_app.core_groups.begin() + group);
    if ((size_t)group < s_core_group_open.size())
        s_core_group_open.erase(s_core_group_open.begin() + group);
    core_configs_remap(moved);
    // The dialogs name groups by position as well, and so does a download that
    // is still on its way: one for this group is left with a position no group
    // has, so its result is dropped instead of filling another group.
    if (s_core_import_group == group) s_core_import_group = -1;
    else if (s_core_import_group > group) --s_core_import_group;
    if (s_core_fetch_group == group) s_core_fetch_group = kMaxCoreGroups;
    else if (s_core_fetch_group > group && s_core_fetch_group < kMaxCoreGroups) --s_core_fetch_group;
}

/// How long ago a group was filled, as its row says it: "5 min ago", or
/// nothing for a group that never was.
static std::string core_group_age(int64_t updated) {
    if (updated <= 0) return {};
    const int64_t age = (int64_t)std::time(nullptr) - updated;
    char text[32];
    if (age < 90) return "just now";
    if (age < 5400) snprintf(text, sizeof(text), "%d min ago", (int)((age + 30) / 60));
    else if (age < 2 * 86400) snprintf(text, sizeof(text), "%d h ago", (int)((age + 1800) / 3600));
    else snprintf(text, sizeof(text), "%d d ago", (int)(age / 86400));
    return text;
}
/// The same as a clause: "updated 5 min ago", or "never updated".
static std::string core_group_updated(int64_t updated) {
    const std::string age = core_group_age(updated);
    return age.empty() ? "never updated" : "updated " + age;
}

static void set_core_import_status(bool error, bool warning, const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(s_core_import_status, sizeof(s_core_import_status), format, args);
    va_end(args);
    s_core_import_status_error = error;
    s_core_import_status_warning = warning;
    ++s_core_import_status_revision;
}

/// How a download, a save or a removal ended is news for a moment and after
/// that only in the way, so the line takes itself down: after five seconds, or
/// after the time a longer one takes to read. What a download is doing stays
/// up for as long as it runs.
static void expire_core_import_status(double now) {
    static uint64_t timed_revision = 0;
    static double deadline = 0.0;
    if (!s_core_import_status[0] || s_core_import_in_progress) {
        deadline = 0.0;
        return;
    }
    if (!deadline || timed_revision != s_core_import_status_revision) {
        timed_revision = s_core_import_status_revision;
        deadline = now + std::clamp(2.0 + (double)strlen(s_core_import_status) / 20.0, 5.0, 12.0);
        return;
    }
    if (now >= deadline) {
        s_core_import_status[0] = 0;
        deadline = 0.0;
        ui_request_redraw();
    }
}

/// `text` as the end of a status sentence: with a full stop, but only one.
static std::string sentence_end(std::string text) {
    while (!text.empty() && std::isspace((unsigned char)text.back())) text.pop_back();
    if (!text.empty() && text.back() != '.' && text.back() != '!' && text.back() != '?') text.push_back('.');
    return text;
}

/// A download finished: fill the group it was for, creating it for an import.
static void finish_core_subscription_fetch(const std::string& body, const std::string& header_title,
                                           const std::string& file_name) {
    SubscriptionParse parsed = parse_core_subscription(body);
    int group = s_core_fetch_group;
    const bool creating = group < 0;
    if (!creating && group >= (int)g_app.core_groups.size()) {
        set_core_import_status(true, false, "The group was removed before its subscription arrived.");
        return;
    }
    if (creating && g_app.core_groups.size() >= (size_t)kMaxCoreGroups) {
        set_core_import_status(true, false, "There are already %d groups. Remove one first.", kMaxCoreGroups);
        return;
    }
    // The response header is the feed speaking for itself; a title line in the
    // body is the same statement by other means. The name of the file it is
    // sent as is all a Clash-style feed says, and says less: it comes last.
    const std::string title = !header_title.empty() ? header_title
        : !parsed.title.empty() ? parsed.title : file_name;
    std::string name;
    if (creating) {
        name = core_group_auto_name(s_core_fetch_name, title, s_core_fetch_url, -1);
    } else if (s_core_fetch_origin == kCoreFetchManage) {
        // The dialog's name field decides, and emptied it asks for the feed's.
        name = core_group_auto_name(s_core_fetch_name, title, s_core_fetch_url, group);
    } else if (!clean_core_name(s_core_fetch_name).empty()) {
        // A URL that is already a group, imported again under a name.
        name = core_group_auto_name(s_core_fetch_name, {}, s_core_fetch_url, group);
    } else {
        name = g_app.core_groups[(size_t)group].name;
    }
    if (creating) {
        g_app.core_groups.emplace_back();
        group = (int)g_app.core_groups.size() - 1;
    }
    CoreGroupChange change;
    if (!core_group_apply(group, name, parsed, change)) {
        if (creating) g_app.core_groups.pop_back();
        const std::string problem = sentence_end(parsed.first_problem.empty()
            ? "check the URL" : parsed.first_problem);
        set_core_import_status(true, false, "Nothing was imported: %s%s", problem.c_str(),
            creating ? "" : " The group keeps the configs it had.");
        return;
    }
    {
        AppState::CoreGroupEntry& entry = g_app.core_groups[(size_t)group];
        entry.name = name;
        entry.url = s_core_fetch_url;
        // Each config keeps its own core now. The field stays in the settings
        // file for the builds that read one core per group.
        entry.backend = parsed.profiles.empty() ? 0 : parsed.profiles.front().backend;
        entry.updated = (int64_t)std::time(nullptr);
    }
    if (s_core_group_open.size() < g_app.core_groups.size())
        s_core_group_open.resize(g_app.core_groups.size(), 0);
    if (s_core_fetch_origin == kCoreFetchImport) {
        // An import answers in the list: the dialog closes on the group it
        // made, or found, opened and in view.
        s_core_group_open[(size_t)group] = 1;
        s_core_group_reveal = group;
        s_core_import_should_close = true;
    } else if (s_core_fetch_origin == kCoreFetchManage && s_core_import_group == group) {
        snprintf(s_core_import_name, sizeof(s_core_import_name), "%s", name.c_str());
        snprintf(s_core_import_url, sizeof(s_core_import_url), "%s", s_core_fetch_url.c_str());
    }
    std::string text;
    char counts[192];
    if (creating) {
        snprintf(counts, sizeof(counts), "Imported %d config%s into \"%s\".",
                 change.total, change.total == 1 ? "" : "s", name.c_str());
    } else {
        snprintf(counts, sizeof(counts), "\"%s\" now has %d config%s (%d new, %d removed).",
                 name.c_str(), change.total, change.total == 1 ? "" : "s", change.added, change.removed);
    }
    text = counts;
    if (parsed.skipped > 0) {
        snprintf(counts, sizeof(counts), " Skipped %d line%s", parsed.skipped, parsed.skipped == 1 ? "" : "s");
        text += counts;
        text += parsed.first_problem.empty() ? "." : ": " + sentence_end(parsed.first_problem);
    }
    if (change.lost_selection)
        text += " The config that was selected as the protocol is no longer in it, so the protocol was reset.";
    set_core_import_status(false, parsed.skipped > 0 || change.lost_selection, "%s", text.c_str());
}

/// Download `url` for `group`, or for a group that does not exist yet (`-1`).
/// `name` is what the user typed as the group's name, "" when nothing.
static void begin_core_subscription_fetch(int group, const std::string& url_text, const std::string& name,
                                          CoreFetchOrigin origin) {
    const std::string url = trim_subscription_text(url_text);
    if (url.empty()) {
        set_core_import_status(true, false, "Enter the subscription URL.");
        return;
    }
    s_core_fetch_group = group;
    s_core_fetch_url = url;
    s_core_fetch_name = name;
    s_core_fetch_origin = origin;
    if (group >= 0 && group < (int)g_app.core_groups.size())
        set_core_import_status(false, false, "Refreshing \"%s\"...", g_app.core_groups[(size_t)group].name.c_str());
    else
        set_core_import_status(false, false, "Downloading subscription...");
    uint64_t request_id;
    {
        std::lock_guard<std::mutex> lock(s_core_import_mutex);
        request_id = ++s_core_import_request_id;
        s_core_import_awaiting = true;
        s_core_import_result_ready = false;
        s_core_import_result.clear();
        s_core_import_result_title.clear();
        s_core_import_result_file_name.clear();
    }
    s_core_import_in_progress = true;
    try {
        std::thread([request_id, url] {
            try {
                std::vector<char> response((size_t)FCAE_SUBSCRIPTION_MAX_BODY + 1, '\0');
                char title[256] = {};
                char file_name[256] = {};
                const bool success = fcae_fetch_subscription_titled(
                    url.c_str(), response.data(), (uint32_t)response.size(), title, sizeof(title),
                    file_name, sizeof(file_name));
                ui_core_subscription_fetch_complete(request_id, success, response.data(), title, file_name);
            } catch (...) {
                ui_core_subscription_fetch_complete(request_id, false,
                    "Could not start the subscription download.", {}, {});
            }
        }).detach();
    } catch (...) {
        ui_core_subscription_fetch_complete(request_id, false,
            "Could not start the subscription download.", {}, {});
    }
}

static void cancel_core_subscription_fetch() {
    {
        std::lock_guard<std::mutex> lock(s_core_import_mutex);
        ++s_core_import_request_id;
        s_core_import_awaiting = false;
        s_core_import_result_ready = false;
        s_core_import_result.clear();
        s_core_import_result_title.clear();
        s_core_import_result_file_name.clear();
    }
    s_core_import_in_progress = false;
    set_core_import_status(false, false, "Download cancelled.");
}

static void poll_core_subscription_fetch() {
    bool ready = false;
    bool success = false;
    std::string result, title, file_name;
    {
        std::lock_guard<std::mutex> lock(s_core_import_mutex);
        if (s_core_import_result_ready) {
            ready = true;
            success = s_core_import_result_ok;
            result = std::move(s_core_import_result);
            title = std::move(s_core_import_result_title);
            file_name = std::move(s_core_import_result_file_name);
            s_core_import_result.clear();
            s_core_import_result_title.clear();
            s_core_import_result_file_name.clear();
            s_core_import_result_ready = false;
            s_core_import_awaiting = false;
        }
    }
    if (!ready) return;
    s_core_import_in_progress = false;
    if (!success) {
        // The engine's reasons start lower case; a status line is a sentence.
        if (!result.empty()) result[0] = (char)std::toupper((unsigned char)result[0]);
        set_core_import_status(true, false, "%s", sentence_end(result).c_str());
    } else {
        finish_core_subscription_fetch(result, title, file_name);
    }
}

// ---- Paste ------------------------------------------------------------------------
//
// "+ Paste" adds what the clipboard holds and asks nothing: share links, one
// to a line, or one native config, either of them possibly base64-encoded.
// That is what a subscription's body may be, and it is read by the same
// parser, so each config goes under the first of Xray, sing-box and Mihomo
// that accepts it. A lone web address that none of them runs as a proxy is
// where a subscription is fetched from, and is imported as one.

/// Whether `text` is one http(s) address and nothing else.
static bool is_web_address(const std::string& text) {
    if (text.size() >= sizeof(s_core_import_url)) return false;
    if (!subscription_line_opens_with(text, "https://") && !subscription_line_opens_with(text, "http://"))
        return false;
    return std::none_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isspace(c) != 0 || std::iscntrl(c) != 0;
    });
}

/// Whether a web address names a user or a port, the way one that is a proxy
/// does: `https://user:secret@host`, `http://10.0.0.1:8080`. The link grammar
/// also reads a bare `https://host` as an open proxy on port 443, but nobody
/// shares a proxy like that and every site's address looks like it, so one
/// that names neither is never offered to the cores.
static bool web_address_names_proxy(const std::string& url) {
    const size_t begin = url.find("://") + 3;
    const size_t end = url.find_first_of("/?#", begin);
    const std::string authority = url.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    if (authority.find('@') != std::string::npos) return true;
    // A colon inside brackets belongs to an IPv6 address.
    const size_t colon = authority.rfind(':');
    return colon != std::string::npos && colon + 1 < authority.size()
        && authority.find(']', colon) == std::string::npos;
}

/// Add what `clipboard` holds to the configs added by hand, and say on the
/// list's status line what became of it.
static void paste_core_configs(const char* clipboard) {
    const std::string text = trim_subscription_text(clipboard ? clipboard : "");
    if (text.empty()) {
        set_core_import_status(true, false, "The clipboard holds no text.");
        return;
    }
    if (text.size() > FCAE_SUBSCRIPTION_MAX_BODY) {
        set_core_import_status(true, false, "The clipboard holds more than %u MiB of text.",
                               (unsigned)(FCAE_SUBSCRIPTION_MAX_BODY / (1024u * 1024u)));
        return;
    }
    const bool web_address = is_web_address(text);
    SubscriptionParse parsed;
    if (!web_address || web_address_names_proxy(text)) parsed = parse_core_subscription(text);
    if (parsed.profiles.empty() && web_address) {
        // The same URL is the group that already exists: it is refreshed, the
        // way the import dialog does it.
        int existing = -1;
        for (int g = 0; g < (int)g_app.core_groups.size() && existing < 0; ++g)
            if (g_app.core_groups[(size_t)g].url == text) existing = g;
        begin_core_subscription_fetch(existing, text, {}, kCoreFetchImport);
        return;
    }
    if (parsed.profiles.empty()) {
        set_core_import_status(true, false, "Nothing was added: %s", sentence_end(
            parsed.first_problem.empty() ? "the clipboard holds no config" : parsed.first_problem).c_str());
        return;
    }
    const auto taken = [](const std::string& name) { return !core_config_name_free(name.c_str(), -1); };
    int added = 0;
    int known = 0;
    int per_core[3] = {};
    int first_row = -1;
    for (SubscriptionProfile& profile : parsed.profiles) {
        // Pasting the same text twice is one config, not two: without this a
        // second press doubles a list that has no way to remove rows in bulk.
        const bool saved = std::any_of(g_app.core_configs.begin(), g_app.core_configs.end(),
            [&](const AppState::CoreConfigEntry& entry) {
                return core_config_group(entry) < 0 && entry.backend == profile.backend
                    && entry.text == profile.text;
            });
        if (saved) {
            ++known;
            continue;
        }
        if (g_app.core_configs.size() >= (size_t)kMaxCoreConfigs) {
            ++parsed.skipped;
            if (parsed.first_problem.empty()) parsed.first_problem = core_list_limit_text();
            continue;
        }
        AppState::CoreConfigEntry entry;
        entry.backend = profile.backend;
        entry.name = profile.name.empty() ? numbered_config_name(profile.text, profile.backend, taken)
                                          : unique_core_name(profile.name, taken);
        entry.text = std::move(profile.text);
        AppState::refresh_core_listeners(entry);
        if (first_row < 0) first_row = (int)g_app.core_configs.size();
        ++per_core[std::clamp(entry.backend, 0, 2)];
        g_app.core_configs.push_back(std::move(entry));
        ++added;
    }
    if (added == 0 && known == 0) {
        // Every one of them ran into the list's limit.
        set_core_import_status(true, false, "Nothing was added: %s", sentence_end(parsed.first_problem).c_str());
        return;
    }
    std::string message;
    char part[192];
    if (added == 1) {
        const AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)first_row];
        snprintf(part, sizeof(part), "Added \"%s\" (%s).", entry.name.c_str(),
                 AppState::core_backend_name(entry.backend));
        message = part;
    } else if (added > 1) {
        // Which cores took them, where it was not one core for all of them.
        std::string cores;
        int cores_used = 0;
        for (int backend = 0; backend < 3; ++backend) {
            if (!per_core[backend]) continue;
            snprintf(part, sizeof(part), "%s%d %s", cores.empty() ? "" : ", ", per_core[backend],
                     AppState::core_backend_name(backend));
            cores += part;
            ++cores_used;
        }
        if (cores_used == 1) snprintf(part, sizeof(part), "Added %s configs.", cores.c_str());
        else snprintf(part, sizeof(part), "Added %d configs: %s.", added, cores.c_str());
        message = part;
    }
    if (known > 0) {
        if (added > 0) snprintf(part, sizeof(part), " %d more %s already saved.", known, known == 1 ? "was" : "were");
        else if (known == 1) snprintf(part, sizeof(part), "This config is already saved.");
        else snprintf(part, sizeof(part), "These %d configs are already saved.", known);
        message += part;
    }
    if (parsed.skipped > 0) {
        snprintf(part, sizeof(part), "%sSkipped %d line%s", message.empty() ? "" : " ", parsed.skipped,
                 parsed.skipped == 1 ? "" : "s");
        message += part;
        message += parsed.first_problem.empty() ? "." : ": " + sentence_end(parsed.first_problem);
    }
    if (added > 0) s_core_row_reveal = first_row;
    set_core_import_status(false, added == 0 || parsed.skipped > 0, "%s", message.c_str());
}

/// "+ Paste" was pressed.
static void request_core_paste() {
    if (!UiText::refresh_clipboard) {
        paste_core_configs(ImGui::GetClipboardText());
        return;
    }
    // This host hands ImGui a copy of the clipboard and reads the real one on
    // its own thread, so what is there now arrives a frame or two from here.
    s_core_paste_pending = true;
    s_core_paste_revision = UiText::clipboard_revision;
    s_core_paste_deadline = ui_now_seconds() + 3.0;
    UiText::refresh_clipboard();
    ui_request_redraw();
}

/// Carry out a paste whose clipboard has arrived, or give up on one that never
/// will. Called on every frame the saved-configs dialog draws.
static void poll_core_paste() {
    if (!s_core_paste_pending) return;
    if (UiText::clipboard_revision != s_core_paste_revision) {
        s_core_paste_pending = false;
        paste_core_configs(ImGui::GetClipboardText());
    } else if (ui_now_seconds() >= s_core_paste_deadline) {
        s_core_paste_pending = false;
        set_core_import_status(true, false, "Could not read the clipboard.");
    } else {
        // Frames are what brings the answer, and the deadline, round.
        ui_request_redraw();
    }
}

/// Validate the editor's buffers against the rules the engine parses the
/// library with, so a config that saves is a config that runs: the name is a
/// reference in that document and must be unique, the profile has to parse for
/// the core it is stored under, and every field is bounded in bytes.
///
/// `row` is the entry being rewritten, or -1 for one that does not exist yet.
static void core_config_check(int row) {
    s_core_status_error = true;
    s_core_auto_name.clear();
    const std::string name = trim_subscription_text(s_core_name_buf);
    const bool empty_text = s_core_text_buf.empty() || s_core_text_buf[0] == 0;
    if (name.empty() && empty_text) {
        // A form nobody has filled in yet is not a mistake to paint red: the
        // Save button stays disabled and the status stays silent.
        s_core_status[0] = 0;
        return;
    }
    // The name is optional: left empty, the config goes by the name it gives
    // itself, or by one made up for it (below, once it is known to be valid).
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
    if (!name.empty() && !core_config_name_free(name.c_str(), row)) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Another config is already called \"%s\".", name.c_str());
        return;
    }
    if (empty_text) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Paste a share link or the core's native config.");
        return;
    }
    const size_t length = strlen(s_core_text_buf.data());
    if (length > kMaxCoreConfigText) {
        snprintf(s_core_status, sizeof(s_core_status),
                 "Configs are limited to %d KiB.", (int)(kMaxCoreConfigText / 1024));
        return;
    }
    char reason[224] = {};
    const int32_t backend = AppState::core_backend_id(s_core_backend_buf);
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
    const char* core = AppState::core_backend_name(s_core_backend_buf);
    // Said before Save, so the row that appears is the row that was promised.
    std::string saved_as;
    if (name.empty()) {
        const auto taken = [&](const std::string& candidate) {
            return !core_config_name_free(candidate.c_str(), row);
        };
        s_core_auto_name = core_auto_name(s_core_text_buf.data(), s_core_backend_buf, taken);
        saved_as = " It will be saved as \"" + s_core_auto_name + "\".";
    }
    if ((kinds & FCAE_CORE_LISTENER_SOCKS) == 0) {
        s_core_status_error = false;
        snprintf(s_core_status, sizeof(s_core_status),
                 "Valid %s config. It declares no SOCKS5 inbound, so TUN mode and a chained "
                 "hop cannot run it.%s", core, saved_as.c_str());
        return;
    }
    s_core_status_error = false;
    snprintf(s_core_status, sizeof(s_core_status), "Valid %s config.%s", core, saved_as.c_str());
}

/// Store the editor's buffers as the row it was opened on, or as a new one.
/// Only called with a validated form, so the entry it writes always parses.
static void apply_core_editor() {
    AppState::CoreConfigEntry entry;
    entry.name = trim_subscription_text(s_core_name_buf);
    if (entry.name.empty()) entry.name = s_core_auto_name;
    entry.backend = s_core_backend_buf;
    entry.text = s_core_text_buf.data();
    if (s_core_editor_row >= 0 && s_core_editor_row < (int)g_app.core_configs.size()) {
        // An edited config stays in the subscription group it came from.
        entry.group = g_app.core_configs[(size_t)s_core_editor_row].group;
        g_app.core_configs[(size_t)s_core_editor_row] = std::move(entry);
    } else {
        g_app.core_configs.push_back(std::move(entry));
    }
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
    const char* label = AppState::core_backend_name(backend);
    bool& socks_enabled = backend == 2 ? g_app.mihomo_socks_enabled : backend == 1 ? g_app.singbox_socks_enabled : g_app.xray_socks_enabled;
    bool& http_enabled  = backend == 2 ? g_app.mihomo_http_enabled : backend == 1 ? g_app.singbox_http_enabled : g_app.xray_http_enabled;
    uint16_t& socks_port = backend == 2 ? g_app.mihomo_socks_port : backend == 1 ? g_app.singbox_socks_port : g_app.xray_socks_port;
    uint16_t& http_port  = backend == 2 ? g_app.mihomo_http_port : backend == 1 ? g_app.singbox_http_port : g_app.xray_http_port;

    // Both pairs stay live whatever the library holds. The switch is a stored
    // preference and the port is a stored value either way; what a listener can
    // answer on is decided at start time, by the config the session runs.
    ImGui::Spacing();
    ImGui::TextDisabled("%s listener", label);
    listener_row(backend == 2 ? "Mihomo SOCKS5" : backend == 1 ? "sing-box SOCKS5" : "Xray SOCKS5", &socks_enabled, &socks_port, 1, 65535);
    listener_row(backend == 2 ? "Mihomo HTTP" : backend == 1 ? "sing-box HTTP" : "Xray HTTP", &http_enabled, &http_port, 1, 65535);
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
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_HorizontalScrollbar)) return;

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
    changed |= UiText::InputTextWithHint("##core_name", "optional: taken from the config when left empty",
                                        s_core_name_buf, kMaxCoreConfigName + 1);
    ImGui::PopItemWidth();
    // Three cores, so all stay on screen: radio circles like Outbound IP
    // version, not a dropdown that hides a choice behind a click.
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
        ImGui::SameLine();
        if (ImGui::RadioButton("Mihomo", s_core_backend_buf == 2)) {
            s_core_backend_buf = 2;
            changed = true;
        }
        ImGui::PopStyleColor();
    }
    ImGui::Spacing();
    UiText::TextColoredWrapped(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled),
                              "Config (share link or native config)");
    const float status_width = std::max(1.0f, ImGui::GetContentRegionAvail().x
        - ImGui::GetStyle().WindowPadding.x * 2.0f - ImGui::GetStyle().ScrollbarSize);
    const float status_height = std::clamp(ImGui::CalcTextSize(s_core_status, nullptr, false, status_width).y,
        ImGui::GetTextLineHeight(), ImGui::GetTextLineHeightWithSpacing() * 5.0f);
    float text_height = ImGui::GetContentRegionAvail().y
        - status_height - ImGui::GetFrameHeightWithSpacing()
        - ImGui::GetStyle().ItemSpacing.y * 3.0f;
    if (text_height < 160.0f) text_height = 160.0f;
    changed |= UiText::InputTextMultiline("##core_text", s_core_text_buf.data(),
                                         s_core_text_buf.size(), ImVec2(-FLT_MIN, text_height), ImGuiInputTextFlags_WordWrap);
    if (changed) core_config_check(s_core_editor_row);
    ImGui::BeginChild("##core_validation", ImVec2(0, status_height));
    UiText::TextColoredWrapped(s_core_status_error ? ImVec4(0.95f, 0.38f, 0.38f, 1.0f)
                                           : ImVec4(0.3f, 0.9f, 0.4f, 1.0f),
                       "%s", s_core_status);
    ImGui::EndChild();
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

static ImVec4 core_import_status_color() {
    return s_core_import_status_error ? ImVec4(0.95f, 0.38f, 0.38f, 1.0f)
        : s_core_import_status_warning ? ImVec4(0.95f, 0.72f, 0.25f, 1.0f)
        : ImVec4(0.3f, 0.9f, 0.4f, 1.0f);
}

/// The tooltip of the button just drawn. Pressing the button puts it away until
/// the pointer has left: a tooltip opens just under the pointer, and that is
/// where a press shows what it did -- the message under a dialog's buttons, the
/// rows of the group a list button refreshed.
static void core_button_tooltip(bool pressed, const char* text) {
    static ImGuiID s_pressed = 0;
    static int s_pressed_frame = 0;
    const int frame = ImGui::GetFrameCount();
    const ImGuiID id = ImGui::GetItemID();
    // Disabled still counts as under the pointer: a button is disabled for as
    // long as the download it started is running.
    const bool over = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled);
    if (pressed) s_pressed = id;
    else if (s_pressed == id && (!over || s_pressed_frame + 1 < frame)) s_pressed = 0;
    if (s_pressed == id) {
        s_pressed_frame = frame;
        return;
    }
    if (over && ImGui::IsItemHovered()) UiText::Tooltip("%s", text);
}

/// The subscription dialog: a URL and the group it fills. It imports a new
/// group, or edits one that exists: refresh it from its URL, rename or
/// re-point it, remove it. The core is not asked for: each config goes under
/// the first of Xray, sing-box and Mihomo that takes it.
static void render_core_subscription_import() {
    static const char* const kTitle = "##core-subscription-import";
    if (s_core_import_popup_open) {
        ImGui::OpenPopup(kTitle);
        s_core_import_popup_open = false;
    }
    poll_core_subscription_fetch();
    s_core_import_visible = false;
    if (!begin_account_dialog(kTitle, 620.0f)) return;
    if (s_core_import_group >= (int)g_app.core_groups.size()) s_core_import_group = -1;
    const bool managing = s_core_import_group >= 0;
    if (s_core_import_should_close) {
        s_core_import_should_close = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    s_core_import_visible = true;
    // One download runs at a time, and it may have been started from the list
    // behind this dialog: only the dialog's own download is its to cancel.
    const bool busy = s_core_import_in_progress;
    const bool busy_here = busy && s_core_fetch_origin != kCoreFetchList;

    ImGui::TextColored(ImVec4(0.38f, 0.65f, 0.98f, 1.0f),
                       managing ? "Edit subscription group" : "Import a subscription URL");
    ImGui::Separator();
    ImGui::BeginDisabled(busy_here);
    // Enter in either field is the dialog's primary button.
    bool enter = false;
    ImGui::TextDisabled("Subscription URL");
    ImGui::PushItemWidth(-FLT_MIN);
    enter |= UiText::InputTextWithHint("##core_subscription_url", "https://example.com/subscription",
                                       s_core_import_url, sizeof(s_core_import_url),
                                       ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::TextDisabled("Group name (optional)");
    enter |= UiText::InputTextWithHint("##core_subscription_name", "named after the subscription when left empty",
                                       s_core_import_name, sizeof(s_core_import_name),
                                       ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopItemWidth();
    ImGui::EndDisabled();
    if (managing) {
        const int count = core_group_size(s_core_import_group);
        ImGui::TextDisabled("%d config%s, %s", count, count == 1 ? "" : "s",
            core_group_updated(g_app.core_groups[(size_t)s_core_import_group].updated).c_str());
    }
    ImGui::Spacing();

    const bool can_fetch = !busy && !trim_subscription_text(s_core_import_url).empty();
    ImGui::BeginDisabled(!can_fetch);
    if (!managing) {
        if ((ImGui::Button("Import") || enter) && can_fetch) {
            // The same URL is the group that already exists: importing it
            // again refreshes that group instead of copying it.
            const std::string url = trim_subscription_text(s_core_import_url);
            int existing = -1;
            for (int g = 0; g < (int)g_app.core_groups.size() && existing < 0; ++g)
                if (g_app.core_groups[(size_t)g].url == url) existing = g;
            begin_core_subscription_fetch(existing, url, s_core_import_name, kCoreFetchImport);
        }
    } else {
        const bool refresh = ImGui::Button("Refresh");
        core_button_tooltip(refresh,
            "Download the subscription again and replace this group's configs with what it lists now.");
        if ((refresh || enter) && can_fetch)
            begin_core_subscription_fetch(s_core_import_group, s_core_import_url, s_core_import_name,
                                          kCoreFetchManage);
        // Refresh fetches what the fields say and keeps it when that worked;
        // Save keeps it without asking the URL anything.
        button_row_next("Save");
        const bool save = secondary_button("Save");
        core_button_tooltip(save, "Keep the name and URL as written here without downloading anything.");
        if (save) {
            AppState::CoreGroupEntry& group = g_app.core_groups[(size_t)s_core_import_group];
            group.url = trim_subscription_text(s_core_import_url);
            group.name = core_group_auto_name(s_core_import_name, {}, group.url, s_core_import_group);
            snprintf(s_core_import_name, sizeof(s_core_import_name), "%s", group.name.c_str());
            snprintf(s_core_import_url, sizeof(s_core_import_url), "%s", group.url.c_str());
            set_core_import_status(false, false, "Saved.");
        }
    }
    ImGui::EndDisabled();
    if (managing) {
        button_row_next("Remove group");
        ImGui::BeginDisabled(busy);
        // One click, and no second question: the button says what it does,
        // and the URL brings the group back.
        if (secondary_button("Remove group")) {
            const std::string name = g_app.core_groups[(size_t)s_core_import_group].name;
            core_group_remove(s_core_import_group);
            s_core_import_group = -1;
            set_core_import_status(false, false, "Removed \"%s\".", name.c_str());
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
    }
    button_row_next("Cancel");
    if (secondary_button(busy_here ? "Cancel" : "Close")) {
        if (busy_here) cancel_core_subscription_fetch();
        ImGui::CloseCurrentPopup();
    }
    // Under the buttons, where the account dialogs say theirs: a message that
    // comes and goes makes the dialog longer or shorter and moves nothing in it.
    if (s_core_import_status[0])
        UiText::TextColoredWrapped(core_import_status_color(), "%s", s_core_import_status);
    ImGui::EndPopup();
}

/// One saved config's row: the name the user gave the config, the core that
/// runs it and the two things that can be done to it -- the same `name  core`
/// row the Android dialog shows. Buttons are the only items in a row that take
/// input, so nothing can swallow their clicks: a full-width Selectable claimed
/// the whole row, which is why Remove never fired.
static void core_config_row(int i, int& edit_row, int& remove_row) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float buttons_width = ImGui::CalcTextSize("Edit").x + ImGui::CalcTextSize("Remove").x
        + 4.0f * style.FramePadding.x + style.ItemSpacing.x;
    const AppState::CoreConfigEntry& entry = g_app.core_configs[(size_t)i];
    const char* tag = transport_tag(kCoreTransportBase + i);
    // Measured before the row draws anything: what the name may take is the
    // row less the buttons and the tag beside it, so the tag and the buttons
    // sit in the same place on every row and a long name cannot reach them.
    const float row_x = ImGui::GetCursorPosX();
    const float tag_width = tag ? ImGui::CalcTextSize(tag).x + kCoreTagGap : 0.0f;
    const float row_avail = std::max(ImGui::GetContentRegionAvail().x,
        buttons_width + tag_width + style.ItemSpacing.x * 2.0f + ImGui::CalcTextSize("...").x);
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

/// A subscription group's header: its name, what it holds, and the two things
/// that can be done to it. The whole bar opens and closes the group; the
/// buttons sit on top of it and take their own clicks. Returns whether the
/// group is open.
static bool core_group_header(int g, int& refresh_group, int& manage_group) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const AppState::CoreGroupEntry& group = g_app.core_groups[(size_t)g];
    const int count = core_group_size(g);
    const std::string name = group.name.empty() ? "(unnamed group)" : group.name;
    char count_text[32];
    snprintf(count_text, sizeof(count_text), "%d config%s", count, count == 1 ? "" : "s");
    const std::string age = core_group_age(group.updated);
    const std::string count_and_age = age.empty() ? std::string(count_text) : std::string(count_text) + ", " + age;
    const float buttons_width = ImGui::CalcTextSize("Refresh").x + ImGui::CalcTextSize("Edit").x
        + 4.0f * style.FramePadding.x + style.ItemSpacing.x;
    const float row_x = ImGui::GetCursorPosX();
    const float row_avail = std::max(ImGui::GetContentRegionAvail().x,
        buttons_width + ImGui::GetFrameHeight() + style.ItemSpacing.x * 3.0f + ImGui::CalcTextSize("...").x);
    ImGui::PushID("group");
    ImGui::PushID(g);
    ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.13f, 0.18f, 0.27f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.17f, 0.24f, 0.36f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0.21f, 0.31f, 0.45f, 1.0f));
    ImGui::SetNextItemOpen(s_core_group_open[(size_t)g] != 0, ImGuiCond_Always);
    const bool open = ImGui::TreeNodeEx("##header", ImGuiTreeNodeFlags_Framed
        | ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_AllowOverlap);
    ImGui::PopStyleColor(3);
    const bool bar_hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip);
    s_core_group_open[(size_t)g] = open ? 1 : 0;

    ImGui::SameLine();
    const float name_room = std::max(0.0f, row_x + row_avail - buttons_width - style.ItemSpacing.x - ImGui::GetCursorPosX());
    // Beside the name, as far as the row has room: how many configs and how
    // long since they were fetched, else how many, else the name alone. The
    // age gives way before the name is cut at all; the count only once the
    // name would be left too short to tell the groups apart.
    const float name_width = ImGui::CalcTextSize(name.c_str()).x;
    const char* detail = nullptr;
    if (name_room - ImGui::CalcTextSize(count_and_age.c_str()).x - kCoreTagGap >= name_width)
        detail = count_and_age.c_str();
    else if (name_room - ImGui::CalcTextSize(count_text).x - kCoreTagGap >= std::min(name_width, 160.0f))
        detail = count_text;
    ImGui::TextUnformatted(fit_core_name(name,
        name_room - (detail ? ImGui::CalcTextSize(detail).x + kCoreTagGap : 0.0f)).c_str());
    if (detail) {
        ImGui::SameLine(0.0f, kCoreTagGap);
        ImGui::TextDisabled("%s", detail);
    }
    bool button_hovered = false;
    ImGui::SameLine(row_x + row_avail - buttons_width);
    ImGui::BeginDisabled(s_core_import_in_progress);
    const bool refresh = ImGui::SmallButton("Refresh");
    if (refresh) refresh_group = g;
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) button_hovered = true;
    // Put away by the press: it would lie over the rows being refreshed.
    core_button_tooltip(refresh,
        "Download the subscription again and replace this group's configs with what it lists now.");
    ImGui::SameLine();
    if (ImGui::SmallButton("Edit")) manage_group = g;
    if (ImGui::IsItemHovered()) {
        button_hovered = true;
        UiText::Tooltip("Rename the group, change its URL, or remove it with its configs.");
    }
    // Everything about the group in one place, for the rows too narrow to say
    // it. The buttons lie on the bar, so over them it is theirs to explain.
    if (bar_hovered && !button_hovered)
        UiText::Tooltip("%s\n%s, %s", name.c_str(), count_text, core_group_updated(group.updated).c_str());
    ImGui::PopID();
    ImGui::PopID();
    return open;
}

/// The saved configs: the ones added by hand first, then each subscription
/// group under a header that opens it, refreshes it and manages it.
static void render_core_library() {
    const ImGuiStyle& style = ImGui::GetStyle();
    if (s_core_group_open.size() != g_app.core_groups.size())
        s_core_group_open.resize(g_app.core_groups.size(), 0);
    // The buttons under the list and the count beside them, on as many rows
    // as the dialog's width makes of them: one on a desktop, two on a phone.
    // Worked out before the list is drawn, because the list takes what they
    // and Close leave.
    static const char* const kButtons[] = { "+ Add config", "+ Paste", "+ Import URL" };
    char count_text[32];
    snprintf(count_text, sizeof(count_text), "%d/%d", (int)g_app.core_configs.size(), kMaxCoreConfigs);
    float item_width[4];
    for (int i = 0; i < 3; ++i)
        item_width[i] = ImGui::CalcTextSize(kButtons[i]).x + style.FramePadding.x * 2.0f;
    item_width[3] = ImGui::CalcTextSize(count_text).x;
    // Whether an item goes beside the one before it.
    bool beside[4] = {};
    int button_rows = 1;
    {
        const float row_width = ImGui::GetContentRegionAvail().x;
        float used = item_width[0];
        for (int i = 1; i < 4; ++i) {
            beside[i] = used + style.ItemSpacing.x + item_width[i] <= row_width;
            if (beside[i]) {
                used += style.ItemSpacing.x + item_width[i];
            } else {
                used = item_width[i];
                ++button_rows;
            }
        }
    }
    const float list_height = (std::max)(146.0f,
        ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * (float)(button_rows + 1));
    // What a subscription download is doing, or how the last one ended, is said
    // on a strip along the bottom of the list's own frame, up to three lines of
    // it. The message takes itself down again (expire_core_import_status), and
    // inside the frame its coming and going moves no button: the ones under
    // the list stay where they are, and the rows lend it the room.
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(style.ChildBorderSize, style.ChildBorderSize));
    ImGui::BeginChild("##core_list_frame", ImVec2(0, list_height), ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();
    const bool status_shown = s_core_import_status[0] && !s_core_import_visible;
    const float status_width = std::max(1.0f, ImGui::GetContentRegionAvail().x - style.WindowPadding.x * 2.0f);
    const float status_height = status_shown
        ? std::min(ImGui::CalcTextSize(s_core_import_status, nullptr, false, status_width).y,
                   ImGui::GetTextLineHeight() * 3.0f)
        : 0.0f;
    // A rule, and the same space above the words as under them.
    const float strip_height = status_shown ? status_height + style.ItemSpacing.y * 2.0f + 1.0f : 0.0f;
    ImGui::BeginChild("##core_list", ImVec2(0, -strip_height), ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_HorizontalScrollbar);
    {
        // A list that was scrolled to its end keeps its end in view: the rows
        // a refresh just changed are not what its message should cover.
        static float shown_strip_height = 0.0f;
        const float grown = strip_height - shown_strip_height;
        if (grown > 0.0f && ImGui::GetScrollY() > 0.0f
            && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - grown - 1.0f)
            ImGui::SetScrollY(ImGui::GetScrollMaxY());
        shown_strip_height = strip_height;
    }
    int edit_row = -1;
    int remove_row = -1;
    int refresh_group = -1;
    int manage_group = -1;
    for (int i = 0; i < (int)g_app.core_configs.size(); ++i) {
        if (core_config_group(g_app.core_configs[(size_t)i]) >= 0) continue;
        core_config_row(i, edit_row, remove_row);
        if (i == s_core_row_reveal) ImGui::SetScrollHereY(0.0f);
    }
    s_core_row_reveal = -1;
    for (int g = 0; g < (int)g_app.core_groups.size(); ++g) {
        const bool open = core_group_header(g, refresh_group, manage_group);
        if (g == s_core_group_reveal) ImGui::SetScrollHereY(0.0f);
        if (!open) continue;
        const float indent = ImGui::GetFontSize() + style.FramePadding.x;
        ImGui::Indent(indent);
        bool any = false;
        for (int i = 0; i < (int)g_app.core_configs.size(); ++i) {
            if (g_app.core_configs[(size_t)i].group != g) continue;
            core_config_row(i, edit_row, remove_row);
            any = true;
        }
        if (!any) ImGui::TextDisabled("No configs. Refresh to fetch them.");
        ImGui::Unindent(indent);
    }
    s_core_group_reveal = -1;
    if (g_app.core_configs.empty() && g_app.core_groups.empty()) {
        ImGui::TextDisabled("No configs found.");
    }
    ImGui::EndChild();
    if (status_shown) {
        const ImVec2 frame_min = ImGui::GetWindowPos();
        const ImVec2 frame_size = ImGui::GetWindowSize();
        const float strip_y = frame_min.y + frame_size.y - style.ChildBorderSize - strip_height;
        ImGui::GetWindowDrawList()->AddLine(
            ImVec2(frame_min.x + style.ChildBorderSize, strip_y),
            ImVec2(frame_min.x + frame_size.x - style.ChildBorderSize, strip_y),
            ImGui::GetColorU32(ImGuiCol_Separator));
        ImGui::SetCursorScreenPos(ImVec2(frame_min.x + style.ChildBorderSize + style.WindowPadding.x,
                                         strip_y + 1.0f + style.ItemSpacing.y));
        ImGui::BeginChild("##core_import_status", ImVec2(status_width, status_height));
        UiText::TextColoredWrapped(core_import_status_color(), "%s", s_core_import_status);
        ImGui::EndChild();
    }
    ImGui::EndChild();

    // Nothing is stored until Save: a config the engine cannot parse is one
    // library that does not start, and a draft is not a config yet. The count
    // beside it is the list's place in the library the engine accepts, and
    // nothing gates on it: the limit is there to be read, not to be hit.
    if (ImGui::Button(kButtons[0])) open_core_editor(-1);
    if (beside[1]) ImGui::SameLine();
    // One thing at a time on the status line: a paste waits for the download
    // that is writing there, and for the clipboard it has already asked for.
    ImGui::BeginDisabled(s_core_import_in_progress || s_core_paste_pending);
    const bool paste = ImGui::Button(kButtons[1]);
    ImGui::EndDisabled();
    core_button_tooltip(paste,
        "Add what is on the clipboard: share links, a native config or a subscription URL. "
        "Each config goes under the first of Xray, sing-box and Mihomo that accepts it.");
    if (beside[2]) ImGui::SameLine();
    if (ImGui::Button(kButtons[2])) open_core_subscription_import(-1);
    if (beside[3]) ImGui::SameLine();
    else ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("%s", count_text);

    // After the loops, so nothing reads a vector whose size changed under it.
    if (paste) request_core_paste();
    if (edit_row >= 0) open_core_editor(edit_row);
    if (remove_row >= 0) {
        g_app.core_configs.erase(g_app.core_configs.begin() + remove_row);
        // Re-points the protocol choice and the chain, and drops the editor's
        // own row number with the config it named.
        core_configs_forget(remove_row);
        g_app.refresh_core_listeners();
    }
    if (manage_group >= 0) open_core_subscription_import(manage_group);
    if (refresh_group >= 0) {
        const AppState::CoreGroupEntry& group = g_app.core_groups[(size_t)refresh_group];
        begin_core_subscription_fetch(refresh_group, group.url, {}, kCoreFetchList);
    }
}

static void render_core_configs() {
    static const char* const kTitle = "Xray / sing-box / Mihomo settings";
    bool opened = false;
    if (s_core_configs_popup_open) {
        ImGui::OpenPopup(kTitle);
        s_core_configs_popup_open = false;
        opened = true;
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(760.0f, 720.0f), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_HorizontalScrollbar)) return;

    // Before the list is drawn, so the frame the clipboard arrives on already
    // shows what was pasted.
    poll_core_paste();

    // Two pages, because one could not hold both: the listeners and the log
    // level under the list left it a few rows and still pushed Close off the
    // bottom of a window that does not resize. The library comes first: one
    // list of configs, because that is what all three cores run.
    const float close_height = ImGui::GetFrameHeightWithSpacing();
    if (ImGui::BeginTabBar("##core_pages")) {
        if (ImGui::BeginTabItem("Saved configs", nullptr, opened ? ImGuiTabItemFlags_SetSelected : 0)) {
            render_core_library();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Listeners")) {
            ImGui::BeginChild("##core_listeners", ImVec2(0, -close_height), ImGuiChildFlags_None,
                              ImGuiWindowFlags_HorizontalScrollbar);
            core_listener_block(0);
            core_listener_block(1);
            core_listener_block(2);
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
                ImGui::TextWrapped("Xray / sing-box / Mihomo log level");
                ImGui::SetNextItemWidth(std::min(log_combo_w, std::max(1.0f, ImGui::GetContentRegionAvail().x)));
                ImGui::Combo("##core_log_level", &g_app.core_log, kCoreLogs, 6);
                if (ImGui::IsItemHovered())
                    UiText::Tooltip("Applies on the next connection. Mihomo maps Trace to Debug.");
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    // The editor and the subscription dialog are modals of their own, opened
    // from the buttons above and drawn inside this one so they stay scoped to
    // the core settings.
    render_core_editor();
    render_core_subscription_import();
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
    if (!ImGui::BeginPopupModal("##protocol-editor", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_HorizontalScrollbar)) return;

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
    // A dangling saved selection remains unresolved until the user chooses a
    // replacement; opening this popup must not reset it to MASQUE.
    const int protocol_before = s_protocol_draft;
    // Saved configs read the way the settings list shows them: the ones added
    // by hand, then each subscription group under its name. Only the order on
    // screen is different; a row's value is still its position in the list.
    std::vector<int> rows;
    rows.reserve((size_t)transport_choices);
    for (int i = 0; i < transport_choices && i < kCoreTransportBase; ++i) rows.push_back(i);
    for (int group = -1; group < (int)g_app.core_groups.size(); ++group)
        for (int i = kCoreTransportBase; i < transport_choices; ++i)
            if (core_config_group(g_app.core_configs[(size_t)(i - kCoreTransportBase)]) == group) rows.push_back(i);
    int heading = -2;
    for (int i : rows) {
        if (i >= kCoreTransportBase) {
            const int group = core_config_group(g_app.core_configs[(size_t)(i - kCoreTransportBase)]);
            if (group != heading) {
                heading = group;
                ImGui::SeparatorText(group < 0 ? "Saved configs"
                    : g_app.core_groups[(size_t)group].name.c_str());
            }
        }
        // The position is the row's identity here: two saved configs may well
        // share a name, and a radio button's own id is its label.
        ImGui::PushID(i);
        changed |= ImGui::RadioButton(labels.names[(size_t)i].c_str(), &s_protocol_draft, i);
        ImGui::PopID();
    }
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    ImGui::Text("Additional exits");
    int remove_index = -1;
    for (size_t i = 0; i < s_chain_draft.size(); ++i) {
        ImGui::PushID((int)i);
        ImGui::Text("Exit %d", (int)i + 1);
        const float remove_width = ImGui::CalcTextSize("Remove").x + 2.0f * ImGui::GetStyle().FramePadding.x;
        ImGui::SetNextItemWidth(std::max(1.0f, ImGui::GetContentRegionAvail().x - remove_width - ImGui::GetStyle().ItemSpacing.x));
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
        if (s_protocol_draft != protocol_before) apply_transport(s_protocol_draft);
        // Selecting Tor or Psiphon never invents a MASQUE H3/Aether exit; only
        // the chain edits the user made above are applied.
        g_app.chain_transports = s_chain_draft;
    }
    ImGui::EndPopup();
}

static char s_firefox_relay_url[4097] = {};
static bool s_firefox_relay_error = false;

#include "urnetwork_ui.h"

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
    firefox_request_status();
    ImGui::BeginChild("##firefox_scroll",
        ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8.0f),
        ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
    const std::string root = firefox_json_escape(data_dir().c_str());
    firefox_location_combo();
    ImGui::Spacing();
    UiText::InputTextWithHint("Firefox relay URL", "Optional HTTP or HTTPS URL", s_firefox_relay_url,
        sizeof(s_firefox_relay_url));
    if (ImGui::IsItemDeactivatedAfterEdit()) {
        s_firefox_relay_error = !fcae_firefox_relay_set(data_dir().c_str(), s_firefox_relay_url);
    }
    if (s_firefox_relay_error)
        ImGui::TextWrapped("Could not save or load the relay URL. Use a valid HTTP or HTTPS URL; the previous setting may still be active.");
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    firefox_account_rows(root);
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    listener_row("Firefox SOCKS5", &g_app.firefox_socks_enabled, &g_app.firefox_socks_port, 1, 65535);
    listener_row("Firefox HTTP", &g_app.firefox_http_enabled, &g_app.firefox_http_port, 1, 65535);
    UiText::InputTextWithHint("Server override", "Optional proxy host[:port]", g_app.firefox_server, sizeof(g_app.firefox_server));
    static const char* const firefox_transports[] = {"Auto (H3 → H2 → H1)", "HTTP/2", "HTTP/1.1", "HTTP/3"};
    ImGui::Combo("Firefox transport", &g_app.firefox_transport, firefox_transports, 4);
    backend_log_combo("Firefox log level", 2, g_app.firefox_log);
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
    if (!begin_account_dialog("Add Firefox account", 520)) return;
    if (s_firefox_add_should_close) {
        s_firefox_add_should_close = false;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    s_firefox_captcha_embedded = true;
    render_firefox_captcha_content();
    const bool enter = account_identity_fields(g_app.firefox_email, sizeof(g_app.firefox_email),
        g_app.firefox_password, sizeof(g_app.firefox_password));
    const bool ready = g_app.firefox_job == 0 && g_app.firefox_email[0] && g_app.firefox_password[0];
    ImGui::BeginDisabled(!ready);
    const bool pressed = ImGui::Button("Sign in");
    ImGui::EndDisabled();
    if ((pressed || enter) && ready) {
        const std::string root = firefox_json_escape(data_dir().c_str());
        const std::string request = "{\"op\":\"login\",\"data_dir\":\"" + root
            + "\",\"email\":\"" + firefox_json_escape(g_app.firefox_email)
            + "\",\"password\":\"" + firefox_json_escape(g_app.firefox_password) + "\"}";
        g_app.firefox_pending_id[0] = 0;
        g_app.firefox_totp = false;
        s_firefox_unblock_required = false;
        firefox_submit(request, "Signing in to Firefox Accounts…");
    }
    button_row_next("Close");
    if (secondary_button("Close")) {
        if (!g_app.firefox_job && !s_firefox_unblock_required) {
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
        }
        ImGui::CloseCurrentPopup();
    }
    firefox_request_status();
    ImGui::EndPopup();
}

static void render_firefox_code_prompt() {
    const bool verification = g_app.firefox_pending_id[0] != 0;
    if (!verification && !s_firefox_unblock_required && !s_firefox_code_should_close) return;
    if (s_firefox_code_popup_open) {
        ImGui::OpenPopup("Firefox account security code");
        s_firefox_code_popup_open = false;
    }
    if (!begin_account_dialog("Firefox account security code", 500)) return;
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
    bool enter = false;
    if (!email_link) {
        ImGui::SetNextItemWidth(-FLT_MIN);
        enter = UiText::InputTextWithHint("##firefox_code", verification ? "Verification code" : "Unblock code",
            g_app.firefox_code, sizeof(g_app.firefox_code), ImGuiInputTextFlags_EnterReturnsTrue);
    }
    firefox_request_status();
    // Enter in the field is the dialog's primary button.
    const bool can_submit = g_app.firefox_job == 0 && (email_link || g_app.firefox_code[0]);
    enter = enter && can_submit;
    ImGui::BeginDisabled(!can_submit);
    if (verification && (ImGui::Button(email_link ? "Continue after opening link" : "Verify") || enter)) {
        const char* operation = g_app.firefox_totp ? "verify_totp" : email_link ? "confirm_email_link" : "verify_email";
        std::string request = std::string("{\"op\":\"") + operation + "\",\"data_dir\":\"" + root
            + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"";
        if (!email_link) request += ",\"code\":\"" + firefox_json_escape(g_app.firefox_code) + "\"";
        request += "}";
        firefox_submit(request, "Checking Firefox account verification…");
    }
    if (!verification && (ImGui::Button("Sign in with code") || enter)) {
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
        button_row_next("Resend email");
        if (secondary_button("Resend email")) {
            firefox_submit("{\"op\":\"resend\",\"data_dir\":\"" + root
                + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"}",
                "Resending verification code…");
        }
    }
    if (!verification) {
        button_row_next("Resend unblock code");
        if (secondary_button("Resend unblock code")) {
            firefox_submit("{\"op\":\"unblock\",\"data_dir\":\"" + root
                + "\",\"email\":\"" + firefox_json_escape(g_app.firefox_email) + "\"}",
                "Requesting another unblock code…");
        }
    }
    ImGui::EndDisabled();
    if (verification) {
        ImGui::BeginDisabled(g_app.firefox_job != 0);
        if (secondary_button("Cancel verification")) {
            firefox_submit("{\"op\":\"cancel\",\"data_dir\":\"" + root
                + "\",\"pending_id\":\"" + firefox_json_escape(g_app.firefox_pending_id) + "\"}",
                "Cancelling sign-in verification…");
        }
        ImGui::EndDisabled();
    } else {
        ImGui::BeginDisabled(g_app.firefox_job != 0);
        if (secondary_button("Cancel sign-in")) {
            g_app.firefox_password[0] = 0;
            g_app.firefox_code[0] = 0;
            s_firefox_unblock_required = false;
            s_firefox_email_link = false;
            set_firefox_status("Direct sign-in cancelled");
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
    }
    button_row_next("Later");
    if (secondary_button("Later")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

#ifdef _WIN32
static std::atomic<int> s_tray_toggle_requested{0};
// 0: none, 1: stop, 2: start. Preserve the action the menu displayed.
static std::atomic<int> s_tray_tun_requested{0};
void ui_request_tray_toggle(int action) {
    // The window thread consumes this even while the main window is hidden.
    // Refresh telemetry first so the action is checked against current state.
    g_app.last_telem_t = 0;
    s_tray_toggle_requested.store(action, std::memory_order_release);
    ui_request_redraw();
}
void ui_request_tray_tun_control(bool resume) {
    g_app.last_telem_t = 0;
    s_tray_tun_requested.store(resume ? 2 : 1, std::memory_order_release);
    ui_request_redraw();
}
bool ui_tray_action_pending() {
    return s_tray_toggle_requested.load(std::memory_order_acquire) != 0
        || s_tray_tun_requested.load(std::memory_order_acquire) != 0;
}
#endif

/// What the Home page's panels are drawn on. Straight on the background
/// picture, text is only as readable as the part of the picture behind it, and
/// the sky is the brightest part. The panel has no colour of its own: it is
/// the window's colour without a picture (`ImGuiCol_WindowBg` in ui_style.h),
/// 30% see-through. With "Background: None" it is that background.
static void home_panel_background(const ImVec2& min, const ImVec2& max, float rounding = 10.0f) {
    ImGui::GetWindowDrawList()->AddRectFilled(min, max,
        ImGui::GetColorU32(ImVec4(0.08f, 0.08f, 0.12f, 0.70f)), rounding);
}
/// The room a Home panel leaves around what it holds.
static float home_panel_padding() {
    return std::floor(ImGui::GetTextLineHeight() * 0.5f);
}

static void render_home_summary() {
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    {
        // The sponsor row sits on a panel like the numbers above it, directly
        // under the mode: its heading and its link are text on the picture
        // otherwise.
        const float panel_pad = home_panel_padding();
        const float panel_w = std::floor(std::max(1.0f, ImGui::GetContentRegionAvail().x));
        const float card_w = std::max(1.0f, panel_w - panel_pad * 2.0f);
        const char* sponsor_policy = "https://github.com/FCFlenkchy/FCAE_VPN/blob/main/SPONSOR_POLICY.md";
        const bool sponsor_has_content = s_sponsor.available;
        const char* sponsor_destination = sponsor_has_content ? s_sponsor.destination_url : sponsor_policy;
        const char* sponsor_title = sponsor_has_content ? s_sponsor.title : "Become a sponsor";
        const char* sponsor_message = sponsor_has_content ? s_sponsor.message : "Click to learn more";

        const float kHeaderPadV = 4.0f;
        const float kHeaderHeight = icon_button_size() + kHeaderPadV * 2.0f;
        const float icon_scale = std::clamp((float)s_sponsor.icon_scale / 100.0f, 0.5f, 1.6f);
        const float background_scale = std::clamp((float)s_sponsor.background_scale / 100.0f, 0.5f, 1.6f);
        const float title_scale = std::clamp((float)(s_sponsor.title_scale ? s_sponsor.title_scale : 100) / 100.0f, 0.5f, 2.0f);
        constexpr float kSponsorMessageFontRatio = 14.0f / 16.0f;
        const float message_scale = kSponsorMessageFontRatio
            * std::clamp((float)(s_sponsor.message_scale ? s_sponsor.message_scale : 100) / 100.0f, 0.5f, 2.0f);
        constexpr float kSponsorTextInset = 8.0f;
        const float sponsor_card_height = std::max(80.0f,
            ImGui::GetTextLineHeightWithSpacing() * 2.0f * message_scale
            + kSponsorTextInset * 3.0f + 8.0f);

        const float sponsor_total_h = kHeaderHeight + 8.0f + sponsor_card_height;
        const ImVec2 panel_cursor = ImGui::GetCursorScreenPos();
        const ImVec2 panel_min(std::floor(panel_cursor.x), std::floor(panel_cursor.y));
        const ImVec2 panel_max(panel_min.x + panel_w, panel_min.y + sponsor_total_h + panel_pad * 2.0f);
        home_panel_background(panel_min, panel_max);

        ImGui::BeginGroup();
        {
            const ImVec2 header_min(panel_min.x + panel_pad, panel_min.y + panel_pad);
            const ImVec2 header_max(header_min.x + card_w, header_min.y + kHeaderHeight);
            ImDrawList* const header_draw = ImGui::GetWindowDrawList();
            const float header_icon = icon_button_size();
            const float audio_x = header_max.x - header_icon;
            const float refresh_x = audio_x - 6.0f - header_icon;
            const float title_x = header_min.x;
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
            ImGui::NewLine();
            ImGui::SetCursorScreenPos(ImVec2(
                link_left + std::max(0.0f, (link_right - link_left - cta_w) * 0.5f), header_text_y));
            if (ImGui::TextLink(cta)) open_link(sponsor_policy);
            if (ImGui::IsItemHovered()) UiText::Tooltip("%s", sponsor_policy);
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
            const ImVec4 card_color = sponsor_color(s_sponsor.card_color, ImVec4(0.08f, 0.13f, 0.22f, 1.0f),
                s_sponsor.background_color_opacity);
            ImGui::PushStyleColor(ImGuiCol_ChildBg, card_color);
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.28f, 0.49f, 0.76f, 1.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
            ImGui::SetNextWindowScroll(ImVec2(0.0f, 0.0f));
            ImGui::BeginChild("##sponsor_card", ImVec2(card_w, sponsor_card_height),
                ImGuiChildFlags_Borders, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
                    | ImGuiWindowFlags_NoNavInputs | ImGuiWindowFlags_NoNavFocus);
            // Use the actual rounded child size and one consistent interior
            // rectangle. The requested float size may round by a pixel.
            const float card_border = ImGui::GetStyle().ChildBorderSize;
            const ImVec2 card_pos = ImGui::GetWindowPos();
            const ImVec2 card_size = ImGui::GetWindowSize();
            const ImVec2 media_origin(card_pos.x + card_border, card_pos.y + card_border);
            const ImVec2 media_area(std::max(1.0f, card_size.x - card_border * 2.0f),
                                    std::max(1.0f, card_size.y - card_border * 2.0f));

            if (background_texture) {
                // Stretch the full source to the current card on every frame:
                // no cover crop, aspect-fit bars, or destructive source resize.
                const auto image = UiMedia::stretch(media_origin, media_area, background_scale);
                const bool fills_card = image.min.x <= media_origin.x && image.min.y <= media_origin.y
                    && image.max.x >= media_origin.x + media_area.x
                    && image.max.y >= media_origin.y + media_area.y;
                ImGui::GetWindowDrawList()->AddImageRounded(background_texture, image.min, image.max,
                    image.uv0, image.uv1,
                    ImGui::GetColorU32(ImVec4(1, 1, 1, (float)s_sponsor.background_opacity / 100.0f)),
                    fills_card ? ImGui::GetStyle().ChildRounding : 0.0f);
            }

            if (texture) {
                // The same complete-image mapping on every platform, including
                // legacy campaigns which requested cover/cropping.
                const auto image = UiMedia::stretch(media_origin, media_area, icon_scale,
                    ImVec2((float)s_sponsor.icon_x / 100.0f, (float)s_sponsor.icon_y / 100.0f));
                ImGui::GetWindowDrawList()->AddImage(texture, image.min, image.max, image.uv0, image.uv1,
                    ImGui::GetColorU32(ImVec4(1, 1, 1, (float)s_sponsor.icon_opacity / 100.0f)));
            }
            ImGui::SetCursorScreenPos(media_origin);
            ImGui::InvisibleButton("##sponsor_card_touch", media_area);
#if defined(ANDROID)
            android_ui_horizontal_drag_item();
#endif
            static bool sponsor_dragged = false;
            if (ImGui::IsItemActivated()) sponsor_dragged = false;
            if (ImGui::IsItemActive() && s_sponsor.campaign_count > 1
                    && std::abs(ImGui::GetMouseDragDelta(ImGuiMouseButton_Left).x) >= 36.0f)
                sponsor_dragged = true;
            if (ImGui::IsItemDeactivated()) {
                if (sponsor_dragged && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
                    fcae_sponsor_next();
                    ui_request_redraw();
                } else if (ImGui::IsMouseReleased(ImGuiMouseButton_Left) && ImGui::IsItemHovered()
                        && !ImGui::IsMouseDragPastThreshold(ImGuiMouseButton_Left)
                        && strncmp(sponsor_destination, "https://", 8) == 0) {
                    open_link(sponsor_destination);
                }
                sponsor_dragged = false;
            }
            if (ImGui::IsItemHovered())
                UiText::Tooltip(s_sponsor.campaign_count > 1
                    ? "Click to open, drag to change sponsor"
                    : "Click to open sponsor website");

            const ImVec2 text_card = media_area;
            const ImVec2 text_origin = media_origin;
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
        // The panel's own bottom edge, so the page ends under it and not under
        // the card inside it.
        ImGui::SetCursorScreenPos(ImVec2(panel_min.x, panel_max.y));
        ImGui::Dummy(ImVec2(panel_w, 0.0f));
    }

}

void render_ui() {
    const ImGuiIO& io = ImGui::GetIO();
    const bool narrow = io.DisplaySize.x < 720.0f * ImGui::GetFontSize() / 22.0f;

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(narrow ? 12.0f : 20.0f, narrow ? 10.0f : 16.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_HorizontalScrollbar);

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
                        // Give a long release URL its own full-width lines.
                        bool hovered = false;
                        if (UiText::TextLinkWrapped(url.c_str(), &hovered))
                            open_link(url.c_str());
                        if (hovered) UiText::Tooltip("%s", url.c_str());
                    } else {
                        ImGui::TextWrapped("Download: %s", s_update_dl_url);
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
                    UiText::InputTextMultiline("##update_raw_body", s_update_raw_body,
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
#if defined(FCAE_IOS)
        const bool show_tun_control = false;
#else
        const bool show_tun_control = session_is_tun() && (connected || tun_paused);
#endif
        const float pair_reserve = show_tun_control ? stop_btn_w + 6.0f : 0.0f;
        float btn_w = narrow ? (std::max)(action_btn_min, ImGui::GetContentRegionAvail().x - pair_reserve)
                             : action_btn_min;
        bool show_disconnect = connected || busy || tun_paused;
        bool connect_disabled = startup || ur_account_busy();
#ifdef _WIN32
        connect_disabled |= s_elevation_pending.load(std::memory_order_acquire);
#endif
        if (connect_disabled) ImGui::BeginDisabled();
        const bool clicked_connect = ImGui::Button(show_disconnect ? "DISCONNECT" : "CONNECT", ImVec2(btn_w, kActionRowHeight));
#ifdef _WIN32
        const int tray_action = s_tray_toggle_requested.exchange(0, std::memory_order_acq_rel);
        // The state may change while the shell menu is open. Never turn an
        // advertised Disconnect into a Connect (or vice versa) on the next frame.
        const bool tray_state_matches = tray_action == 1 ? !show_disconnect && !errored
            : tray_action == 2 ? show_disconnect && !errored
            : tray_action == 3 ? errored : false;
        // An OS tray-menu selection is an explicit command, independent of any
        // modal that happened to be open in the hidden main window.
        const bool tray_toggle = tray_state_matches && !connect_disabled;
#else
        const bool tray_toggle = false;
#endif
        if (clicked_connect || tray_toggle) {
            s_telemetry_soon_until = now + 3.0;
#if defined(ANDROID)
            if (connected || busy || errored || tun_paused) {
                android_ui_command("disconnect");
            } else {
                save_config(true);
                android_ui_save_session(true);
            }
#else
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
                // If parsing failed, let runtime validation report the profile
                // error instead of misdiagnosing it as a disabled listener.
                const AppState::CoreConfigEntry* final_entry = g_app.final_core_config();
                const bool core_final = g_app.final_listener_is_core() && final_entry && final_entry->kinds;
                const int final_core = g_app.final_listener_core();
                const std::string core_socks_name =
                    std::string(final_core == 5 ? "Mihomo" : final_core == 4 ? "sing-box" : "Xray") + " SOCKS5";
                const std::string core_listener_name = core_socks_name + " or HTTP";
                const bool psi_carrier = !g_app.chain_transports.empty() &&
                    (g_app.backend == 1 || std::find(g_app.chain_transports.begin(), g_app.chain_transports.end() - 1, 5) != g_app.chain_transports.end() - 1);
                const bool firefox_carrier = !g_app.chain_transports.empty() &&
                    (g_app.backend == 2 || std::find(g_app.chain_transports.begin(), g_app.chain_transports.end() - 1, 10) != g_app.chain_transports.end() - 1);
                bool uses_aether = g_app.backend == 0 && g_app.protocol != 4;
                for (int t : g_app.chain_transports)
                    if (t != 4 && t != 5 && t != 10 && t != 11 && !transport_is_core(t)) uses_aether = true;
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
                #ifdef _WIN32
                const bool vpn_privileged=fcae_windows_process_admin(GetCurrentProcess());
#else
                const bool vpn_privileged=fcae_is_privileged();
#endif
                if (g_app.mode == 1 && !vpn_privileged && !PlatformAppRouting::uses_macos_ne()) {
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
                    fcae_ui_diagnostic(2, 0);
                    // The decision to exit is published here and acted on by
                    // the window thread: PostQuitMessage only affects the thread
                    // that calls it, so a worker cannot end this process.
                    const HWND consent_owner = reinterpret_cast<HWND>(s_ui_window.load());
                    s_elevation_pending.store(true, std::memory_order_release);
                    RECT bounds = {};
                    GetWindowRect(consent_owner, &bounds);
                    WINDOWPLACEMENT placement = {};
                    placement.length = sizeof(placement);
                    int show = SW_SHOWNORMAL;
                    if (GetWindowPlacement(consent_owner, &placement) && placement.showCmd == SW_SHOWMAXIMIZED) {
                        show = SW_SHOWMAXIMIZED;
                        bounds = placement.rcNormalPosition;
                        MONITORINFO monitor = {};
                        monitor.cbSize = sizeof(monitor);
                        if (GetMonitorInfoW(MonitorFromWindow(consent_owner, MONITOR_DEFAULTTONEAREST), &monitor))
                            OffsetRect(&bounds, monitor.rcWork.left - monitor.rcMonitor.left,
                                       monitor.rcWork.top - monitor.rcMonitor.top);
                    }
                    std::thread([exe_path = std::wstring(exe_path), consent_owner, bounds, show] {
                        wchar_t event_name[96];
                        std::swprintf(event_name, 96, L"Local\\FCAE.UI.Ready.%lu",
                                      static_cast<unsigned long>(GetCurrentProcessId()));
                        HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, event_name);
                        if (!ready) {
                            g_app.add_log(FCAE_LOG_ERROR, "[ui] Cannot create elevation handoff event");
                            s_elevation_pending.store(false, std::memory_order_release);
                            ui_request_redraw();
                            return;
                        }
                        SHELLEXECUTEINFOW sei = {};
                        sei.cbSize = sizeof(sei);
                        sei.hwnd = consent_owner;
                        sei.lpVerb = L"runas";
                        sei.lpFile = exe_path.c_str();
                        const auto slash = exe_path.find_last_of(L"\\/");
                        const std::wstring work_dir = slash == std::wstring::npos
                            ? std::wstring() : exe_path.substr(0, slash);
                        sei.lpDirectory = work_dir.empty() ? nullptr : work_dir.c_str();
                        wchar_t handoff_args[192];
                        std::swprintf(handoff_args, 192, L"--fcae-wait-parent %lu --fcae-window %ld %ld %ld %ld %d",
                                      static_cast<unsigned long>(GetCurrentProcessId()), bounds.left, bounds.top,
                                      bounds.right - bounds.left, bounds.bottom - bounds.top, show);
                        sei.lpParameters = handoff_args;
                        sei.nShow = SW_NORMAL;
                        // SEE_MASK_NOASYNC keeps the shell from failing a caller
                        // that is not pumping messages, which this thread is not.
                        sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
                        if (ShellExecuteExW(&sei)) {
                            DWORD child_pid = sei.hProcess ? GetProcessId(sei.hProcess) : 0;
                            fcae_ui_diagnostic(3, child_pid);
                            HANDLE waits[] = {ready, sei.hProcess};
                            DWORD wait = WaitForMultipleObjects(sei.hProcess ? 2 : 1, waits, FALSE, 30000);
                            // Some compatibility launchers exit before the real
                            // GUI is ready. The child checks its own token before
                            // it may signal this event; a process launch is not
                            // itself proof that elevation succeeded.
                            if (sei.hProcess && wait==WAIT_OBJECT_0+1)
                                wait=WaitForSingleObject(ready,5000);
                            bool confirmed=wait==WAIT_OBJECT_0;
                            DWORD exit_code = STILL_ACTIVE;
                            if (sei.hProcess && GetExitCodeProcess(sei.hProcess, &exit_code)
                                    && exit_code != STILL_ACTIVE) {
                                confirmed = false;
                                fcae_ui_diagnostic(10, exit_code);
                            }
                            if (!confirmed) fcae_ui_diagnostic(11, wait);
                            if (confirmed) {
                                s_elevation_child.store(sei.hProcess, std::memory_order_release);
                                fcae_ui_diagnostic(9, child_pid);
                                s_elevation_handoff_at.store(GetTickCount() | 1u, std::memory_order_relaxed);
                            } else {
                                if (sei.hProcess) CloseHandle(sei.hProcess);
                                g_app.add_log(FCAE_LOG_ERROR, "[ui] Administrator handoff was not confirmed; keeping this window open. The elevated copy did not finish initialization. Check deps/logs.txt (or %LOCALAPPDATA%/FCAE_VPN/logs/logs.txt) and Windows UAC / compatibility policy.");
                                s_elevation_pending.store(false, std::memory_order_release);
                            }
                            ui_request_redraw();
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
                            s_elevation_pending.store(false, std::memory_order_release);
                            ui_request_redraw();
                        }
                        CloseHandle(ready);
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
                    std::string noize, peer, path, sni, team, token, email, routes_inline;
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
                    std::string app_routing;
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
                o->psi_dir = resolve_data_path(g_app.psiphon_data_dir);
                o->upstream = g_app.upstream_proxy;
                o->root = data_dir();
                o->firefox_account = g_app.firefox_account_id;
                o->firefox_location = g_app.firefox_location;
                o->firefox_server = g_app.firefox_server;
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
                o->routes_inline = o->c.routing.rules_inline ? o->c.routing.rules_inline : "";
#if !defined(FCAE_IOS)
                o->app_routing = PlatformAppRouting::connection_policy();
#endif
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
#if defined(FCAE_IOS)
                    const auto start_status = fcae_start(&guard->c);
#else
                    const auto start_status = fcae_start_with_app_routing(&guard->c, guard->app_routing.c_str());
#endif
                    if (start_status != FCAE_OK) {
                        g_app.add_log(FCAE_LOG_ERROR, fcae_last_error());
                        ui_request_redraw();
                    }
                }).detach();
            }
#endif
        }
        if (connect_disabled) ImGui::EndDisabled();
        if (startup) UiText::ItemTooltip("Finishing initialization...");
        ImGui::PopStyleColor(3);

#ifdef _WIN32
        const int tray_tun_request = s_tray_tun_requested.exchange(0, std::memory_order_acq_rel);
        const bool tray_tun_allowed = show_tun_control && !startup
            && !s_elevation_pending.load(std::memory_order_acquire);
#else
        const int tray_tun_request = 0;
        const bool tray_tun_allowed = false;
#endif
        if (show_tun_control) {
            ImGui::SameLine(0, 6);
            ImGui::SetCursorPosY(row_start_y);
            if (tun_paused) {
                ImVec4 start_col(0.18f, 0.35f, 0.85f, 1.0f);
                ImVec4 start_h(0.26f, 0.45f, 0.95f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, start_col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, start_h);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(start_col.x - 0.05f, start_col.y - 0.05f, start_col.z - 0.05f, 1.0f));
                if (ImGui::Button("START", ImVec2(stop_btn_w, kActionRowHeight))
                    || (tray_tun_allowed && tray_tun_request == 2)) {
#if defined(ANDROID)
                    android_ui_command("resume");
#else
                    std::thread([] {
                        if (fcae_resume_tun() != FCAE_OK) {
                            g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                        }
                        ui_request_redraw();
                    }).detach();
#endif
                }
                ImGui::PopStyleColor(3);
            } else {
                ImVec4 stop_col(0.85f, 0.55f, 0.15f, 1.0f);
                ImVec4 stop_h(0.95f, 0.65f, 0.25f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, stop_col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, stop_h);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(stop_col.x - 0.05f, stop_col.y - 0.05f, stop_col.z - 0.05f, 1.0f));
                if (ImGui::Button("STOP", ImVec2(stop_btn_w, kActionRowHeight))
                    || (tray_tun_allowed && tray_tun_request == 1)) {
#if defined(ANDROID)
                    android_ui_command("pause");
#else
                    std::thread([] {
                        if (fcae_pause_tun() != FCAE_OK) {
                            g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                        }
                        ui_request_redraw();
                    }).detach();
#endif
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
            UiText::TextColoredWrapped(sc, "ERROR: %s", telem.last_error);
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
            ImGui::BeginGroup();
            UiText::TextColoredWrapped(ImVec4(0.95f, 0.38f, 0.38f, 1.0f), "%s", g_app.save_status);
            ImGui::EndGroup();
            s_save_status_painted_revision = s_save_status_revision;
        }

        // "Check for Updates" rides in the CONNECT row, pinned as far right
        // as the window allows; on narrow windows it drops to its own line,
        // still flush right. Gated until the runtime is live.
        if (startup) ImGui::BeginDisabled();
        {
            const ImGuiStyle& style = ImGui::GetStyle();
            float btn_width = 0.0f;
            for (const char* label : {"Check for Updates", "Update Available!", "Check Timed Out",
                                      "Checking... 999s", "ATTENTION!", "Check Failed", "Up to Date"})
                btn_width = std::max(btn_width, ImGui::CalcTextSize(label).x);
            const float label_width = btn_width;
            const float padding = style.FramePadding.x * 2.0f;
            btn_width += padding;
            const float content_right = ImGui::GetWindowContentRegionMax().x;
            const float content_left = ImGui::GetWindowContentRegionMin().x;
            btn_width = std::min(btn_width, std::max(1.0f, content_right - content_left));
            const bool compact_label = label_width + padding > btn_width;
            if (compact_label)
                ImGui::PushFont(nullptr, style.FontSizeBase * std::max(1.0f, btn_width - padding - 1.0f) / label_width);
            const float last_item_right = ImGui::GetItemRectMax().x - ImGui::GetWindowPos().x;
            if (!narrow && content_right - last_item_right >= btn_width + 10.0f) {
                ImGui::SameLine(0, 10);
                ImGui::SetCursorPosY(row_start_y);
            }
            ImGui::SetCursorPosX(content_right - btn_width);
            const float update_btn_h = std::max(32.0f, ImGui::GetFrameHeight());
            ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.5f, 0.5f));
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
            ImGui::PopStyleVar();
            if (compact_label) ImGui::PopFont();
        }
        if (startup) ImGui::EndDisabled();

        {
            static bool gram_copied = false;
            if (s_about_popup_open) {
                ImGui::OpenPopup("##about_popup");
                s_about_popup_open = false;
                gram_copied = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            ImGui::SetNextWindowSize(modal_size(680.0f, ImGui::GetTextLineHeightWithSpacing() * 21.0f),
                                     ImGuiCond_Always);
            constrain_modal();
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24.0f, 16.0f));
            ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 12.0f);
            if (ImGui::BeginPopupModal("##about_popup", nullptr,
                    ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar)) {
                const float footer_height = ImGui::GetFrameHeightWithSpacing();
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 7.0f));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
                ImGui::TextUnformatted("About");
                ImGui::Spacing();
                if (ImGui::BeginChild("##about_content", ImVec2(0, -footer_height))) {
                    auto link = [](const char* label, const char* url) {
                        bool hovered = false;
                        if (UiText::TextLinkWrapped(label, &hovered)) open_link(url);
                        if (hovered) UiText::Tooltip("%s", url);
                    };
                    auto inline_link = [&](const char* prefix, const char* label, const char* url) {
                        ImGui::TextWrapped("%s", prefix);
                        const float width = ImGui::CalcTextSize(label).x;
                        const float right = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
                        if (ImGui::GetItemRectMax().x + ImGui::GetStyle().ItemSpacing.x + width <= right)
                            ImGui::SameLine();
                        link(label, url);
                    };
                    auto colored_button = [](const char* label, const ImVec4& color, const ImVec2& size) {
                        ImGui::PushStyleColor(ImGuiCol_Button, color);
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(
                            std::min(color.x + 0.08f, 1.0f), std::min(color.y + 0.08f, 1.0f),
                            std::min(color.z + 0.08f, 1.0f), 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                            ImVec4(color.x * 0.8f, color.y * 0.8f, color.z * 0.8f, 1.0f));
                        const bool pressed = ImGui::Button(label, size);
                        ImGui::PopStyleColor(3);
                        return pressed;
                    };
                    ImGui::TextUnformatted("FCAE VPN");
                    ImGui::TextColored(build_is_prerelease()
                        ? ImVec4(240 / 255.0f, 180 / 255.0f, 41 / 255.0f, 1.0f)
                        : ImVec4(138 / 255.0f, 147 / 255.0f, 166 / 255.0f, 1.0f),
                        "%s  |  %s", fcae_display_version(),
                        build_is_prerelease() ? "pre-release" : "release");
                    ImGui::Spacing();
                    for (const CommunityLink& community : kCommunityLinks) {
                        ImGui::PushID(community.url);
                        inline_link(community.label, community.shown, community.url);
                        ImGui::PopID();
                    }
                    ImGui::Spacing();
                    inline_link(build_is_prerelease() ? "Pre-released under the" : "Released under the",
                                "LICENSE", kLinkLicense.c_str());
                    inline_link("Credits are listed in the", "GitHub repository", kLinkCredits.c_str());
                    ImGui::Spacing();
                    ImGui::Spacing();
                    const float gap = 8.0f;
                    const float button_width = std::max(1.0f, (ImGui::GetContentRegionAvail().x - gap) * 0.5f);
                    const float min_button_width = std::max(ImGui::CalcTextSize("Telegram").x,
                        ImGui::CalcTextSize("GitHub").x) + ImGui::GetStyle().FramePadding.x * 2.0f;
                    const bool button_row = button_width >= min_button_width;
                    const ImVec2 button_size(button_row ? button_width : -1.0f, 0);
                    if (colored_button("Telegram##about", ImVec4(34 / 255.0f, 158 / 255.0f, 217 / 255.0f, 1), button_size))
                        open_link(kLinkTelegram);
                    if (button_row) ImGui::SameLine(0, gap);
                    if (colored_button("GitHub##about", ImVec4(52 / 255.0f, 52 / 255.0f, 74 / 255.0f, 1), button_size))
                        open_link(kLinkGithub);
                    ImGui::Spacing();
                    ImGui::Spacing();
                    ImGui::TextWrapped("Support the developer with GRAM (The Open Network):");
                    ImGui::TextWrapped("%s", kGramAddress);
                    if (colored_button("Copy GRAM address", ImVec4(0, 136 / 255.0f, 204 / 255.0f, 1), ImVec2(-1, 0))) {
                        ImGui::SetClipboardText(kGramAddress);
                        gram_copied = true;
                    }
                    if (gram_copied)
                        ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1), "GRAM address copied");
                }
                ImGui::EndChild();
                ImGui::PopStyleColor();
                ImGui::PopStyleVar();
                if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
            ImGui::PopStyleVar(2);
        }

        ImGui::PopStyleVar(2);
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
            const char* final_name = final_backend == FCAE_BACKEND_URNETWORK ? "URnetwork" : final_backend == FCAE_BACKEND_FIREFOX ? "Firefox"
                : final_backend == FCAE_BACKEND_PSIPHON ? "Psiphon"
                : final_backend == FCAE_BACKEND_SINGBOX ? "sing-box"
                : final_backend == FCAE_BACKEND_XRAY ? "Xray" : final_backend == FCAE_BACKEND_MIHOMO ? "Mihomo" : "Aether";
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
                : final_backend == FCAE_BACKEND_SINGBOX ? "sing-box" : final_backend == FCAE_BACKEND_MIHOMO ? "Mihomo" : nullptr;
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
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();
        ImGui::Spacing();
        if (ImGui::Button("Close"))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // Main navigation is a full-width bottom bar: Settings on the left,
    // Home in the center (the initial page), and Logs on the right.
    static int main_page = 1; // 0 = Settings, 1 = Home, 2 = Logs
    const ImGuiStyle& page_style = ImGui::GetStyle();
    const float nav_height = std::max(42.0f, ImGui::GetFrameHeight() + 8.0f);
    const float nav_y = ImGui::GetWindowContentRegionMax().y - nav_height;
    const float page_height = std::max(1.0f, nav_y - ImGui::GetCursorPosY()
                                       - page_style.ItemSpacing.y);
    ImGui::BeginChild("##main_page_content", ImVec2(0, page_height), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    if (main_page == 1) {
            ImGui::BeginChild("##home_scroll", ImVec2(0, 0), ImGuiChildFlags_None);
            ImGui::Spacing();
            {
                char dl_rate[32], dl_total[32], ul_rate[32], ul_total[32], rtt_buf[24];
                fmt_rate(dl_rate, sizeof(dl_rate), telem.rx_bytes_sec);
                fmt_bytes(dl_total, sizeof(dl_total), telem.total_rx);
                fmt_rate(ul_rate, sizeof(ul_rate), telem.tx_bytes_sec);
                fmt_bytes(ul_total, sizeof(ul_total), telem.total_tx);
                // The round trip keeps its place between the two rates. It has
                // no caption: "ms" already says what the number is. A session
                // is connected before its tunnel has answered, so a round trip
                // that was tried and got nothing back (the core reports
                // UINT32_MAX for it) reads "-1ms", in red, until one lands.
                const bool rtt_failed = (telem.state == FCAE_STATE_CONNECTED && telem.rtt_ms == UINT32_MAX);
                const bool rtt_live = (telem.state == FCAE_STATE_CONNECTED && telem.rtt_ms > 0 && !rtt_failed);
                if (rtt_failed)
                    snprintf(rtt_buf, sizeof(rtt_buf), "-1ms");
                else if (rtt_live)
                    snprintf(rtt_buf, sizeof(rtt_buf), "%ums", telem.rtt_ms);
                else
                    snprintf(rtt_buf, sizeof(rtt_buf), "--");

                char dl_total_line[48], ul_total_line[48];
                snprintf(dl_total_line, sizeof(dl_total_line), "Total %s", dl_total);
                snprintf(ul_total_line, sizeof(ul_total_line), "Total %s", ul_total);

                const ImGuiStyle& style = ImGui::GetStyle();
                const float avail_w = std::max(1.0f, ImGui::GetContentRegionAvail().x);
                const float col_w = avail_w / 3.0f;
                const float base_x = ImGui::GetCursorPosX();
                const float card_y = ImGui::GetCursorPosY();
                const float line_h = ImGui::GetTextLineHeight();
                const float row_gap = style.ItemSpacing.y;
                const float info_btn_w = ImGui::CalcTextSize("INFO").x
                    + style.FramePadding.x * 2.0f + 8.0f;
                const float info_btn_h = ImGui::GetFrameHeight();

                // The numbers sit on a panel of their own: captions, rates,
                // and a last row as tall as the button in the middle of it.
                const float card_pad = home_panel_padding();
                const float card_h = line_h * 2.0f + row_gap * 2.0f + info_btn_h + card_pad * 2.0f;
                const ImVec2 card_min = ImGui::GetCursorScreenPos();
                home_panel_background(card_min, ImVec2(card_min.x + avail_w, card_min.y + card_h));
                const float base_y = card_y + card_pad;

                // Centred in its third of the panel. What is wider than that
                // stays on the panel and takes the room from the middle.
                auto col_text_x = [&](int col, const char* text) -> float {
                    const float w = ImGui::CalcTextSize(text).x;
                    const float cx = base_x + col_w * (float)col + (col_w - w) * 0.5f;
                    const float inner_min = base_x + card_pad;
                    return std::floor(std::clamp(cx, inner_min,
                        std::max(inner_min, base_x + avail_w - card_pad - w)));
                };

                ImGui::SetCursorPos(ImVec2(col_text_x(0, "DOWNLOAD"), base_y));
                ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "DOWNLOAD");

                ImGui::SetCursorPos(ImVec2(col_text_x(2, "UPLOAD"), base_y));
                ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "UPLOAD");

                const float y2 = base_y + line_h + row_gap;
                ImGui::SetCursorPos(ImVec2(col_text_x(0, dl_rate), y2));
                ImGui::TextUnformatted(dl_rate);

                ImGui::SetCursorPos(ImVec2(col_text_x(1, rtt_buf), y2));
                ImGui::TextColored(rtt_failed ? ImVec4(0.95f, 0.38f, 0.38f, 1.0f)
                                   : rtt_live ? ImVec4(0.45f, 0.92f, 0.55f, 1.0f)
                                              : ImVec4(0.62f, 0.66f, 0.74f, 1.0f),
                                   "%s", rtt_buf);

                ImGui::SetCursorPos(ImVec2(col_text_x(2, ul_rate), y2));
                ImGui::TextUnformatted(ul_rate);

                const float y3 = y2 + line_h + row_gap;
                const float total_text_y = y3 + std::floor((info_btn_h - line_h) * 0.5f);
                // The totals share the last row with the button. A panel too
                // narrow for the longest of them beside it shows the numbers
                // alone: by its width, so the row does not change as they grow.
                const float total_room = (avail_w - info_btn_w) * 0.5f - card_pad - style.ItemSpacing.x;
                const bool total_word = ImGui::CalcTextSize("Total 1023.99 MB").x <= total_room;
                const char* const dl_total_text = total_word ? dl_total_line : dl_total;
                const char* const ul_total_text = total_word ? ul_total_line : ul_total;

                ImGui::SetCursorPos(ImVec2(col_text_x(0, dl_total_text), total_text_y));
                ImGui::TextDisabled("%s", dl_total_text);

                const float info_x = std::floor(base_x + (avail_w - info_btn_w) * 0.5f);
                ImGui::SetCursorPos(ImVec2(std::max(base_x, info_x), y3));
                if (ImGui::Button("INFO", ImVec2(info_btn_w, info_btn_h))) {
                    s_connection_info_popup_open = true;
                    ui_request_redraw();
                }
                if (ImGui::IsItemHovered()) UiText::Tooltip("Show connection details");

                ImGui::SetCursorPos(ImVec2(col_text_x(2, ul_total_text), total_text_y));
                ImGui::TextDisabled("%s", ul_total_text);

                ImGui::SetCursorPos(ImVec2(base_x, card_y + card_h + row_gap));
                ImGui::Dummy(ImVec2(0.0f, 0.0f));
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (ImGui::Button("Protocol", ImVec2(-FLT_MIN, 0)))
                open_protocol_editor();

            ImGui::Spacing();
            // The mode is the next connection's. A session keeps the mode it
            // started in, so there is nothing to protect by locking this while
            // one runs: the choice is simply taken up the next time.
            const char* mode_items[] = {"Proxy", "TUN"};
            int mode_selection = g_app.mode == 1 ? 1 : 0;
            const float mode_avail = ImGui::GetContentRegionAvail().x;
            const float mode_label_width = ImGui::CalcTextSize("MODE").x;
            const float mode_gap = ImGui::GetStyle().ItemSpacing.x;
            const float combo_width = mode_avail - mode_label_width - mode_gap;
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("MODE");
            if (combo_width >= 84.0f) ImGui::SameLine(0, mode_gap);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::Combo("##connection_mode", &mode_selection, mode_items, 2))
                g_app.mode = mode_selection;
            if (session_live() && (g_app.mode == 1) != session_is_tun()) {
                // Not the disabled grey of a caption: it is drawn on the
                // background picture, and it is news.
                UiText::TextColoredWrapped(ImVec4(0.96f, 0.80f, 0.40f, 1.0f),
                    "This connection stays in %s mode. %s applies the next time you connect.",
                    mode_items[session_is_tun() ? 1 : 0], mode_items[g_app.mode == 1 ? 1 : 0]);
            }

            render_home_summary();
            ImGui::EndChild();
        }

        if (main_page == 0) {
            ImGui::BeginChild("##settings_scroll", ImVec2(0, 0), ImGuiChildFlags_None,
                              ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
            static int settings_category = 0;
            static int aether_settings_section = 0;
            static const char* const aether_settings_sections[] = {
                "Aether", "Routes", "Tor", "Zero Trust", "Obfuscation", "Scanner",
            };
            static const char* const settings_categories[] = {
                "App Settings", "TUN", "Aether", "Psiphon", "Services",
            };
            if (settings_category < 0 || settings_category >= IM_ARRAYSIZE(settings_categories))
                settings_category = 0;
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "SETTINGS");
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::Combo("Category", &settings_category, settings_categories,
                         IM_ARRAYSIZE(settings_categories));
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (settings_category == 0) {
                ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "APP SETTINGS");
    #if defined(ANDROID)
                android_ui_render_controls();
    #endif
                {
                    // The built-in choices, then the pictures the user added --
                    // each with a button that deletes it -- then the entry that
                    // opens the system's file picker to add another.
                    const ImGuiStyle& bg_style = ImGui::GetStyle();
                    const bool bg_custom = background_custom_active();
                    const bool bg_none = !bg_custom && strcmp(g_app.background_mode, "none") == 0;
                    const std::string bg_preview = bg_custom ? g_app.background_image
                        : bg_none ? "None" : "Mountain";
                    const auto bg_choose = [](const char* mode, const std::string& image) {
                        snprintf(g_app.background_mode, sizeof(g_app.background_mode), "%s", mode);
                        g_app.background_image = image;
                        s_background_note.clear();
                        save_config();
                    };
                    const float bg_delete_w = ImGui::CalcTextSize("X").x + bg_style.FramePadding.x * 2.0f;
                    float bg_list_w = 160.0f;
                    for (const std::string& name : g_app.background_images)
                        bg_list_w = std::max(bg_list_w, ImGui::CalcTextSize(name.c_str()).x + bg_delete_w
                            + bg_style.ItemSpacing.x * 2.0f + bg_style.WindowPadding.x * 2.0f);
                    bg_list_w = std::min(bg_list_w, std::max(160.0f, ImGui::GetIO().DisplaySize.x * 0.9f));
                    int bg_delete = -1;
                    ImGui::SetNextWindowSizeConstraints(ImVec2(bg_list_w, 0.0f), ImVec2(FLT_MAX, FLT_MAX));
                    ImGui::SetNextItemWidth(std::clamp(ImGui::CalcTextSize(bg_preview.c_str()).x
                        + ImGui::GetFrameHeight() + bg_style.FramePadding.x * 2.0f, 160.0f, 360.0f));
                    if (ImGui::BeginCombo("Background", bg_preview.c_str())) {
                        if (ImGui::Selectable("Mountain", !bg_custom && !bg_none)) bg_choose("mountain", {});
                        if (ImGui::Selectable("None", bg_none)) bg_choose("none", {});
                        for (size_t i = 0; i < g_app.background_images.size(); ++i) {
                            const std::string name = g_app.background_images[i];
                            ImGui::PushID((int)i);
                            const float row_w = ImGui::GetContentRegionAvail().x;
                            if (ImGui::Selectable(name.c_str(), bg_custom && name == g_app.background_image,
                                    ImGuiSelectableFlags_None,
                                    ImVec2(std::max(1.0f, row_w - bg_delete_w - bg_style.ItemSpacing.x), 0.0f)))
                                bg_choose("image", name);
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.62f, 0.16f, 0.16f, 1.0f));
                            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.82f, 0.22f, 0.22f, 1.0f));
                            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.92f, 0.28f, 0.28f, 1.0f));
                            if (ImGui::SmallButton("X")) bg_delete = (int)i;
                            ImGui::PopStyleColor(3);
                            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Delete this picture");
                            ImGui::PopID();
                        }
                        ImGui::Separator();
#if defined(FCAE_IOS)
                        // Photos and Files are two pickers on iOS, and neither
                        // shows the pictures the other holds.
                        if (ImGui::Selectable("+ Add from Photos...")) {
                            s_background_note.clear();
                            background_pick_request(false);
                        }
                        if (ImGui::Selectable("+ Add from Files...")) {
                            s_background_note.clear();
                            background_pick_request(true);
                        }
#else
                        if (ImGui::Selectable("+ Add image...")) {
                            s_background_note.clear();
                            background_pick_request();
                        }
#endif
                        ImGui::EndCombo();
                    }
                    if (bg_delete >= 0) background_remove_image((size_t)bg_delete);
                    if (!s_background_note.empty())
                        UiText::TextColoredWrapped(ImVec4(1.0f, 0.45f, 0.40f, 1.0f), "%s", s_background_note.c_str());
                }
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
                UiText::InputTextWithHint("##upstream_proxy", "socks5://host:port or http://host:port",
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
                        UiText::TextColoredWrapped(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", proxy_err);
                }
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            }
            if (settings_category == 1) {
                if (ImGui::CollapsingHeader("TUN Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Text("TUN engine");
                    ImGui::SameLine(0, 8);
                    const uint32_t te_n = fcae_tun_engine_count();
                    std::vector<FcaeTunEngineInfo> tei(te_n);
                    std::vector<const char*> te_names(te_n);
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
                    if (ImGui::Combo("##tun_engine", &te_sel, te_names.data(), (int)te_n)) {
                        g_app.tun_engine = te_sel;
                        fcae_ui_diagnostic(0, uint32_t(te_sel));
                    }
                    ImGui::PopItemWidth();
                    if (te_sel < (int)te_n && !tei[te_sel].available)
                        UiText::TextColoredWrapped(ImVec4(1, 0.6f, 0.2f, 1), "%s", tei[te_sel].unavailable_reason);
                    ImGui::Spacing();
                    ImGui::PushItemWidth(160);
                    UiText::InputText("TUN MTU (bytes)", g_app.tun_mtu, sizeof(g_app.tun_mtu));
                    ImGui::PopItemWidth();
                    ImGui::Checkbox("Exclude private IPs", &g_app.tun_exclude_private);
    #if defined(ANDROID)
                    android_ui_render_routing();
    #else
                    PlatformAppRouting::routing();
    #endif
                    if (g_app.parsed_tun_mtu() == 0xffffffffu)
                        UiText::TextColoredWrapped(ImVec4(1, 0.4f, 0.3f, 1), "MTU: 1280..9000 bytes.");
                    const char* t2s_logs[] = { "Silent", "Error", "Warn", "Info", "Debug" };
                    int t2s_pos = g_app.t2s_log > 0 ? g_app.t2s_log - 1 : 0;
                    if (t2s_pos > 4) t2s_pos = 4;
                    if (ImGui::Combo("TUN engine log", &t2s_pos, t2s_logs, 5))
                        g_app.t2s_log = t2s_pos + 1;
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
                        ImGui::SetTooltip("Independent of proxy-core logging. A native TUN engine that attaches to the same already-running core may still share that core's logger.");

                    ImGui::Spacing();
                    ImGui::Text("TUN DNS (comma-separated IP addresses)");
                    ImGui::PushItemWidth(-1);
                    UiText::InputTextWithHint("##tun_dns4", "IPv4 DNS — e.g. 1.1.1.1,1.0.0.1", g_app.tun_dns4, sizeof(g_app.tun_dns4));
                    UiText::InputTextWithHint("##tun_dns6", "IPv6 DNS — e.g. 2606:4700:4700::1111", g_app.tun_dns6, sizeof(g_app.tun_dns6));
    #if !defined(ANDROID)
                    if (ImGui::Checkbox("DNS firewall", &g_app.dns_firewall)) {
                        save_config();
                    }
    #endif
                    ImGui::PopItemWidth();
                    if (g_app.tun_engine == 0) {
                        ImGui::Spacing();
                        ImGui::Text("tun2socks TCP settings");
                        ImGui::PushItemWidth(160);
                        UiText::InputText("TCP send buffer (bytes)", g_app.tun_tcp_sndbuf, sizeof(g_app.tun_tcp_sndbuf));
                        UiText::InputText("TCP receive buffer (bytes)", g_app.tun_tcp_rcvbuf, sizeof(g_app.tun_tcp_rcvbuf));
                        ImGui::PopItemWidth();
                        ImGui::Checkbox("TCP auto-tuning", &g_app.tun_tcp_auto_tuning);
                        if (!fcae_parse_tcp_buffer_size(g_app.tun_tcp_sndbuf) || !fcae_parse_tcp_buffer_size(g_app.tun_tcp_rcvbuf))
                            UiText::TextColoredWrapped(ImVec4(1, 0.4f, 0.3f, 1), "Buffers: 4096..4194304 bytes.");
                    }
                }
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            }
            if (settings_category == 2) {
                ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "AETHER SETTINGS");
                ImGui::SetNextItemWidth(-FLT_MIN);
                ImGui::Combo("Section", &aether_settings_section, aether_settings_sections,
                             IM_ARRAYSIZE(aether_settings_sections));
                ImGui::Spacing();
                if (aether_settings_section == 0) {
                    ImGui::Separator();
                    listener_row("Aether SOCKS5", &g_app.socks_enabled, &g_app.socks_port, 1, 65535);
                    listener_row("Aether HTTP", &g_app.http_enabled, &g_app.http_port, 1, 65535);
                    ImGui::Text("Transport Options");
                    ImGui::Checkbox("ECH", &g_app.ech_enabled);
                    if (g_app.ech_enabled) {
                        ImGui::PushItemWidth(260);
                        UiText::InputTextWithHint("ECH resolver", "udp://1.1.1.1 | tcp:// | https:// DoH",
                                                 g_app.ech_dns, sizeof(g_app.ech_dns));
                        UiText::InputTextWithHint("ECH domain", "cloudflare-ech.com",
                                                 g_app.ech_domain, sizeof(g_app.ech_domain));
                        ImGui::PopItemWidth();
                    }
                    ImGui::Checkbox("Quick Reconnect", &g_app.quick_reconnect);
                    if (g_app.protocol == 6) {
                        ImGui::PushItemWidth(260);
                        UiText::InputTextWithHint("Inner WireGuard endpoint", "auto (ip:port)",
                                                 g_app.gool_inner, sizeof(g_app.gool_inner));
                        ImGui::PopItemWidth();
                    }
                    ImGui::Spacing();
                    UiText::InputTextWithHint("Force peer (optional)", "ip:port",
                                             g_app.force_peer, sizeof(g_app.force_peer));
                    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                    const char* sysprofiles[] = { "Auto", "Low", "Medium", "High" };
                    ImGui::Combo("Performance profile", &g_app.sys_profile, sysprofiles, 4);

                    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                    // Verbosity of the Aether engine, not the UI log pane.
                    const char* engine_logs[] = {
                        "Off", "Error", "Warn", "Info", "Debug", "Trace",
                    };
                    ImGui::Combo("Aether engine log level", &g_app.engine_log, engine_logs, 6);
                    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                }
            }
            if (settings_category == 3) {
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

                {
                    ImU16 socks_port = (ImU16)g_app.psiphon_socks_port;
                    ImU16 http_port  = (ImU16)g_app.psiphon_http_port;
                    listener_row("Psiphon SOCKS5", &g_app.psiphon_socks_enabled, &socks_port, 1, 65535);
                    listener_row("Psiphon HTTP", &g_app.psiphon_http_enabled, &http_port, 1, 65535);
                    g_app.psiphon_socks_port = socks_port;
                    g_app.psiphon_http_port  = http_port;
                }

                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            }
            if (settings_category == 2 && aether_settings_section == 2) {
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
                UiText::InputTextMultiline("##tor_bridge_lines", g_app.tor_bridge_lines,
                                          sizeof(g_app.tor_bridge_lines), ImVec2(0, 60));
            }
            if (settings_category == 4) {
                ImGui::TextUnformatted("Protocol services");
                ImGui::Spacing();
                if (ImGui::Button("Firefox IP Protection settings", ImVec2(-FLT_MIN, 0)))
                    open_firefox_settings();
                if (ImGui::Button("URnetwork settings", ImVec2(-FLT_MIN, 0)))
                    open_urnetwork_settings();
                if (ImGui::Button("Xray / sing-box / Mihomo profiles", ImVec2(-FLT_MIN, 0)))
                    open_core_configs();
            }
            if (settings_category == 2 && aether_settings_section == 3) {
                ImGui::Spacing();
                ImGui::Text("Cloudflare Zero Trust (Teams)");
                UiText::InputTextWithHint("##team_name", "team-name", g_app.team_name, sizeof(g_app.team_name));
                ImGui::SameLine();
                ImGui::Text("Team");
                ImGui::Spacing();
                ImGui::Text("Authentication (choose one):");
                UiText::InputTextWithHint("##access_token", "JWT token from enrolment page", g_app.access_token, sizeof(g_app.access_token));
                ImGui::Spacing();
                ImGui::Text("--- or Service Token ---");
                UiText::InputTextWithHint("##access_client_id", "Client ID", g_app.access_client_id, sizeof(g_app.access_client_id));
                UiText::InputTextWithHint("##access_client_secret", "Client Secret", g_app.access_client_secret, sizeof(g_app.access_client_secret));
                ImGui::Spacing();
                ImGui::Text("--- or Email OTP ---");
                UiText::InputTextWithHint("##access_email", "user@example.com", g_app.access_email, sizeof(g_app.access_email));
            }
            if (settings_category == 2 && aether_settings_section == 1) {
                ImGui::Spacing();
                ImGui::TextUnformatted("Inline Routing Rules (Aether only)");
                const float rules_height = (std::max)(ImGui::GetTextLineHeightWithSpacing() * 4.0f,
                                                       ImGui::GetContentRegionAvail().y);
                UiText::InputTextMultilineWithHint("##routes_inline",
                    "[direct] domain.com,ip:1.2.3.4\n[block] ads.example,10.0.0.0/8\nRules: domain, IP, CIDR, port:3000-3010",
                    g_app.routes_inline, sizeof(g_app.routes_inline), ImVec2(-FLT_MIN, rules_height),
                    ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_WordWrap);
            }
            if (settings_category == 2 && aether_settings_section == 4) {
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
    #if defined(ANDROID)
                    android_ui_horizontal_drag_item();
    #endif
                    ImGui::SliderInt("Chunk Max (B)", &g_app.frag_max_size, 16, 128);
    #if defined(ANDROID)
                    android_ui_horizontal_drag_item();
    #endif
                    ImGui::SliderInt("Delay Min (ms)", &g_app.frag_min_delay, 0, 20);
    #if defined(ANDROID)
                    android_ui_horizontal_drag_item();
    #endif
                    ImGui::SliderInt("Delay Max (ms)", &g_app.frag_max_delay, 1, 50);
    #if defined(ANDROID)
                    android_ui_horizontal_drag_item();
    #endif
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
                UiText::InputTextWithHint("##tls_ciphers", "TLS 1.2 ciphers (default: Chrome's)",
                                         g_app.tls_ciphers, sizeof(g_app.tls_ciphers));
                UiText::InputTextWithHint("##tls13_ciphers", "TLS 1.3 ciphers", g_app.tls13_ciphers, sizeof(g_app.tls13_ciphers));
                UiText::InputTextWithHint("##tls_groups", "TLS groups", g_app.tls_groups, sizeof(g_app.tls_groups));
                UiText::InputTextWithHint("##tls_key_shares", "TLS key-share groups", g_app.tls_key_shares, sizeof(g_app.tls_key_shares));
                UiText::InputTextWithHint("##tls_sigalgs", "TLS signature algorithms", g_app.tls_sigalgs, sizeof(g_app.tls_sigalgs));
                UiText::InputTextWithHint("##tls_cert_compression", "Certificate compression (zlib:brotli:zstd)", g_app.tls_cert_compression, sizeof(g_app.tls_cert_compression));
                UiText::InputTextWithHint("##tls_alps", "ALPS mode (new or old)", g_app.tls_alps, sizeof(g_app.tls_alps));
                UiText::InputTextWithHint("##tls_trust_anchors", "Trust-anchor OIDs", g_app.tls_trust_anchors, sizeof(g_app.tls_trust_anchors));
                UiText::InputTextWithHint("##tls_server_padding", "Server padding (0-65535)", g_app.tls_server_padding, sizeof(g_app.tls_server_padding));
                ImGui::PopItemWidth();
            }
            if (settings_category == 2 && aether_settings_section == 5) {
                ImGui::Spacing();
                const char* modes[] = { "Turbo", "Balanced", "Thorough", "Verified", "Ironclad" };
                if (g_app.scan_mode > 4) g_app.scan_mode = 1;
                ImGui::Combo("Scan mode", &g_app.scan_mode, modes, 5);
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                ImGui::Text("MASQUE SNI");
                UiText::InputText("##sni", g_app.sni, sizeof(g_app.sni));
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                ImGui::Text("WARP API");
                UiText::InputTextWithHint("##api_address", "Address (default: built-in)",
                                         g_app.api_address, sizeof(g_app.api_address));
                UiText::InputTextWithHint("##api_host", "HTTP host (optional)",
                                         g_app.api_host, sizeof(g_app.api_host));
                UiText::InputTextWithHint("##api_sni", "TLS SNI (optional)",
                                         g_app.api_sni, sizeof(g_app.api_sni));
                ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
                ImGui::Text("Exit Countries");
                UiText::InputTextWithHint("##exit_loc", "any (DE,SE accepts / !IR,RU refuses)",
                                         g_app.exit_loc, sizeof(g_app.exit_loc));
            }
            ImGui::EndChild();
        }

        s_log_scroll_pending = false;
        if (main_page == 2) {
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
                UiText::TextColoredWrapped(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", g_app.copy_status);
            }
            ImGui::Spacing();

            // Reserve a real footer below the log rows so the Latest control
            // never covers the newest lines, including on short desktop windows.
            const float log_footer_h = ImGui::GetFrameHeightWithSpacing()
                + 2.0f * ImGui::GetStyle().WindowPadding.y + 4.0f;
            const float log_height = std::max(1.0f, ImGui::GetContentRegionAvail().y
                - log_footer_h - ImGui::GetStyle().ItemSpacing.y);
            // The log is text straight on the picture otherwise. It sits on
            // the panel the Home page's rows sit on.
            {
                const ImVec2 log_min = ImGui::GetCursorScreenPos();
                home_panel_background(log_min,
                    ImVec2(log_min.x + std::max(1.0f, ImGui::GetContentRegionAvail().x), log_min.y + log_height),
                    ImGui::GetStyle().ChildRounding);
            }
            ImGui::BeginChild("##log", ImVec2(0, log_height), ImGuiChildFlags_Borders,
                              ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // Take a thread-safe snapshot of the logs for rendering.
            // This avoids a data race with the FFI callback thread which
            // calls add_log() concurrently.
            auto& revision = s_logs_revision;
            auto& logs_snapshot = s_logs_snapshot;
            g_app.sync_logs(revision, logs_snapshot);

            const bool manual_scroll =
#if defined(ANDROID)
                android_ui_is_scrolling() ||
#endif
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
            ImGui::EndChild();
        }

    ImGui::EndChild();

    // The content pane ends above the fixed bottom navigation row, so each
    // page gets the full remaining width and height without the nav covering it.
    ImGui::SetCursorPosY(nav_y);
    ImGui::SetCursorPosX(ImGui::GetWindowContentRegionMin().x);
    const ImVec2 nav_origin = ImGui::GetCursorScreenPos();
    const float nav_width_all = ImGui::GetContentRegionAvail().x;
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(nav_origin.x, nav_origin.y - 6.0f),
        ImVec2(nav_origin.x + nav_width_all, nav_origin.y - 6.0f),
        IM_COL32(95, 112, 143, 185), 1.0f);
    const float nav_gap = page_style.ItemSpacing.x;
    const float nav_width = std::max(1.0f, (nav_width_all - nav_gap * 2.0f) / 3.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f, 6.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    auto nav_button = [&](const char* label, int page) {
        const bool selected = main_page == page;
        const ImVec4 base = selected ? ImVec4(0.10f, 0.38f, 0.60f, 0.98f)
                                     : ImVec4(0.10f, 0.13f, 0.20f, 0.92f);
        ImGui::PushStyleColor(ImGuiCol_Button, base);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
            selected ? ImVec4(0.15f, 0.49f, 0.74f, 1.0f)
                     : ImVec4(0.16f, 0.22f, 0.33f, 0.98f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.09f, 0.32f, 0.51f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text,
            selected ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
                     : ImVec4(0.78f, 0.82f, 0.90f, 1.0f));
        const float text_width = ImGui::CalcTextSize(label).x;
        const float inner_width = std::max(1.0f,
            nav_width - ImGui::GetStyle().FramePadding.x * 2.0f);
        const bool shrink_text = text_width > inner_width && text_width > 0.0f;
        if (shrink_text) {
            const float scale = std::max(0.72f, inner_width / text_width);
            ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * scale);
        }
        if (ImGui::Button(label, ImVec2(nav_width, nav_height)) && main_page != page) {
            main_page = page;
            ui_request_redraw();
        }
        if (shrink_text) ImGui::PopFont();
        ImGui::PopStyleColor(4);
    };
    nav_button("Settings", 0);
    ImGui::SameLine(0, nav_gap);
    nav_button("Home", 1);
    ImGui::SameLine(0, nav_gap);
    nav_button("Logs", 2);
    ImGui::PopStyleVar(3);

#if defined(ANDROID)
    android_ui_render_app_picker();
#else
    PlatformAppRouting::picker();
#endif
    render_protocol_editor();
    s_firefox_captcha_embedded = false;
    render_core_configs();
    render_firefox_settings();
    render_urnetwork_settings();
    render_firefox_add_account();
    render_firefox_code_prompt();
    render_firefox_captcha_popup();

    ImGui::PopStyleVar(2);
    ImGui::End();
#if !defined(ANDROID) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && !defined(FCAE_IOS)
    static ImGuiHorizontalDrag horizontal_drag;
    if (horizontal_drag.update()) ui_request_redraw();
#endif
}

#if defined(ANDROID)
void ui_release_view() {
    fcae_sponsor_set_ui_active(false);
    // The view is gone (rather than merely hidden), so its retained sponsor
    // still is disposable too. Encoded disk cache and active sessions survive;
    // the sponsor service hydrates the media again when a view returns.
    fcae_sponsor_release_media();
    std::vector<uint8_t>{}.swap(s_sponsor_rgba);
    std::vector<uint8_t>{}.swap(s_sponsor_background_rgba);
    s_sponsor_loaded_foreground_generation = 0;
    s_sponsor_loaded_background_generation = 0;
    s_about_popup_open = false;
    s_connection_info_popup_open = false;
    s_update_popup_open = false;
    s_update_decode_popup_open = false;
    s_update_error_popup_open = false;
    std::vector<char>{}.swap(s_core_text_buf);
    s_core_editor_open = s_core_configs_popup_open = false;
    s_core_editor_fresh = false;
    s_core_editor_row = -1;
    s_core_name_buf[0] = s_core_status[0] = 0;
    std::vector<int>{}.swap(s_chain_draft);
    s_chain_editor_popup_open = false;
    s_firefox_settings_popup_open = s_firefox_settings_visible = false;
    s_firefox_add_popup_open = s_firefox_code_popup_open = false;
    s_firefox_add_should_close = s_firefox_code_should_close = false;
    std::vector<uint8_t>{}.swap(s_firefox_captcha_rgba);
    s_firefox_captcha_width = s_firefox_captcha_height = 0;
    g_app.firefox_captcha_id = 0;
    decltype(s_logs_snapshot){}.swap(s_logs_snapshot);
    s_logs_revision = ~0ULL;
    ui_request_redraw();
}
#endif
