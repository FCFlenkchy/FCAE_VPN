#include "ui_render.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <cctype>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#elif !defined(ANDROID)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// ── Global application state ─────────────────────────────────────────────

AppState g_app;

// ── Idle-friendly rendering ──────────────────────────────────────────────
// Everything below decides whether a frame needs to be painted at all. The
// window content is a pure function of telemetry + logs + UI state, so a cheap
// FNV-1a fingerprint of exactly those values tells us when repainting would
// produce identical pixels — and then the platform loop simply sleeps instead.

// Update-check UI state, hoisted out of render_ui() so the fingerprint can see
// when the update panel still has live content (e.g. "Checking... (3s)").
static bool s_update_checked = false;
static bool s_update_available = false;
static char s_update_status[128] = {};
static char s_update_latest[32] = {};
static char s_update_notes[1024] = {};
static char s_update_dl_url[512] = {};
static bool s_update_popup_open = false;
static bool s_about_popup_open = false;
static char s_update_date[32] = {};
static std::chrono::steady_clock::time_point s_check_start_time = std::chrono::steady_clock::now();
static bool s_update_in_progress = false;

// What the last painted frame looked like / when it was painted.
static uint64_t s_painted_sig = 0;
static bool s_log_scroll_pending = false;
static bool     s_painted_once = false;
static double   s_last_paint_t = 0.0;

// UI state that keeps needing frames on its own.
static bool s_busy_anim = false;      // connect/scan spinner is on screen
static bool s_text_input = false;     // a text field is focused (blinking caret)

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

/// Fingerprint of everything the UI paints. Unchanged fingerprint + no input ⇒
/// the next frame would be pixel-identical, so it can be skipped.
static uint64_t ui_content_signature() {
    uint64_t h = 1469598103934665603ull;   // FNV-1a offset basis

    const FcaeTelemetry& t = g_app.telem;
    h = fnv_value(h, t.state);
    h = fnv_value(h, t.rtt_ms);
    h = fnv_value(h, t.rx_bytes_sec);
    h = fnv_value(h, t.tx_bytes_sec);
    h = fnv_value(h, t.total_rx);
    h = fnv_value(h, t.total_tx);
    h = fnv_cstr(h, t.connected_peer);
    h = fnv_cstr(h, t.lan_ip);
    h = fnv_cstr(h, t.status_message);
    h = fnv_cstr(h, t.last_error);

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
    h = fnv_value(h, g_app.mode);
    h = fnv_value(h, g_app.tun_engine);
    h = fnv_value(h, g_app.scan_mode);
    h = fnv_value(h, g_app.ip_version);
    h = fnv_value(h, g_app.lan_sharing);
    h = fnv_value(h, g_app.quick_reconnect);
    h = fnv_value(h, g_app.socks_enabled);
    h = fnv_value(h, g_app.http_enabled);
    h = fnv_value(h, g_app.tor_http_enabled);
    h = fnv_value(h, g_app.tor_http_port);
    h = fnv_value(h, g_app.socks_port);
    h = fnv_value(h, g_app.http_port);
    h = fnv_value(h, g_app.h2_enabled);
    h = fnv_value(h, g_app.ech_enabled);
    h = fnv_value(h, g_app.sys_profile);
    h = fnv_value(h, g_app.engine_log);
    h = fnv_value(h, g_app.t2s_log);
    h = fnv_value(h, g_app.tor_mode);
    h = fnv_value(h, g_app.tor_bridges);
    h = fnv_cstr(h, g_app.tor_bridge_lines);
    h = fnv_cstr(h, g_app.tun_mtu);
    h = fnv_cstr(h, g_app.tun_tcp_sndbuf);
    h = fnv_cstr(h, g_app.tun_tcp_rcvbuf);
    h = fnv_value(h, g_app.tun_tcp_auto_tuning);
    h = fnv_cstr(h, g_app.tun_dns4);
    h = fnv_cstr(h, g_app.tun_dns6);
    h = fnv_cstr(h, g_app.noize_profile);
    h = fnv_cstr(h, g_app.force_peer);
    h = fnv_cstr(h, g_app.config_path);
    h = fnv_cstr(h, g_app.sni);
    h = fnv_cstr(h, g_app.team_name);
    h = fnv_cstr(h, g_app.access_token);
    h = fnv_cstr(h, g_app.access_email);
    h = fnv_cstr(h, g_app.routes_file);
    h = fnv_cstr(h, g_app.routes_inline);
    h = fnv_cstr(h, g_app.save_status);
    h = fnv_cstr(h, g_app.copy_status);
    h = fnv_value(h, g_app.start_busy.load());

    // Update panel (button label, "Checking... (Ns)" counter, popup contents).
    h = fnv_value(h, s_update_checked);
    h = fnv_value(h, s_update_available);
    h = fnv_value(h, s_update_in_progress);
    h = fnv_value(h, s_update_popup_open);
    h = fnv_value(h, s_about_popup_open);
    h = fnv_cstr(h, s_update_status);
    h = fnv_cstr(h, s_update_latest);
    h = fnv_cstr(h, s_update_notes);
    h = fnv_cstr(h, s_update_dl_url);
    return h;
}

/// True while the engine is running in any live state — the only time the
/// telemetry numbers (and therefore the painted content) can move on their own.
static bool ui_stats_live() {
    return g_app.ffi_state.load() != FCAE_STATE_DISCONNECTED || g_app.start_busy.load();
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
        next_lan_probe = now + 1.0;
    }
    g_app.telem = telem;
    g_app.ffi_state.store(telem.state);
    g_app.ffi_connected.store(telem.state == FCAE_STATE_CONNECTED);
    g_app.last_telem_t = now;
}

void ui_request_redraw() {
    g_app.redraw_requested.store(true);
}

bool ui_should_render(bool interacting) {
    const double now = ui_now_seconds();

    // Telemetry is the main thing that changes without user input; poll it here
    // so the fingerprint below is up to date.
    ui_poll_telemetry(now);

    // A redraw request is only cleared once a frame is really painted, so it
    // cannot be lost while the window is minimized.
    if (g_app.redraw_requested.load() || s_log_scroll_pending) return true;

    // The user is interacting: paint every frame the caller offers (hover,
    // drag, typing, scroll). The platform caps this at ~60 FPS.
    if (interacting) return true;

    // Spinner/connect animation is running: it moves on its own.
    if (s_busy_anim) return true;

    // Nothing changed since the last painted frame → the frame would be
    // pixel-identical, so skip it and let the platform go back to sleep.
    if (s_painted_once && ui_content_signature() == s_painted_sig) {
        // …except for the few things that tick slowly on their own:
        const double period = (s_update_in_progress || s_text_input) ? 0.5 : 0.0;
        if (period <= 0.0 || now - s_last_paint_t < period) return false;
    }
    return true;
}

unsigned ui_sleep_ms() {
    if (s_busy_anim) return 16;              // connect spinner: keep it smooth
    if (s_update_in_progress) return 250;    // "Checking... (Ns)" counter
    if (s_text_input) return 250;            // caret blink in a focused field
    if (ui_stats_live()) return 1000;        // counters/state refresh once a second
    return 1000;                             // idle: poll the engine once a second
}

void ui_note_frame_drawn() {
    s_painted_sig = ui_content_signature();
    s_painted_once = true;
    s_last_paint_t = ui_now_seconds();
    g_app.redraw_requested.store(false);
}

// ── Config persistence ──────────────────────────────────────────────────

static std::string join_cfg(const std::string& dir) {
    if (dir.empty()) return "FCAE_VPN.cfg";
    char sep =
#if defined(_WIN32)
        '\\';
#else
        '/';
#endif
    if (dir.back() == '/' || dir.back() == '\\') return dir + "FCAE_VPN.cfg";
    return dir + sep + "FCAE_VPN.cfg";
}

static std::string exe_dir() {
#if defined(ANDROID)
    return "/data/data/com.fc.fcaevpn/files";
#elif defined(_WIN32)
    wchar_t wbuf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, wbuf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::wstring w(wbuf, n);
    size_t slash = w.find_last_of(L"\\/");
    if (slash != std::wstring::npos) w.resize(slash);
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string u8((size_t)len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &u8[0], len, nullptr, nullptr);
    return u8;
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = PATH_MAX;
    if (_NSGetExecutablePath(buf, &size) == 0) {
        std::string p(buf);
        size_t slash = p.find_last_of('/');
        if (slash != std::string::npos) p.resize(slash);
        return p;
    }
    return {};
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

// Preferred write path: next to the executable (stable regardless of cwd).
static std::string get_config_path() {
    static std::string cached;
    if (!cached.empty()) return cached;
    std::string dir = exe_dir();
    cached = dir.empty() ? "FCAE_VPN.cfg" : join_cfg(dir);
    return cached;
}

// Open for read/write. On Windows use wide paths so UTF-8 exe dirs work.
static FILE* open_cfg(const std::string& path, const char* mode) {
#if defined(_WIN32)
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return nullptr;
    std::wstring wpath((size_t)wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);
    int mlen = MultiByteToWideChar(CP_UTF8, 0, mode, -1, nullptr, 0);
    if (mlen <= 0) return nullptr;
    std::wstring wmode((size_t)mlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, &wmode[0], mlen);
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

// Resolve which cfg to load: prefer next to exe, then cwd (legacy), then create at exe.
static std::string resolve_config_path_for_load() {
    std::string primary = get_config_path();
    if (file_exists(primary)) return primary;
    if (primary != "FCAE_VPN.cfg" && file_exists("FCAE_VPN.cfg"))
        return "FCAE_VPN.cfg";
    return primary;
}

// atoi wraps out-of-range and negative values; a config line saying
// socks_port=-1 would otherwise bind port 65535. Keep the previous value
// instead of trusting garbage.
static int parse_port(const std::string& v, int fallback) {
    int p = atoi(v.c_str());
    return (p > 0 && p < 65536) ? p : fallback;
}

static void apply_config_kv(const std::string& key, const std::string& val) {
    if (key == "protocol") g_app.protocol = atoi(val.c_str());
    else if (key == "backend") g_app.backend = atoi(val.c_str());
    else if (key == "tor_socks_port") g_app.tor_socks_port = parse_port(val, g_app.tor_socks_port);
    else if (key == "psiphon_region") snprintf(g_app.psiphon_region, sizeof(g_app.psiphon_region), "%s", val.c_str());
    else if (key == "tun_mtu") snprintf(g_app.tun_mtu, sizeof(g_app.tun_mtu), "%s", val.c_str());
    else if (key == "tun_tcp_sndbuf") snprintf(g_app.tun_tcp_sndbuf, sizeof(g_app.tun_tcp_sndbuf), "%s", val.c_str());
    else if (key == "tun_tcp_rcvbuf") snprintf(g_app.tun_tcp_rcvbuf, sizeof(g_app.tun_tcp_rcvbuf), "%s", val.c_str());
    else if (key == "tun_tcp_auto_tuning") g_app.tun_tcp_auto_tuning = atoi(val.c_str()) != 0;
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
    else if (key == "socks_port") g_app.socks_port = (uint16_t)parse_port(val, g_app.socks_port);
    else if (key == "http_port") g_app.http_port = (uint16_t)parse_port(val, g_app.http_port);
    else if (key == "socks_enabled") g_app.socks_enabled = atoi(val.c_str()) != 0;
    else if (key == "tor_http_port") g_app.tor_http_port = parse_port(val, g_app.tor_http_port);
    else if (key == "tor_http_enabled") g_app.tor_http_enabled = atoi(val.c_str()) != 0;
    else if (key == "http_enabled") g_app.http_enabled = atoi(val.c_str()) != 0;
    else if (key == "force_peer")
        snprintf(g_app.force_peer, sizeof(g_app.force_peer), "%s", val.c_str());
    else if (key == "config_path")
        snprintf(g_app.config_path, sizeof(g_app.config_path), "%s", val.c_str());
    else if (key == "h2_enabled") g_app.h2_enabled = atoi(val.c_str()) != 0;
    else if (key == "ech_enabled") g_app.ech_enabled = atoi(val.c_str()) != 0;
    else if (key == "sni")
        snprintf(g_app.sni, sizeof(g_app.sni), "%s", val.c_str());
    else if (key == "logging_enabled") g_app.logging_enabled = atoi(val.c_str()) != 0;
    else if (key == "auto_scroll") g_app.auto_scroll = atoi(val.c_str()) != 0;
    else if (key == "auto_update_check") g_app.auto_update_check = atoi(val.c_str()) != 0;
    else if (key == "check_prereleases") g_app.check_prereleases = atoi(val.c_str()) != 0;
    else if (key == "sys_profile") g_app.sys_profile = atoi(val.c_str());
    else if (key == "engine_log") g_app.engine_log = atoi(val.c_str());
    else if (key == "tun2socks_log") g_app.t2s_log = atoi(val.c_str());
    else if (key == "tor_mode") g_app.tor_mode = atoi(val.c_str());
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
}

static void save_config() {
    const std::string path = get_config_path();
    FILE* f = open_cfg(path, "wb");
    if (!f) {
        snprintf(g_app.save_status, sizeof(g_app.save_status), "Save failed");
        g_app.add_log(1, ("[ui] save failed: " + path).c_str());
        return;
    }
    // Always LF; empty values allowed. Line-based load is robust on Win/Linux.
    fprintf(f, "protocol=%d\n", g_app.protocol);
    fprintf(f, "backend=%d\n", g_app.backend);
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
    fprintf(f, "tor_http_port=%u\n", (unsigned)g_app.tor_http_port);
    fprintf(f, "tor_http_enabled=%d\n", g_app.tor_http_enabled ? 1 : 0);
    fprintf(f, "socks_enabled=%d\n", g_app.socks_enabled ? 1 : 0);
    fprintf(f, "http_enabled=%d\n", g_app.http_enabled ? 1 : 0);
    fprintf(f, "force_peer=%s\n", g_app.force_peer);
    fprintf(f, "config_path=%s\n", g_app.config_path);
    fprintf(f, "h2_enabled=%d\n", g_app.h2_enabled ? 1 : 0);
    fprintf(f, "ech_enabled=%d\n", g_app.ech_enabled ? 1 : 0);
    fprintf(f, "sni=%s\n", g_app.sni);
    fprintf(f, "tun_mtu=%s\n", g_app.tun_mtu);
    fprintf(f, "tun_tcp_sndbuf=%s\n", g_app.tun_tcp_sndbuf);
    fprintf(f, "tun_tcp_rcvbuf=%s\n", g_app.tun_tcp_rcvbuf);
    fprintf(f, "tun_tcp_auto_tuning=%d\n", g_app.tun_tcp_auto_tuning ? 1 : 0);
    fprintf(f, "tun_dns4=%s\n", g_app.tun_dns4);
    fprintf(f, "tun_dns6=%s\n", g_app.tun_dns6);
    fprintf(f, "logging_enabled=%d\n", g_app.logging_enabled ? 1 : 0);
    fprintf(f, "auto_scroll=%d\n", g_app.auto_scroll ? 1 : 0);
    fprintf(f, "auto_update_check=%d\n", g_app.auto_update_check ? 1 : 0);
    fprintf(f, "check_prereleases=%d\n", g_app.check_prereleases ? 1 : 0);
    fprintf(f, "sys_profile=%d\n", g_app.sys_profile);
    fprintf(f, "engine_log=%d\n", g_app.engine_log);
    fprintf(f, "tun2socks_log=%d\n", g_app.t2s_log);
    fprintf(f, "tor_mode=%d\n", g_app.tor_mode);
    fprintf(f, "tor_bridges=%d\n", g_app.tor_bridges);
    // The cfg file is line-based, so newlines in a value would corrupt it on
    // reload. The engine accepts ';' as a bridge-line separator too, so store
    // the multi-line box that way. (routes_inline has the same shape and the
    // same pre-existing caveat.)
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
    fprintf(f, "routes_inline=%s\n", g_app.routes_inline);
    fclose(f);
    snprintf(g_app.save_status, sizeof(g_app.save_status), "Config saved!");
    g_app.add_log(4, ("[ui] config saved: " + path).c_str());
}

static bool load_config_from(const std::string& path) {
    FILE* f = open_cfg(path, "rb");
    if (!f) return false;

    static char line[8192];
    int applied = 0;
    while (fgets(line, sizeof(line), f)) {
        // strip CR/LF and trailing spaces
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ' || line[len - 1] == '\t')) {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#' || line[0] == ';') continue;

        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char* key = line;
        const char* val = eq + 1;
        // trim key
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

    if (applied == 0) return false;
    snprintf(g_app.save_status, sizeof(g_app.save_status), "Config loaded!");
    g_app.add_log(4, ("[ui] config loaded (" + std::to_string(applied) + " keys): " + path).c_str());
    return true;
}

static bool load_config() {
    std::string path = resolve_config_path_for_load();
    if (!load_config_from(path)) return false;
    // If we loaded a legacy cwd cfg, migrate a copy next to the exe for next time.
    std::string primary = get_config_path();
    if (path != primary && !file_exists(primary)) {
        save_config();
        g_app.add_log(4, ("[ui] migrated config to " + primary).c_str());
    }
    return true;
}

void log_callback(FcaeLogLevel level, const char* message, void* user_data) {
    (void)user_data;
    if (g_app.logging_enabled) g_app.add_log((int)level, message);
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

static void draw_spinner(float radius, int segments, float speed) {
    float t = (float)ImGui::GetTime() * speed;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 c(p.x + radius + 2, p.y + radius);
    for (int i = 0; i < segments; i++) {
        float a = ((float)i / segments) * 6.2832f + t;
        float r = radius * 0.5f + radius * 0.5f * ((float)i / segments);
        float fade = (float)i / segments;
        ImVec4 col(0.3f + fade * 0.4f, 0.6f + fade * 0.2f, 1.0f, 0.3f + fade * 0.7f);
        dl->AddCircleFilled(ImVec2(c.x + cosf(a) * r, c.y + sinf(a) * r),
                            1.5f + fade, ImGui::ColorConvertFloat4ToU32(col));
    }
    ImGui::Dummy(ImVec2(radius * 2 + 4, radius * 2 + 4));
}

void ui_init() {
    FcaeInitOptions opt = {};
    opt.struct_size   = sizeof(opt);
    opt.abi_version   = FCAE_ABI_VERSION;
    opt.log_cb        = log_callback;
    opt.state_cb      = nullptr;   // the UI already polls telemetry each frame
    opt.user_data     = nullptr;
    opt.max_log_level = FCAE_LOG_INFO;
    if (fcae_init(&opt) != FCAE_OK) {
        g_app.add_log(FCAE_LOG_ERROR, fcae_last_error());
    }
    if (!load_config()) {
        // First run: write defaults next to the executable (or app files on
        // Android). AppState defaults mode = 1, so a fresh install starts in
        // TUN (full-system) mode on every desktop platform; a saved config
        // keeps whatever the user last chose.
        save_config();
        snprintf(g_app.save_status, sizeof(g_app.save_status), "Created FCAE_VPN.cfg");
        g_app.add_log(4, ("[ui] created default config: " + get_config_path()).c_str());
    }
    // Make relative identity path (aether.toml) resolve next to the executable
    if (g_app.config_path[0] && g_app.config_path[0] != '/' && g_app.config_path[0] != '\\'
        && !(g_app.config_path[0] && g_app.config_path[1] == ':')) {
        std::string dir = exe_dir();
        if (!dir.empty()) {
            char sep =
#if defined(_WIN32)
                '\\';
#else
                '/';
#endif
            std::string full = dir + sep + g_app.config_path;
            snprintf(g_app.config_path, sizeof(g_app.config_path), "%s", full.c_str());
        }
    }
    g_app.add_log(4, ("[ui] settings file: " + get_config_path()).c_str());
    g_app.add_log(4, (std::string("[ui] identity file: ") + g_app.config_path).c_str());

    // Psiphon keeps a persistent datastore and refuses to start without a
    // writable directory for it. Default it next to the executable, in its own
    // subdirectory so it never collides with the engine's state. The user can
    // still override it in the config file.
    if (g_app.psiphon_data_dir[0] == '\0') {
        std::string dir = exe_dir();
        if (!dir.empty()) {
            char sep =
#if defined(_WIN32)
                '\\';
#else
                '/';
#endif
            std::string full = dir + sep + "psiphon";
            snprintf(g_app.psiphon_data_dir, sizeof(g_app.psiphon_data_dir),
                     "%s", full.c_str());
        }
    }

    // Auto-trigger update check once on startup if enabled
    if (g_app.auto_update_check) {
        fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
    }
}

void ui_frame() {
    // The update panel sets this again below when a check is running; resetting
    // it first keeps the flag honest on frames that return early.
    s_update_in_progress = false;

    render_ui();

    // Bookkeeping for the render gate (ui_should_render/ui_sleep_ms):
    //  - a focused text field needs ~2 Hz frames so the caret keeps blinking,
    //  - the connect/scan spinner animates on its own and wants smooth frames.
    const ImGuiIO& io = ImGui::GetIO();
    s_text_input = io.WantTextInput;
    const int st = g_app.ffi_state.load();
    s_busy_anim = g_app.start_busy.load()
               || st == FCAE_STATE_PROVISIONING
               || st == FCAE_STATE_SCANNING
               || st == FCAE_STATE_CONNECTING
               || st == FCAE_STATE_RECONNECTING;

    ui_note_frame_drawn();
}

void ui_shutdown() {
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

// ── External links ───────────────────────────────────────────────────────
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
    return ImVec2(vp->Pos.x + vp->Size.x * 0.5f, vp->Pos.y + vp->Size.y * 0.5f);
}

static const char* const kLinkTelegram = "https://t.me/FCAE_VPN";
static const char* const kLinkGithub = "https://github.com/FCFlenkchy/FCAE_VPN";
static const std::string kLinkCredits = std::string(kLinkGithub) + "#credits";
struct CommunityLink { const char* label; const char* url; const char* shown; };
static const CommunityLink kCommunityLinks[] = {
    { "Telegram", kLinkTelegram, "t.me/FCAE_VPN" },
    { "GitHub",   kLinkGithub,   "github.com/FCFlenkchy/FCAE_VPN" },
};

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

    // ── 1. STATUS BAR + ACTIONS ──────────────────────────────────────────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 10));

        ImVec4 sc = state_color(cur);
        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        ImGui::Text("FCAE VPN");
        if (ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            ImGui::SetTooltip("About");
        }
        if (ImGui::IsItemClicked()) s_about_popup_open = true;
        ImGui::PopStyleColor();

        ImGui::SameLine(0, 10);
        ImGui::TextColored(build_is_prerelease() ? ImVec4(1.0f, 0.72f, 0.20f, 1.0f)
                                                : ImVec4(0.62f, 0.66f, 0.74f, 1.0f),
                           "%s  |  %s", fcae_display_version(),
                           build_is_prerelease() ? "pre-release" : "release");
        if (ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (build_is_prerelease())
                ImGui::SetTooltip("About\nThis build is a pre-release (%s).\n"
                                  "Update checks offer only newer versions, respecting\n"
                                  "your pre-releases setting.", fcae_display_version());
            else
                ImGui::SetTooltip("About\nThis build is a release (%s).", fcae_display_version());
        }
        if (ImGui::IsItemClicked()) s_about_popup_open = true;
        ImGui::SameLine(0, 10);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 0.75f, 0.80f, 1.0f));
        ImGui::Text("|");
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 10);
        bool tun_paused = false;
        try { tun_paused = fcae_tun_paused(); } catch (...) {}
        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        // If errored and we have an error message, show it instead of just "ERROR"
        if (errored && telem.last_error[0]) {
            ImGui::Text("ERROR: %s", telem.last_error);
        } else {
            // Stop only turns the TUN interface off; the status keeps
            // showing the live session state while paused.
            ImGui::Text("%s", state_label(cur));
        }
        ImGui::PopStyleColor();

        if (busy) { ImGui::SameLine(0, 8); draw_spinner(7.0f, 14, 7.0f); }

        if (!narrow) {
            ImGui::SameLine(0, 16);
        } else {
            ImGui::Spacing();
        }

        ImVec4 btn = (connected || busy) ? ImVec4(0.70f, 0.18f, 0.18f, 1.0f) : ImVec4(0.12f, 0.55f, 0.18f, 1.0f);
        ImVec4 btn_h(btn.x + 0.08f, btn.y + 0.08f, btn.z + 0.08f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, btn_h);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(btn.x - 0.05f, btn.y - 0.05f, btn.z - 0.05f, 1.0f));

        float btn_w = narrow ? (ImGui::GetContentRegionAvail().x - 72.0f) : 140.0f;
        bool show_disconnect = connected || busy || tun_paused;
        if (ImGui::Button(show_disconnect ? " DISCONNECT " : " CONNECT ", ImVec2(btn_w, 34))) {
            if (connected || busy || errored || tun_paused) {
                g_app.start_busy.store(false);
                // fcae_stop() is a fast control path: it cancels the session
                // and aborts the TUN descriptors, then returns while the full
                // teardown (routes/DNS restore, engine stop) runs on the
                // session worker. It is run on a detached thread purely so the
                // window keeps painting; the UI may offer CONNECT again at
                // once — the next start blocks on the reaper barrier until the
                // teardown finishes, so nothing races the previous session.
                std::thread([] {
                    if (fcae_stop() != FCAE_OK) {
                        g_app.add_log(FCAE_LOG_WARN, fcae_last_error());
                    }
                    g_app.ffi_state.store(FCAE_STATE_DISCONNECTED);
                    ui_request_redraw();
                }).detach();
            } else if (!g_app.start_busy.load()) {
                // TUN mode requires admin privileges on Windows
                if (g_app.mode == 1 && !fcae_is_privileged()) {
#ifdef _WIN32
                    // Save config then relaunch self as administrator.
                    // The elevated instance will start fresh — user clicks CONNECT manually.
                    save_config();
                    wchar_t exe_path[MAX_PATH];
                    GetModuleFileNameW(NULL, exe_path, MAX_PATH);

                    SHELLEXECUTEINFOW sei = {};
                    sei.cbSize = sizeof(sei);
                    sei.lpVerb = L"runas";
                    sei.lpFile = exe_path;
                    sei.lpParameters = L"";
                    sei.nShow = SW_NORMAL;
                    sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
                    if (ShellExecuteExW(&sei)) {
                        // Successfully launched elevated copy — give it a moment
                        // to take over the launcher slot and surface any UAC
                        // prompt before we exit. Without this sleep, the
                        // elevated process can race the parent teardown and
                        // produce an orphaned elevated instance plus the
                        // confusing "the app just quit" support report.
                        // Log the relaunch too: the Logs tab then names the
                        // elevated PID the session was handed to, and a later
                        // bind failure has a breadcrumb.
                        DWORD child_pid = sei.hProcess ? GetProcessId(sei.hProcess) : 0;
                        char msg[160];
                        snprintf(msg, sizeof(msg),
                            "[ui] TUN mode needs elevation -- relaunching elevated (PID %lu). "
                            "The non-elevated copy will exit in ~700ms.",
                            static_cast<unsigned long>(child_pid));
                        if (sei.hProcess) CloseHandle(sei.hProcess);
                        g_app.add_log(FCAE_LOG_INFO, msg);
                        snprintf(g_app.save_status, sizeof(g_app.save_status),
                            "Restarting elevated -- current copy will close");
                        std::thread([] {
                            // Hand-off window: enough for UAC to dismiss and
                            // for the elevated copy to enter its message loop
                            // before this instance's WM_DESTROY arrives.
                            Sleep(700);
                            g_app.running.store(false);
                            PostQuitMessage(0);
                        }).detach();
                        ImGui::PopStyleColor(3);  // button colors
                        ImGui::PopStyleVar(2);    // status bar FrameRounding/FramePadding
                        ImGui::PopStyleVar(2);    // window WindowPadding/WindowRounding
                        ImGui::End();
                        return;
                    } else {
                        // Say what happened rather than leaving TUN silently
                        // "not working": the usual cause is a declined UAC
                        // prompt, where GetLastError() is ERROR_CANCELLED.
                        DWORD err = GetLastError();
                        const char* why =
                            err == ERROR_CANCELLED ? "UAC consent was cancelled"
                            : err == ERROR_ACCESS_DENIED ? "access was denied"
                            : err == ERROR_FILE_NOT_FOUND ? "the executable path is missing"
                            : "ShellExecuteExW failed";
                        char msg[160];
                        snprintf(msg, sizeof(msg),
                            "[ui] TUN mode requires Administrator privileges (%s, Win32 error %lu). "
                            "Click CONNECT again, accept the UAC prompt, or restart FCAE VPN "
                            "elevated once and the elevated copy will handle every future start.",
                            why, static_cast<unsigned long>(err));
                        g_app.add_log(FCAE_LOG_ERROR, msg);
                        // The status string is shown next to the CONNECT button
                        // until cleared, so the user gets persistent feedback
                        // even if the log scrolls.
                        snprintf(g_app.save_status, sizeof(g_app.save_status),
                            "TUN needs Admin (error %lu) -- click CONNECT to retry UAC",
                            static_cast<unsigned long>(err));
                        ImGui::PopStyleColor(3);  // button colors
                        ImGui::PopStyleVar(2);    // status bar FrameRounding/FramePadding
                        ImGui::PopStyleVar(2);    // window WindowPadding/WindowRounding
                        ImGui::End();
                        return;
                    }
#else
                    g_app.add_log(FCAE_LOG_ERROR,
                        "[ui] TUN mode requires root privileges on this platform. "
                        "Restart the app with sudo (or as Administrator via pkexec/polkit) and try again.");
                    snprintf(g_app.save_status, sizeof(g_app.save_status),
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
                    std::string psi_json, psi_embedded;
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
                o->path  = g_app.config_path;
                o->sni   = g_app.sni;
                o->team  = g_app.team_name;
                o->token = g_app.access_token;
                o->email = g_app.access_email;
                o->routes = g_app.routes_file;
                o->routes_inline = g_app.routes_inline;
                o->c = g_app.to_config();
                // to_config() built the JSON (with the server-entry fields
                // merged in) into a g_app buffer; snapshot it, and read the
                // embedded server entry list, so fcae_start only ever sees
                // pointers owned by this worker.
                o->psi_json = g_app.psiphon_config_json_built;
                {
                    // Auto-load psiphon_servers.txt
                    // from the executable's directory when it exists and has
                    // content: the drop-in bundled-entries slot. Put entries
                    // you are ENTITLED to distribute there (your own servers
                    // or Psiphon-Labs provisioning) — never entries extracted
                    // from other clients; redistributing the Psiphon
                    // network's server addresses unprovisioned is what gets
                    // repositories taken down.
                    std::string bundled = exe_dir() + "/psiphon_servers.txt";
                    std::ifstream f(bundled, std::ios::binary);
                    if (f) {
                        std::ostringstream ss;
                        ss << f.rdbuf();
                        o->psi_embedded = ss.str();
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
                o->c.dns.sni                   = o->sni.empty() ? nullptr : o->sni.c_str();
                o->c.zero_trust.team_name      = o->team.empty() ? nullptr : o->team.c_str();
                o->c.zero_trust.access_token   = o->token.empty() ? nullptr : o->token.c_str();
                o->c.zero_trust.access_email   = o->email.empty() ? nullptr : o->email.c_str();
                o->c.routing.rules_file        = o->routes.empty() ? nullptr : o->routes.c_str();
                o->c.routing.rules_inline      = o->routes_inline.empty() ? nullptr : o->routes_inline.c_str();
                o->c.psiphon.config_json          = o->psi_json.c_str();
                o->c.psiphon.embedded_server_list =
                    o->psi_embedded.empty() ? nullptr : o->psi_embedded.c_str();
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
        ImGui::PopStyleColor(3);

        if (g_app.mode == 1 && (connected || tun_paused)) {
            ImGui::SameLine(0, 6);
            if (tun_paused) {
                ImVec4 start_col(0.18f, 0.35f, 0.85f, 1.0f);
                ImVec4 start_h(0.26f, 0.45f, 0.95f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, start_col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, start_h);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(start_col.x - 0.05f, start_col.y - 0.05f, start_col.z - 0.05f, 1.0f));
                if (ImGui::Button(" START ", ImVec2(80, 26))) {
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
                if (ImGui::Button(" STOP ", ImVec2(80, 26))) {
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

        ImGui::SameLine(0, 6);
        if (ImGui::Button("Save", ImVec2(60, 34))) {
            save_config();
        }


        if (g_app.save_status[0]) {
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", g_app.save_status);
            g_app.save_status[0] = '\0';
        }

        ImGui::Spacing();
        // ── Check for Updates button (centered) ─────────────────────
        {
            float btn_width = 160.0f;
            float avail = ImGui::GetContentRegionAvail().x;
            ImGui::SetCursorPosX((avail - btn_width) * 0.5f);
        FcaeUpdateInfo info = {};
        info.struct_size = sizeof(info);
        info.abi_version = FCAE_ABI_VERSION;
        bool done = (fcae_poll_update(&info) == FCAE_OK);
        // The render gate watches this so the "Checking... (Ns)" counter keeps
        // ticking (1 Hz) even when the user is not touching the window.
        s_update_in_progress = info.check_in_progress;
        snprintf(s_update_date, sizeof(s_update_date), "%s", info.release_date);

        if (info.check_in_progress) {
            // Safety timeout: if check takes >15s, show timeout message
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_check_start_time).count();
            if (elapsed > 15) {
                // Show timeout — the FFI check_in_progress is stuck, but we override the display
                s_update_checked = true;
                s_update_available = false;
                snprintf(s_update_status, sizeof(s_update_status), "Check timed out (network unreachable?)");
                if (ImGui::Button("Check for Updates", ImVec2(btn_width, 34))) {
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
            } else {
                ImGui::BeginDisabled();
                ImGui::Button("Checking...", ImVec2(btn_width, 34));
                ImGui::EndDisabled();
                ImGui::SameLine(0, 6);
                ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "(%llds)", (long long)elapsed);
            }
        } else if (done && info.update_available) {
                s_update_available = true;
                s_update_checked = true;
                snprintf(s_update_latest, sizeof(s_update_latest), "%s", info.latest_version);
                snprintf(s_update_notes, sizeof(s_update_notes), "%s", info.release_notes);
                snprintf(s_update_dl_url, sizeof(s_update_dl_url), "%s", info.download_url);
                snprintf(s_update_status, sizeof(s_update_status), "%.127s", info.status_message);

                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.55f, 0.0f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.65f, 0.1f, 1.0f));
                const char* label = "Update Available!";
                if (ImGui::Button(label, ImVec2(btn_width, 34))) {
                    s_update_popup_open = true;
                }
                ImGui::PopStyleColor(2);
            } else if (done && !info.update_available) {
                // Check finished — no update needed, but allow re-check
                s_update_available = false;
                s_update_checked = true;
                snprintf(s_update_status, sizeof(s_update_status), "%.127s", info.status_message);
                if (ImGui::Button("Check for Updates", ImVec2(btn_width, 34))) {
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_update_available = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
            } else {
                if (ImGui::Button("Check for Updates", ImVec2(btn_width, 34))) {
                    fcae_check_update_async(FCAE_VERSION, g_app.check_prereleases);
                    s_update_checked = false;
                    s_update_available = false;
                    s_check_start_time = std::chrono::steady_clock::now();
                }
            }

            // Status text
        if ((done || (info.check_in_progress && s_update_checked)) && !s_update_available && s_update_checked) {
            ImGui::SetCursorPosX((avail - btn_width) * 0.5f);
            bool is_error = strstr(s_update_status, "Failed") != nullptr ||
                            strstr(s_update_status, "failed") != nullptr ||
                            strstr(s_update_status, "HTTP") != nullptr ||
                            strstr(s_update_status, "error") != nullptr ||
                            strstr(s_update_status, "timed out") != nullptr;
            if (is_error) {
                ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.3f, 1.0f), "%s", s_update_status);
            } else {
                ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", s_update_status);
            }
        }

            // Update popup modal
            if (s_update_popup_open) {
                ImGui::OpenPopup("##update_popup");
                s_update_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            if (ImGui::BeginPopupModal("##update_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize)) {
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
                    // Defense-in-depth on top of the FFI-side prefix check.
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

            if (s_about_popup_open) {
                ImGui::OpenPopup("##about_popup");
                s_about_popup_open = false;
            }
            ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            if (ImGui::BeginPopupModal("##about_popup", nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::TextUnformatted("FCAE VPN");
                ImGui::TextColored(build_is_prerelease() ? ImVec4(1.0f, 0.72f, 0.20f, 1.0f)
                                                         : ImVec4(0.62f, 0.66f, 0.74f, 1.0f),
                                   "%s  |  %s", fcae_display_version(),
                                   build_is_prerelease() ? "pre-release" : "release");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();
                for (const CommunityLink& link : kCommunityLinks) {
                    if (ImGui::TextLink(link.label))
                        open_link(link.url);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s", link.url);
                    ImGui::SameLine(96.0f);
                    ImGui::TextDisabled("%s", link.shown);
                }
                ImGui::Spacing();
                ImGui::TextDisabled(build_is_prerelease() ? "Pre-released under the MIT License." : "Released under the MIT License.");
                ImGui::TextDisabled("Credits are listed in the");
                ImGui::SameLine(0, 4);
                if (ImGui::TextLink("GitHub repository"))
                    open_link(kLinkCredits.c_str());
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", kLinkCredits.c_str());
                ImGui::Spacing();
                if (ImGui::Button("Telegram")) open_link(kCommunityLinks[0].url);
                ImGui::SameLine();
                if (ImGui::Button("GitHub")) open_link(kCommunityLinks[1].url);
                ImGui::SameLine();
                if (ImGui::Button("Close"))
                    ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
        }

        ImGui::PopStyleVar(2);
    }

    // Error message is now shown inline in the status bar above (avoids double display)

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── 2. TRAFFIC STATS ─────────────────────────────────────────────────
    {
        char total_buf[32], rate_buf[32];

        if (narrow) {
            ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "Download");
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_rx);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.rx_bytes_sec);
            ImGui::Text("%s  %s", total_buf, rate_buf);

            ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "Upload");
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_tx);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.tx_bytes_sec);
            ImGui::Text("%s  %s", total_buf, rate_buf);
        } else {
            ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "Download");
            ImGui::SameLine(0, 12);
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_rx);
            ImGui::Text("%s", total_buf);
            ImGui::SameLine(0, 12);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.rx_bytes_sec);
            ImGui::TextColored(ImVec4(0.50f, 0.50f, 0.55f, 1.0f), "%s", rate_buf);

            ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "Upload  ");
            ImGui::SameLine(0, 12);
            fmt_bytes(total_buf, sizeof(total_buf), telem.total_tx);
            ImGui::Text("%s", total_buf);
            ImGui::SameLine(0, 12);
            fmt_rate(rate_buf, sizeof(rate_buf), telem.tx_bytes_sec);
            ImGui::TextColored(ImVec4(0.50f, 0.50f, 0.55f, 1.0f), "%s", rate_buf);
        }

        ImGui::Spacing();
        // The reading itself, bare, in the same shape the Android surfaces use:
        // no label and no placeholder, just the number and its unit. Outside
        // CONNECTED there is no live measurement (the engine keeps the previous
        // session's rtt_ms, and a stale number must not pass for a live one), so
        // the slot reads 0ms.
        char rtt_buf[24];
        snprintf(rtt_buf, sizeof(rtt_buf), "%ums",
                 telem.state == FCAE_STATE_CONNECTED ? telem.rtt_ms : 0u);
        // No mode here: the state line states it once, the way the Android
        // status does ("CONNECTED - TUN"/"CONNECTED - PROXY", state_label).
        if (telem.backend == FCAE_BACKEND_PSIPHON || g_app.protocol == 4) {
            ImGui::TextWrapped("%s", rtt_buf);
        } else {
            ImGui::TextWrapped("Peer: %s  |  %s",
                telem.connected_peer[0] ? telem.connected_peer : "-",
                rtt_buf);
        }
        // The state line owns the connect phase ("CONNECTING", nothing
        // else — same as the Psiphon paths and the Android UI); the
        // engine's sub-message is connected-state telemetry only.
        if (telem.status_message[0] && telem.state == FCAE_STATE_CONNECTED) {
            ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.60f, 1.0f), "%s", telem.status_message);
        }
    }

    // ── Address callout ──────────────────────────────────────────────────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.10f, 0.16f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.85f, 0.45f, 1.0f));
        float addr_h = narrow ? 130.0f : 94.0f;
        ImGui::BeginChild("##addr", ImVec2(0, addr_h), ImGuiChildFlags_Borders);

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
            ImGui::TextWrapped("Routing: %s", telem.status_message);
            if (telem.backend != FCAE_BACKEND_PSIPHON) {
                if (g_app.protocol != 4 && (g_app.socks_enabled || g_app.mode == 1 || g_app.tor_mode != 0)) endpoint("Aether", "SOCKS5", g_app.socks_port ? g_app.socks_port : 1819);
                if (g_app.protocol != 4 && g_app.http_enabled) endpoint("Aether", "HTTP", g_app.http_port);
                if (g_app.tor_http_enabled && (g_app.protocol == 4 || g_app.tor_mode == 1 || g_app.tor_mode == 2))
                    endpoint("Tor", "HTTP", g_app.tor_http_port);
                if (g_app.protocol == 4 || g_app.tor_mode == 1 || g_app.tor_mode == 2)
                    endpoint("Tor", "SOCKS5", g_app.tor_socks_port ? g_app.tor_socks_port : 1821);
            }
            if (telem.backend == FCAE_BACKEND_PSIPHON || g_app.tor_mode == 3) {
                endpoint("Psiphon", "SOCKS5", fcae_psiphon_socks_port());
                endpoint("Psiphon", "HTTP", fcae_psiphon_http_port());
            }
        } else {
            ImGui::Text("  No active tunnel");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── 3. CONFIG TABS (fill remaining height) ───────────────────────────
    float remain = ImGui::GetContentRegionAvail().y;
    if (remain < 120.0f) remain = 120.0f;
    ImGui::BeginChild("##tabs_host", ImVec2(0, remain), ImGuiChildFlags_None);

    if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {

        if (ImGui::BeginTabItem("Protocol")) {
            ImGui::BeginChild("##proto_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Transport");
            // H2 is folded into the MASQUE entries (used to be a separate
            // "HTTP/2 Fallback" checkbox). Underlying config keeps the same
            // two fields the FFI always took: protocol (0/1/2) + h2_enabled.
            // idx 0 = MASQUE H3, 1 = MASQUE H2, 2 = WireGuard, 3 = WIW.
            // idx 4 = Tor, 5 = Psiphon. Both are peers of the WARP
            // transports to the user even though internally Tor is an engine
            // egress (tor.mode = Only) and Psiphon is a separate backend.
            int transport = (g_app.backend == 1)  ? 5
                          : (g_app.protocol == 5) ? (g_app.h2_enabled ? 7 : 6)
                          : (g_app.protocol == 4) ? 4
                          : (g_app.protocol == 0) ? (g_app.h2_enabled ? 1 : 0)
                          : (g_app.protocol == 1) ? 2 : 3;
            if (ImGui::RadioButton("MASQUE (HTTP/3 QUIC)", &transport, 0)) {
                g_app.protocol = 0; g_app.h2_enabled = false; g_app.backend = 0;
            }
            if (ImGui::RadioButton("MASQUE (HTTP/2 TLS)", &transport, 1)) {
                g_app.protocol = 0; g_app.h2_enabled = true; g_app.backend = 0;
            }
            if (ImGui::RadioButton("MASQUE-in-MASQUE (HTTP/3)", &transport, 6)) {
                g_app.protocol = 5; g_app.h2_enabled = false; g_app.backend = 0;
            }
            if (ImGui::RadioButton("MASQUE-in-MASQUE (HTTP/2)", &transport, 7)) {
                g_app.protocol = 5; g_app.h2_enabled = true; g_app.backend = 0;
            }
            if (ImGui::RadioButton("WireGuard", &transport, 2)) {
                g_app.protocol = 1; g_app.backend = 0;
            }
            if (ImGui::RadioButton("WARP-in-WARP (Gool)", &transport, 3)) {
                g_app.protocol = 2; g_app.backend = 0;
            }
            if (ImGui::RadioButton("Tor", &transport, 4)) {
                // FcaeProtocol::Tor. Do not reset the egress combo — the
                // Tor entries gray out and "Psiphon through the tunnel"
                // stays available (chains behind the Tor-only engine).
                g_app.protocol = 4; g_app.backend = 0;
            }
            if (ImGui::RadioButton("Psiphon", &transport, 5)) {
                // Psiphon picks its own transport, hence FcaeProtocol::Auto.
                g_app.protocol = 3; g_app.backend = 1;
            }
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Mode");
            ImGui::RadioButton("Proxy", &g_app.mode, 0);
            ImGui::RadioButton("TUN",   &g_app.mode, 1);
            ImGui::Checkbox("LAN Sharing", &g_app.lan_sharing);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Transport Options");
            ImGui::Checkbox("ECH", &g_app.ech_enabled);
            ImGui::Checkbox("Quick Reconnect", &g_app.quick_reconnect);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Proxy Ports");
            ImGui::PushItemWidth(100);
            // No forcing, no locking: the checkbox governs proxy mode only.
            // In TUN the local SOCKS5 listener is mandatory, so to_config()
            // ignores the checkbox there and always raises it (same rule as
            // Android's FCAEVpnService).
            ImGui::Checkbox("SOCKS5", &g_app.socks_enabled);
            ImGui::SameLine(0, 20);
            ImGui::InputScalar("##socks", ImGuiDataType_U16, &g_app.socks_port);
            ImGui::Checkbox("Aether HTTP proxy", &g_app.http_enabled);
            ImGui::SameLine(0, 20);
            ImGui::InputScalar("##http", ImGuiDataType_U16, &g_app.http_port);
            ImGui::PopItemWidth();
            if (g_app.mode == 1)
                ImGui::TextDisabled("TUN always raises the local SOCKS5 listener; this checkbox only governs proxy mode.");
            ImGui::Spacing();
            if (g_app.mode == 1 && ImGui::CollapsingHeader("TUN Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
                ImGui::Text("TUN engine");
                ImGui::SameLine(0, 8);
                ImGui::PushItemWidth(140);
                FcaeTunEngineInfo tei[4];
                const char* te_names[4];
                uint32_t te_n = fcae_tun_engine_count();
                if (te_n > 4) te_n = 4;
                for (uint32_t i = 0; i < te_n; ++i) {
                    memset(&tei[i], 0, sizeof(tei[i]));
                    tei[i].struct_size = sizeof(tei[i]);
                    tei[i].abi_version = FCAE_ABI_VERSION;
                    te_names[i] = fcae_tun_engine_info(i, &tei[i]) == FCAE_OK ? tei[i].display_name : "?";
                }
                int te_sel = (g_app.tun_engine >= 0 && g_app.tun_engine < (int)te_n) ? g_app.tun_engine : 0;
                if (ImGui::Combo("##tun_engine", &te_sel, te_names, (int)te_n))
                    g_app.tun_engine = te_sel;
                ImGui::PopItemWidth();
                if (te_sel < (int)te_n && !tei[te_sel].available)
                    ImGui::TextColored(ImVec4(1, 0.6f, 0.2f, 1), "%s", tei[te_sel].unavailable_reason);
                ImGui::Spacing();
                ImGui::PushItemWidth(160);
                ImGui::InputText("TUN MTU (bytes)", g_app.tun_mtu, sizeof(g_app.tun_mtu));
                ImGui::PopItemWidth();
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
            ImGui::Spacing();
            ImGui::InputTextWithHint("##force_peer", "ip:port", g_app.force_peer, sizeof(g_app.force_peer));
            ImGui::InputText("Identity file (aether.toml)", g_app.config_path, sizeof(g_app.config_path));
            ImGui::TextDisabled("UI settings: FCAE_VPN.cfg (next to app). Identity: Cloudflare device certs.");
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Sysprofile (performance tuning)");
            const char* sysprofiles[] = { "Auto", "Low", "Medium", "High" };
            ImGui::Combo("Sysprofile", &g_app.sys_profile, sysprofiles, 4);

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Backends in this build");
            // Queried from the core rather than hardcoded here, so a build
            // without psiphon-live says so instead of the UI quietly implying
            // the backend works.
            {
                uint32_t n = fcae_backend_count();
                for (uint32_t i = 0; i < n; ++i) {
                    FcaeBackendInfo bi;
                    memset(&bi, 0, sizeof(bi));
                    bi.struct_size = (uint32_t)sizeof(bi);
                    bi.abi_version = FCAE_ABI_VERSION;
                    if (fcae_backend_info(i, &bi) != FCAE_OK) continue;

                    if (bi.available) {
                        ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.45f, 1.0f),
                                           "  %s - ready", bi.display_name);
                    } else {
                        ImGui::TextColored(ImVec4(0.70f, 0.70f, 0.75f, 1.0f),
                                           "  %s - unavailable", bi.display_name);
                        if (bi.unavailable_reason[0] && ImGui::IsItemHovered())
                            ImGui::SetTooltip("%s", bi.unavailable_reason);
                    }
                }
            }

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Engine log level");
            // Verbosity of the aether engine itself, not of this UI's log
            // pane -- the FFI always reports to the host at info.
            const char* engine_logs[] = {
                "Off", "Error", "Warn", "Info", "Debug", "Trace",
            };
            ImGui::Combo("Engine log", &g_app.engine_log, engine_logs, 6);

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Psiphon");
            ImGui::TextDisabled("Config is built automatically. Select a target egress region;");
            ImGui::TextDisabled("the list is populated after Psiphon reports available regions.");

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
            ImGui::InputInt("Psiphon SOCKS port", &g_app.psiphon_socks_port);
            ImGui::InputInt("Psiphon HTTP port", &g_app.psiphon_http_port);
            ImGui::TextDisabled("0 restores the built-in value (fixed, never auto-picked).");

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Egress");
            // Tor modes are an Aether-engine hop. Psiphon is a backend.
            // Index 3 = Psiphon (chained behind the engine's SOCKS).
            static const char* kEgressModes[4] = {
                "Off",
                "Tor through the tunnel",
                "Tunnel through Tor (MASQUE only)",
                "Psiphon through the tunnel",
            };
            // No graying, no locking, no relabeling: all four entries are
            // always selectable. An entry that does not apply to the current
            // protocol is simply ignored — tor_mode is normalized at use
            // time (ui_render.h) — and the pick is never touched, so
            // switching protocols restores it verbatim. Same as Android.
            const bool proto_tor = (g_app.protocol == 4);
            if (g_app.tor_mode < 0 || g_app.tor_mode > 3) g_app.tor_mode = 0;
            ImGui::Combo("Egress", &g_app.tor_mode, kEgressModes, 4);
            if (g_app.backend == 1)
                ImGui::TextDisabled("Psiphon is the transport; egress applies to Aether sessions only.");
            else if (proto_tor && g_app.tor_mode == 3)
                ImGui::TextDisabled("Psiphon chains through the Tor-only SOCKS (UpstreamProxyURL): Tor first, then Psiphon exits.");
            else if (proto_tor)
                ImGui::TextDisabled("Tor-only engine. Egress can chain Psiphon through it.");
            // In TUN mode the routing to the right port happens internally,
            // but in proxy mode the user dials the ports by hand -- tell
            // them which one actually carries tor traffic, or they will use
            // the tunnel's plain port and wonder why "tor" did nothing.
            if (g_app.mode == 0) {
                if (g_app.backend == 1)
                    ImGui::TextDisabled(
                        "Psiphon connects independently.");
                else if (g_app.protocol != 4 && g_app.tor_mode == 3)
                    ImGui::TextDisabled(
                        "Aether connects first; Psiphon dials through Aether SOCKS.");
                else if (g_app.tor_mode == 1)
                    ImGui::TextDisabled(
                        "Proxy mode: point SOCKS clients at the Tor SOCKS port below; "
                        "the tunnel's own SOCKS/HTTP ports stay plain (un-tor'ed).");
                else if (g_app.tor_mode == 2)
                    ImGui::TextDisabled(
                        "Proxy mode: use the tunnel's SOCKS/HTTP ports as usual; "
                        "tor is the carrier underneath them.");
                else if (g_app.protocol == 4)
                    ImGui::TextDisabled(
                        "Proxy mode: dial the Tor SOCKS port below; Tor-only has no WARP tunnel.");
            }
            // All Tor knobs stay editable in every combo; the engine
            // ignores them when no Tor is in play (to_config normalises),
            // same ignore-not-gray policy as the egress combo above.
            ImGui::Checkbox("Tor HTTP proxy", &g_app.tor_http_enabled);
            ImGui::InputInt("Tor HTTP port", &g_app.tor_http_port);
            if (g_app.tor_http_enabled && g_app.tor_http_port == 0) g_app.tor_http_port = 1822;
            ImGui::InputInt("Tor SOCKS port", &g_app.tor_socks_port);
            const char* tor_bridges[] = { "No bridges", "obfs4", "snowflake", "Custom lines" };
            ImGui::Combo("Bridges", &g_app.tor_bridges, tor_bridges, 4);
            // Writable even with "No bridges": pasted lines override the
            // built-in set once a bridge family is picked; empty = "auto".
            ImGui::InputTextMultiline("##tor_bridge_lines", g_app.tor_bridge_lines,
                                      sizeof(g_app.tor_bridge_lines), ImVec2(0, 60));
            if (g_app.tor_mode == 2 && (g_app.protocol == 1 || g_app.protocol == 2))
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f),
                                   "Tor is TCP-only: pick MASQUE for this mode.");
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Zero Trust")) {
            ImGui::BeginChild("##zt_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
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
            ImGui::BeginChild("##routes_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Routing Rules File");
            ImGui::InputTextWithHint("##routes_file", "path/to/routes.txt", g_app.routes_file, sizeof(g_app.routes_file));
            ImGui::TextDisabled("Format: [block] / [direct] sections with domain, IP, CIDR, port rules.");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("Inline Routing Rules (comma-separated)");
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
            ImGui::BeginChild("##obf_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
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
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Scanner")) {
            ImGui::BeginChild("##scan_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Scan Mode");
            const char* modes[] = { "Turbo", "Balanced", "Thorough", "Verified", "Ironclad" };
            if (g_app.scan_mode > 4) g_app.scan_mode = 1;
            ImGui::Combo("Mode", &g_app.scan_mode, modes, 5);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("IP Version");
            ImGui::RadioButton("IPv4",       &g_app.ip_version, 4);
            ImGui::SameLine();
            ImGui::RadioButton("IPv6",       &g_app.ip_version, 6);
            ImGui::SameLine();
            ImGui::RadioButton("Dual-Stack", &g_app.ip_version, 10);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("MASQUE SNI");
            ImGui::InputText("##sni", g_app.sni, sizeof(g_app.sni));
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        s_log_scroll_pending = false;
        if (ImGui::BeginTabItem("Logs")) {
            static bool follow_tail = true;
            static bool manual_scroll_last_frame = false;
            static uint64_t rendered_revision = 0;
            ImGui::Checkbox("Logging", &g_app.logging_enabled);
            ImGui::SameLine(0, 12);
            if (ImGui::Checkbox("Auto-scroll", &g_app.auto_scroll))
                follow_tail = g_app.auto_scroll;
            ImGui::SameLine(0, 12);
            ImGui::Checkbox("Auto update check", &g_app.auto_update_check);
            ImGui::SameLine(0, 20);
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
            ImGui::BeginChild("##log", ImVec2(0, -log_footer_h), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_AlwaysVerticalScrollbar);

            // Take a thread-safe snapshot of the logs for rendering.
            // This avoids a data race with the FFI callback thread which
            // calls add_log() concurrently.
            uint64_t revision = 0;
            auto logs_snapshot = g_app.copy_logs(revision);

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

    ImGui::EndChild(); // ##tabs_host

    ImGui::PopStyleVar(2);
    ImGui::End();
}
