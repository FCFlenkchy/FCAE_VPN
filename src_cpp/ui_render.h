#pragma once

#include <cstdint>
#include <cstring>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>

#include "imgui.h"

extern "C" {
#include "fcae.h"
}

struct AppState {
    std::atomic<bool> running{true};
    std::atomic<int>  ffi_state{FCAE_STATE_DISCONNECTED};
    std::atomic<bool> ffi_connected{false};
    std::atomic<bool> start_busy{false};
    /// Set by the platform layer (resize, DPI change, focus/activate, expose) to
    /// force exactly one repaint even when nothing else changed. It is only
    /// cleared once a frame has really been painted, so the request survives a
    /// minimized/occluded period. Starts true so the first frame always draws.
    std::atomic<bool> redraw_requested{true};

    int  protocol        = 0;
    int  mode            = 0;
    bool lan_sharing     = false;
    int  scan_mode       = 0;
    int  ip_version      = 4;
    bool quick_reconnect = false;
    char noize_profile[32] = "balanced";
    bool fragment_enabled = false;
    int  frag_min_size   = 16;
    int  frag_max_size   = 32;
    int  frag_min_delay  = 2;
    int  frag_max_delay  = 10;
    uint16_t socks_port  = 1819;
    uint16_t http_port   = 1820;
    bool socks_enabled   = true;
    bool http_enabled    = true;
    char force_peer[128] = {};
    // Engine identity file (Cloudflare device certs). Not the UI settings file.
    char config_path[256] = "aether.toml";
    bool h2_enabled      = true;
    bool ech_enabled     = true;

    // MASQUE SNI (empty = default consumer-masque.cloudflareclient.com)
    char sni[128] = {};
    // Zero Trust (Cloudflare Teams)
    char team_name[128] = {};
    char access_token[256] = {};
    char access_client_id[128] = {};
    char access_client_secret[128] = {};
    char access_email[128] = {};
    // Routing rules file
    char routes_file[256] = {};
    // Inline routing rules (comma-separated, takes precedence over file)
    char routes_inline[2048] = {};
    int sys_profile       = 0;   // 0=Auto, 1=Low, 2=Medium, 3=High

    FcaeTelemetry telem = {};
    double last_telem_t = 0.0;

    mutable std::mutex logs_mutex;
    std::vector<std::pair<int, std::string>> logs;
    int  max_logs    = 200;
    bool auto_scroll = true;
    int  prev_log_count = 0;
    bool logging_enabled = true;
    bool auto_update_check = true;
    /// "Pre-releases" toggle (default off): when on, version.json's
    /// `prerelease` block takes part in the update check and the highest of the
    /// two versions is offered; when off only the stable release is considered.
    bool prerelease_updates = false;
    char save_status[128] = {};
    char copy_status[64] = {};

    // Thread-safe: called from Rust FFI callback thread.
    void add_log(int level, const char* msg) {
        if (!msg) return;
        std::string s(msg);
        if (s.size() > 256) s.resize(256);
        std::lock_guard<std::mutex> lock(logs_mutex);
        logs.emplace_back(level, std::move(s));
        if ((int)logs.size() > max_logs) {
            const int drop = (int)logs.size() - max_logs;
            logs.erase(logs.begin(), logs.begin() + drop);
        }
    }

    std::string logs_as_text() const {
        std::lock_guard<std::mutex> lock(logs_mutex);
        std::string out;
        out.reserve(logs.size() * 64);
        for (const auto& e : logs) {
            out += e.second;
            out.push_back('\n');
        }
        return out;
    }

    // Thread-safe copy for UI rendering: returns snapshot and size.
    std::vector<std::pair<int, std::string>> copy_logs() const {
        std::lock_guard<std::mutex> lock(logs_mutex);
        return logs;
    }

    /// Build a session config.
    ///
    /// Always starts from fcae_config_default() so struct_size/abi_version are
    /// stamped correctly and any field the UI does not yet expose gets a sane
    /// default instead of a zero.
    FcaeConfig to_config() const {
        FcaeConfig c;
        fcae_config_default(&c);

        c.backend          = FCAE_BACKEND_AETHER;
        c.protocol         = (FcaeProtocol)protocol;
        c.mode             = (FcaeMode)mode;
        c.scan_mode        = (FcaeScanMode)scan_mode;
        c.ip_version       = (FcaeIpVersion)ip_version;
        c.sys_profile      = (FcaeSysProfile)sys_profile;
        c.lan_sharing      = lan_sharing;
        c.quick_reconnect  = quick_reconnect;
        c.socks_port       = socks_enabled ? socks_port : 0;
        c.http_port        = http_enabled ? http_port : 0;
        c.force_peer       = force_peer[0] ? force_peer : nullptr;
        c.config_path      = config_path;

        c.obfuscation.noize_profile    = noize_profile;
        c.obfuscation.fragment_enabled = fragment_enabled;
        c.obfuscation.frag_min_size    = (uint32_t)frag_min_size;
        c.obfuscation.frag_max_size    = (uint32_t)frag_max_size;
        c.obfuscation.frag_min_delay_ms = (uint32_t)frag_min_delay;
        c.obfuscation.frag_max_delay_ms = (uint32_t)frag_max_delay;
        c.obfuscation.h2_enabled       = h2_enabled;
        c.obfuscation.ech_enabled      = ech_enabled;

        c.dns.sni = sni[0] ? sni : nullptr;

        c.routing.rules_file   = routes_file[0] ? routes_file : nullptr;
        c.routing.rules_inline = routes_inline[0] ? routes_inline : nullptr;

        c.zero_trust.team_name    = team_name[0] ? team_name : nullptr;
        c.zero_trust.access_token = access_token[0] ? access_token : nullptr;
        c.zero_trust.access_email = access_email[0] ? access_email : nullptr;

        return c;
    }
};

extern AppState g_app;

void ui_init();
void ui_frame();
void ui_shutdown();
void render_ui();
void log_callback(FcaeLogLevel level, const char* message, void* user_data);

// ── Idle-friendly rendering ──────────────────────────────────────────────
// The window is repainted only when it has something new to show (engine
// telemetry, logs, transient status text) or while the user is interacting.
// Platform main loops call ui_should_render() before each frame and sleep for
// ui_sleep_ms() instead of redrawing on a timer, so an idle window costs ~0%
// CPU: no periodic full-frame repaint, and no 60 FPS spin when stray window
// messages keep arriving.

/// Should the platform paint a frame now?
/// Polls telemetry when due and returns true if anything changed since the last
/// painted frame, if a redraw was requested, if the UI has its own animation
/// running (connect spinner), or while `interacting` is true.
bool ui_should_render(bool interacting);

/// How long (ms) the platform may sleep before calling ui_should_render()
/// again. Small while something is animating or live, 1000 ms when idle.
unsigned ui_sleep_ms();

/// Request one extra repaint (call from window event handlers).
void ui_request_redraw();

/// Bookkeeping after a frame was actually painted. Called by ui_frame().
void ui_note_frame_drawn();

/// Monotonic clock in seconds, shared by the telemetry poll and the render gate.
double ui_now_seconds();
