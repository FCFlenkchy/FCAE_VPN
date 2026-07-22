#pragma once

#include <cstdint>
#include <cstring>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>

#include "imgui.h"

extern "C" {
#include "../include/aether_ffi.h"
}

struct AppState {
    std::atomic<bool> running{true};
    std::atomic<int>  ffi_state{AETHER_STATE_DISCONNECTED};
    std::atomic<bool> ffi_connected{false};
    std::atomic<bool> start_busy{false};

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
    // Post-scan ironclad validation
    bool ironclad_validate = false;
    // Tunnel health
    int health_interval_secs = 20;
    int health_max_fails     = 2;
    int health_timeout_secs  = 5;
    int live_validate_secs   = 20;

    AetherTelemetry telem = {};
    double last_telem_t = 0.0;

    std::vector<std::pair<int, std::string>> logs;
    int  max_logs    = 200;
    bool auto_scroll = true;
    bool logging_enabled = true;
    char save_status[128] = {};
    char copy_status[64] = {};

    void add_log(int level, const char* msg) {
        if (!msg) return;
        std::string s(msg);
        if (s.size() > 256) s.resize(256);
        logs.emplace_back(level, std::move(s));
        if ((int)logs.size() > max_logs) {
            const int drop = (int)logs.size() - max_logs;
            logs.erase(logs.begin(), logs.begin() + drop);
        }
    }

    std::string logs_as_text() const {
        std::string out;
        out.reserve(logs.size() * 64);
        for (const auto& e : logs) {
            out += e.second;
            out.push_back('\n');
        }
        return out;
    }

    AetherConfig to_config() const {
        AetherConfig c = {};
        c.protocol         = protocol;
        c.mode             = (AetherMode)mode;
        c.lan_sharing      = lan_sharing;
        c.scan_mode        = scan_mode;
        c.ip_version       = ip_version;
        c.quick_reconnect  = quick_reconnect;
        c.noize_profile    = noize_profile;
        c.fragment_enabled = fragment_enabled;
        c.frag_min_size    = (uint32_t)frag_min_size;
        c.frag_max_size    = (uint32_t)frag_max_size;
        c.frag_min_delay   = (uint32_t)frag_min_delay;
        c.frag_max_delay   = (uint32_t)frag_max_delay;
        c.socks_port       = socks_enabled ? socks_port : 0;
        c.http_port        = http_enabled ? http_port : 0;
        c.force_peer       = force_peer[0] ? force_peer : nullptr;
        c.config_path      = config_path;
        c.h2_enabled       = h2_enabled;
        c.ech_enabled      = ech_enabled;
        c.dns_server       = nullptr;
        c.dns_mode         = 0;
        c.doh_url          = nullptr;
        c.dns_ip_prefer    = 0;
        c.tls_groups       = nullptr;
        c.udp_buf_kb       = 0;
        c.sni              = sni[0] ? sni : nullptr;
        c.ironclad_validate     = ironclad_validate;
        c.health_interval_secs  = (uint32_t)(health_interval_secs > 0 ? health_interval_secs : 0);
        c.health_max_fails      = (uint32_t)(health_max_fails > 0 ? health_max_fails : 0);
        c.health_timeout_secs   = (uint32_t)(health_timeout_secs > 0 ? health_timeout_secs : 0);
        c.live_validate_secs    = (uint32_t)(live_validate_secs > 0 ? live_validate_secs : 0);
        return c;
    }
};

static AppState g_app;

void ui_init();
void ui_frame();
void ui_shutdown();
void render_ui();
void log_callback(int level, const char* message, void* user_data);
