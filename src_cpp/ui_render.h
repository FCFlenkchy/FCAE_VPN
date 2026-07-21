#pragma once

#include <cstdint>
#include <cstring>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <vector>
#include <string>
#include <atomic>

#include "imgui.h"

extern "C" {
#include "../include/aether_ffi.h"
}

struct AppState {
    std::atomic<bool> running{true};
    std::atomic<int>  ffi_state{AETHER_STATE_DISCONNECTED};
    std::atomic<bool> ffi_connected{false};

    int  protocol        = 0;
    int  mode            = 0;
    bool lan_sharing     = false;
    int  scan_mode       = 1;
    int  ip_version      = 4;
    bool quick_reconnect = true;
    char noize_profile[32] = "balanced";
    bool fragment_enabled = false;
    int  frag_min_size   = 16;
    int  frag_max_size   = 32;
    int  frag_min_delay  = 2;
    int  frag_max_delay  = 10;
    uint16_t socks_port  = 1819;
    uint16_t http_port   = 1820;
    char force_peer[128] = {};
    char config_path[256] = "aether.toml";
    bool h2_enabled      = false;
    bool ech_enabled     = false;

    AetherTelemetry telem = {};

    std::vector<std::pair<int, std::string>> logs;
    int  max_logs    = 500;
    bool auto_scroll = true;

    void add_log(int level, const char* msg) {
        logs.emplace_back(level, std::string(msg));
        if ((int)logs.size() > max_logs) logs.erase(logs.begin());
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
        c.socks_port       = socks_port;
        c.http_port        = http_port;
        c.force_peer       = force_peer[0] ? force_peer : nullptr;
        c.config_path      = config_path;
        return c;
    }
};

static AppState g_app;

void ui_init();
void ui_frame();
void ui_shutdown();
void render_ui();
void log_callback(int level, const char* message, void* user_data);
