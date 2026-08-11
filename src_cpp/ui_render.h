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

    AetherTelemetry telem = {};
    double last_telem_t = 0.0;

    mutable std::mutex logs_mutex;
    std::vector<std::pair<int, std::string>> logs;
    int  max_logs    = 200;
    bool auto_scroll = true;
    int  prev_log_count = 0;
    bool logging_enabled = true;
    bool auto_update_check = true;
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
        c.sys_profile           = sys_profile;
        c.team_name     = team_name[0] ? team_name : nullptr;
        c.access_token  = access_token[0] ? access_token : nullptr;
        c.access_email  = access_email[0] ? access_email : nullptr;
        c.routes_file   = routes_file[0] ? routes_file : nullptr;
        c.routes_inline = routes_inline[0] ? routes_inline : nullptr;
        return c;
    }
};

static AppState g_app;

void ui_init();
void ui_frame();
void ui_shutdown();
void render_ui();
void log_callback(int level, const char* message, void* user_data);
