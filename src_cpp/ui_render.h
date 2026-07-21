#pragma once

#include <cstdint>
#include <cstring>
#include <cfloat>
#include <cmath>
#include <vector>
#include <string>
#include <atomic>

#include "imgui.h"

extern "C" {
#include "../include/aether_ffi.h"
}

// ── Ring-buffer for throughput plots ──────────────────────────────────────
static constexpr int PLOT_HISTORY = 200;

struct TelemetryRing {
    float rx[PLOT_HISTORY] = {};
    float tx[PLOT_HISTORY] = {};
    int   idx = 0;

    void push(float r, float t) {
        rx[idx] = r;
        tx[idx] = t;
        idx = (idx + 1) % PLOT_HISTORY;
    }

    const float* rx_ptr() const { return rx + idx; }
    const float* tx_ptr() const { return tx + idx; }
};

// ── Global application state (thread-safe) ───────────────────────────────
struct AppState {
    std::atomic<bool>  running{true};
    std::atomic<int>   ffi_state{AETHER_STATE_DISCONNECTED};
    std::atomic<bool>  ffi_connected{false};

    // Config mirror for UI ↔ FFI bridge
    int   protocol       = 0;   // 0=MASQUE, 1=WG, 2=Gool
    int   mode           = 0;   // 0=Proxy, 1=TUN
    bool  lan_sharing    = false;
    int   scan_mode      = 1;   // Balanced
    int   ip_version     = 4;
    bool  quick_reconnect = true;
    char  noize_profile[32] = "balanced";
    bool  fragment_enabled = false;
    int   frag_min_size  = 16;
    int   frag_max_size  = 32;
    int   frag_min_delay = 2;
    int   frag_max_delay = 10;
    uint16_t socks_port  = 1819;
    uint16_t http_port   = 1820;
    char  force_peer[128] = {};
    char  config_path[256] = "aether.toml";

    // H2 fallback toggle
    bool  h2_enabled     = false;
    bool  ech_enabled    = false;

    // Telemetry
    AetherTelemetry telem = {};
    TelemetryRing   ring  = {};

    // Log ring-buffer
    std::vector<std::pair<int, std::string>> logs;
    int  max_logs = 500;
    bool auto_scroll = true;

    void add_log(int level, const char* msg) {
        logs.emplace_back(level, std::string(msg));
        if ((int)logs.size() > max_logs) {
            logs.erase(logs.begin());
        }
    }

    AetherConfig to_config() const {
        AetherConfig c = {};
        c.protocol        = protocol;
        c.mode            = (AetherMode)mode;
        c.lan_sharing     = lan_sharing;
        c.scan_mode       = scan_mode;
        c.ip_version      = ip_version;
        c.quick_reconnect = quick_reconnect;
        c.noize_profile   = noize_profile;
        c.fragment_enabled = fragment_enabled;
        c.frag_min_size   = (uint32_t)frag_min_size;
        c.frag_max_size   = (uint32_t)frag_max_size;
        c.frag_min_delay  = (uint32_t)frag_min_delay;
        c.frag_max_delay  = (uint32_t)frag_max_delay;
        c.socks_port      = socks_port;
        c.http_port       = http_port;
        c.force_peer      = force_peer[0] ? force_peer : nullptr;
        c.config_path     = config_path;
        return c;
    }
};

// ── Global singleton ─────────────────────────────────────────────────────
static AppState g_app;

// ── Log callback for FFI ─────────────────────────────────────────────────
static void log_callback(int level, const char* message, void* user_data) {
    (void)user_data;
    g_app.add_log(level, message);
}

// ── Helper: status colour ────────────────────────────────────────────────
static void status_color(AetherState s) {
    switch (s) {
        case AETHER_STATE_DISCONNECTED: ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f)); break;
        case AETHER_STATE_PROVISIONING:
        case AETHER_STATE_SCANNING:
        case AETHER_STATE_CONNECTING:   ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.6f, 1.0f, 1.0f)); break;
        case AETHER_STATE_CONNECTED:    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.9f, 0.3f, 1.0f)); break;
        case AETHER_STATE_ERROR:        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f)); break;
    }
}

static const char* state_label(AetherState s) {
    switch (s) {
        case AETHER_STATE_DISCONNECTED: return "DISCONNECTED";
        case AETHER_STATE_PROVISIONING: return "PROVISIONING";
        case AETHER_STATE_SCANNING:     return "SCANNING";
        case AETHER_STATE_CONNECTING:   return "CONNECTING";
        case AETHER_STATE_CONNECTED:    return "CONNECTED";
        case AETHER_STATE_ERROR:        return "ERROR";
    }
    return "UNKNOWN";
}

// ── Animated spinner helper ──────────────────────────────────────────────
static void draw_spinner(float radius, int num_segments, float speed) {
    float time = (float)ImGui::GetTime() * speed;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 center(p.x + radius, p.y + radius);
    for (int i = 0; i < num_segments; i++) {
        float a = ((float)i / (float)num_segments) * 6.2832f + time;
        float r = radius * 0.6f + radius * 0.4f * ((float)i / (float)num_segments);
        float fade = (float)i / (float)num_segments;
        ImVec4 col(0.3f + fade * 0.4f, 0.6f + fade * 0.2f, 1.0f, 0.3f + fade * 0.7f);
        dl->AddCircleFilled(ImVec2(center.x + cosf(a) * r, center.y + sinf(a) * r), 2.0f, ImGui::ColorConvertFloat4ToU32(col));
    }
}

// ── Format bytes/sec ─────────────────────────────────────────────────────
static std::string fmt_bytes(uint64_t b) {
    if (b > 1073741824ULL) return std::to_string(b / 1073741824ULL) + " GB/s";
    if (b > 1048576ULL)    return std::to_string(b / 1048576ULL) + " MB/s";
    if (b > 1024ULL)       return std::to_string(b / 1024ULL) + " KB/s";
    return std::to_string(b) + " B/s";
}

// ══════════════════════════════════════════════════════════════════════════
//  MAIN UI RENDER FUNCTION
// ══════════════════════════════════════════════════════════════════════════
static void render_ui() {
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
    ImGui::Begin("##FCAE_VPN", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // ── Pull telemetry ────────────────────────────────────────────────────
    AetherTelemetry telem = {};
    aether_get_telemetry(&telem);
    g_app.telem = telem;
    g_app.ring.push((float)telem.rx_bytes_sec, (float)telem.tx_bytes_sec);
    g_app.ffi_state.store(telem.state);
    g_app.ffi_connected.store(telem.state == AETHER_STATE_CONNECTED);

    AetherState cur_state = (AetherState)telem.state;

    // ══════════════════════════════════════════════════════════════════════
    //  1. TOP STATUS BAR & ACTION BANNER
    // ══════════════════════════════════════════════════════════════════════
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16, 12));

        status_color(cur_state);
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]); // Default bold if available
        ImGui::Text("  FCAE VPN  |  %s", state_label(cur_state));
        ImGui::PopFont();
        ImGui::PopStyleColor();

        if (cur_state == AETHER_STATE_PROVISIONING ||
            cur_state == AETHER_STATE_SCANNING ||
            cur_state == AETHER_STATE_CONNECTING) {
            ImGui::SameLine(0, 12);
            draw_spinner(8.0f, 16, 6.0f);
        }

        // Main toggle button
        ImGui::SameLine(ImGui::GetWindowWidth() - 220);
        bool connected = (cur_state == AETHER_STATE_CONNECTED);
        ImVec4 btn_col = connected
            ? ImVec4(0.8f, 0.2f, 0.2f, 1.0f)
            : ImVec4(0.15f, 0.55f, 0.15f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn_col);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(btn_col.x + 0.1f, btn_col.y + 0.1f, btn_col.z + 0.1f, 1.0f));

        char btn_label[64];
        snprintf(btn_label, sizeof(btn_label), "%s TUNNEL",
                 connected ? "DISCONNECT" : "CONNECT");
        if (ImGui::Button(btn_label, ImVec2(200, 36))) {
            if (connected) {
                aether_stop();
                g_app.ffi_state.store(AETHER_STATE_DISCONNECTED);
            } else {
                AetherConfig cfg = g_app.to_config();
                aether_start(&cfg);
            }
        }
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);
    }

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    //  2. REAL-TIME TELEMETRY PANEL
    // ══════════════════════════════════════════════════════════════════════
    {
        ImGui::Columns(2, nullptr, false);
        ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.5f);

        // Download graph
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "Download (RX)");
        ImGui::SameLine(ImGui::GetColumnWidth() - 120);
        ImGui::Text("%s", fmt_bytes(telem.rx_bytes_sec).c_str());
        char rx_label[64];
        snprintf(rx_label, sizeof(rx_label), "##rxplot");
        ImGui::PlotLines(rx_label, g_app.ring.rx_ptr(), PLOT_HISTORY, 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, 80));

        ImGui::NextColumn();

        // Upload graph
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "Upload (TX)");
        ImGui::SameLine(ImGui::GetColumnWidth() - 120);
        ImGui::Text("%s", fmt_bytes(telem.tx_bytes_sec).c_str());
        char tx_label[64];
        snprintf(tx_label, sizeof(tx_label), "##txplot");
        ImGui::PlotLines(tx_label, g_app.ring.tx_ptr(), PLOT_HISTORY, 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, 80));

        ImGui::Columns(1);

        ImGui::Spacing();

        // Mode & proxy display
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.85f, 0.85f, 1.0f));
        ImGui::Text("Mode: %s", g_app.mode == 0 ? "Proxy (Local SOCKS5+HTTP)" : "TUN (System VPN)");
        ImGui::SameLine(0, 24);
        ImGui::Text("Peer: %s", telem.connected_peer[0] ? telem.connected_peer : "none");
        ImGui::SameLine(0, 24);
        ImGui::Text("RTT: %u ms", telem.rtt_ms);
        ImGui::PopStyleColor();

        // Address callout box
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.12f, 0.18f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.9f, 0.4f, 1.0f));
        ImGui::BeginChild("##addr_box", ImVec2(0, 36), ImGuiChildFlags_Borders);
        if (telem.state == AETHER_STATE_CONNECTED) {
            if (g_app.mode == 0) {
                if (g_app.lan_sharing) {
                    ImGui::Text("  LAN SOCKS5: %s:%u  |  LAN HTTP: %s:%u",
                        telem.lan_ip[0] ? telem.lan_ip : "0.0.0.0", g_app.socks_port,
                        telem.lan_ip[0] ? telem.lan_ip : "0.0.0.0", g_app.http_port);
                } else {
                    ImGui::Text("  Local SOCKS5: 127.0.0.1:%u  |  Local HTTP: 127.0.0.1:%u",
                        g_app.socks_port, g_app.http_port);
                }
            } else {
                if (g_app.lan_sharing) {
                    ImGui::Text("  TUN: Active  |  LAN Gateways -> SOCKS5: %s:%u  |  HTTP: %s:%u",
                        telem.lan_ip[0] ? telem.lan_ip : "0.0.0.0", g_app.socks_port,
                        telem.lan_ip[0] ? telem.lan_ip : "0.0.0.0", g_app.http_port);
                } else {
                    ImGui::Text("  TUN: System VPN Active (All Traffic Tunneled)  |  SOCKS5: 127.0.0.1:%u", g_app.socks_port);
                }
            }
        } else {
            ImGui::Text("  No active tunnel");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();

        // Total counters
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.0f),
            "Total RX: %llu  |  Total TX: %llu",
            (unsigned long long)telem.total_rx, (unsigned long long)telem.total_tx);
    }

    ImGui::Separator();

    // ══════════════════════════════════════════════════════════════════════
    //  3. CONFIGURATION TABS
    // ══════════════════════════════════════════════════════════════════════
    if (ImGui::BeginTabBar("##ConfigTabs")) {

        // ── Tab 1: Protocol & Transports ──────────────────────────────────
        if (ImGui::BeginTabItem("Protocol & Transports")) {
            ImGui::Spacing();

            ImGui::Text("Protocol");
            ImGui::RadioButton("MASQUE (HTTP/3 QUIC)", &g_app.protocol, 0);
            ImGui::RadioButton("WireGuard (Classic)",   &g_app.protocol, 1);
            ImGui::RadioButton("WARP-in-WARP (Gool)",   &g_app.protocol, 2);
            ImGui::Spacing();

            ImGui::Checkbox("HTTP/2 over TCP Fallback (--h2)", &g_app.h2_enabled);
            if (g_app.h2_enabled) {
                std::env::set_var("AETHER_MASQUE_HTTP2", "1");
            } else {
                std::env::remove_var("AETHER_MASQUE_HTTP2");
            }
            ImGui::Checkbox("Encrypted ClientHello (ECH)", &g_app.ech_enabled);
            if (g_app.ech_enabled) {
                std::env::set_var("AETHER_ECH", "auto");
            } else {
                std::env::remove_var("AETHER_ECH");
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Text("Transport Mode");
            ImGui::RadioButton("Proxy Mode (Local Forwarding)", &g_app.mode, 0);
            ImGui::RadioButton("TUN Mode (System VPN)",         &g_app.mode, 1);
            ImGui::Spacing();

            ImGui::Checkbox("Enable LAN Sharing (Allow Local Network Connection)", &g_app.lan_sharing);

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Text("Ports");
            ImGui::PushItemWidth(120);
            ImGui::InputScalar("SOCKS5 Port", ImGuiDataType_U16, &g_app.socks_port);
            ImGui::InputScalar("HTTP Port",   ImGuiDataType_U16, &g_app.http_port);
            ImGui::PopItemWidth();

            ImGui::Spacing();
            ImGui::InputText("Force Peer (ip:port)", g_app.force_peer, sizeof(g_app.force_peer));
            ImGui::InputText("Config Path", g_app.config_path, sizeof(g_app.config_path));

            ImGui::EndTabItem();
        }

        // ── Tab 2: DPI Evasion & Obfuscation ─────────────────────────────
        if (ImGui::BeginTabItem("DPI Evasion & Obfuscation")) {
            ImGui::Spacing();

            ImGui::Text("--noize Profile");
            const char* noize_profiles[] = { "off", "firewall", "balanced", "gfw" };
            int noize_idx = 0;
            for (int i = 0; i < 4; i++) {
                if (strcmp(g_app.noize_profile, noize_profiles[i]) == 0) { noize_idx = i; break; }
            }
            if (ImGui::Combo("Obfuscation Profile", &noize_idx, noize_profiles, 4)) {
                strncpy(g_app.noize_profile, noize_profiles[noize_idx], sizeof(g_app.noize_profile) - 1);
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Checkbox("Enable TLS ClientHello Fragmentation (--fragment)", &g_app.fragment_enabled);
            if (g_app.fragment_enabled) {
                ImGui::PushItemWidth(200);
                ImGui::SliderInt("Fragment Min Size (B)", &g_app.frag_min_size, 8, 64);
                ImGui::SliderInt("Fragment Max Size (B)", &g_app.frag_max_size, 16, 128);
                ImGui::SliderInt("Fragment Min Delay (ms)", &g_app.frag_min_delay, 0, 20);
                ImGui::SliderInt("Fragment Max Delay (ms)", &g_app.frag_max_delay, 1, 50);
                ImGui::PopItemWidth();
            }

            ImGui::EndTabItem();
        }

        // ── Tab 3: Scanner & Gateways ────────────────────────────────────
        if (ImGui::BeginTabItem("Scanner & Gateways")) {
            ImGui::Spacing();

            ImGui::Text("Scan Mode (--scan)");
            const char* scan_labels[] = { "Turbo", "Balanced", "Thorough", "Stealth", "Ironclad" };
            ImGui::Combo("Scan Mode", &g_app.scan_mode, scan_labels, 5);

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Text("IP Version");
            ImGui::RadioButton("IPv4",         &g_app.ip_version, 4);
            ImGui::RadioButton("IPv6",         &g_app.ip_version, 6);
            ImGui::RadioButton("Dual-Stack",   &g_app.ip_version, 10);

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Checkbox("Quick Reconnect (use cached gateway)", &g_app.quick_reconnect);

            ImGui::EndTabItem();
        }

        // ── Tab 4: Live Terminal Logs ────────────────────────────────────
        if (ImGui::BeginTabItem("Logs")) {
            ImGui::Spacing();
            ImGui::Checkbox("Auto-scroll", &g_app.auto_scroll);

            ImGui::BeginChild("##log_child", ImVec2(0, 0), ImGuiChildFlags_Borders);
            for (auto& [lvl, msg] : g_app.logs) {
                ImVec4 col;
                switch (lvl) {
                    case 1:  col = ImVec4(1.0f, 0.3f, 0.3f, 1.0f); break; // ERROR
                    case 2:  col = ImVec4(1.0f, 0.8f, 0.2f, 1.0f); break; // WARN
                    case 3:  col = ImVec4(0.3f, 0.8f, 1.0f, 1.0f); break; // INFO
                    default: col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f); break; // other
                }
                ImGui::PushStyleColor(ImGuiCol_Text, col);
                ImGui::TextUnformatted(msg.c_str());
                ImGui::PopStyleColor();
            }
            if (g_app.auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                ImGui::SetScrollHereY(1.0f);
            }
            ImGui::EndChild();

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}
