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

// ── Ring-buffer for throughput plots ──────────────────────────────────────
static constexpr int PLOT_HISTORY = 256;

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

// ── Global application state ─────────────────────────────────────────────
struct AppState {
    std::atomic<bool> running{true};
    std::atomic<int>  ffi_state{AETHER_STATE_DISCONNECTED};
    std::atomic<bool> ffi_connected{false};

    // Config mirror
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

    // Telemetry
    AetherTelemetry telem = {};
    TelemetryRing   ring  = {};

    // Logs
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

static void log_callback(int level, const char* message, void* user_data) {
    (void)user_data;
    g_app.add_log(level, message);
}

// ── Auto-scaling human-readable byte rate ────────────────────────────────
static void fmt_rate(char* buf, size_t len, double bytes_per_sec) {
    if (bytes_per_sec < 0.0) bytes_per_sec = 0.0;
    if (bytes_per_sec >= 1073741824.0)
        snprintf(buf, len, "%.2f GB/s", bytes_per_sec / 1073741824.0);
    else if (bytes_per_sec >= 1048576.0)
        snprintf(buf, len, "%.2f MB/s", bytes_per_sec / 1048576.0);
    else if (bytes_per_sec >= 1024.0)
        snprintf(buf, len, "%.2f KB/s", bytes_per_sec / 1024.0);
    else
        snprintf(buf, len, "%.0f B/s", bytes_per_sec);
}

static void fmt_total(char* buf, size_t len, uint64_t bytes) {
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.2f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.2f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.2f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%llu B", (unsigned long long)bytes);
}

// ── Status helpers ───────────────────────────────────────────────────────
static ImVec4 state_color(AetherState s) {
    switch (s) {
        case AETHER_STATE_DISCONNECTED: return ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
        case AETHER_STATE_PROVISIONING:
        case AETHER_STATE_SCANNING:
        case AETHER_STATE_CONNECTING:   return ImVec4(0.30f, 0.60f, 1.00f, 1.0f);
        case AETHER_STATE_CONNECTED:    return ImVec4(0.20f, 0.90f, 0.35f, 1.0f);
        case AETHER_STATE_ERROR:        return ImVec4(1.00f, 0.30f, 0.30f, 1.0f);
    }
    return ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
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

// ── Animated spinner ─────────────────────────────────────────────────────
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

// ══════════════════════════════════════════════════════════════════════════
//  MAIN UI RENDER
// ══════════════════════════════════════════════════════════════════════════
static void render_ui() {
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 16));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar);

    // ── Pull telemetry ───────────────────────────────────────────────────
    AetherTelemetry telem = {};
    aether_get_telemetry(&telem);
    g_app.telem = telem;
    g_app.ring.push((float)telem.rx_bytes_sec, (float)telem.tx_bytes_sec);
    g_app.ffi_state.store(telem.state);
    g_app.ffi_connected.store(telem.state == AETHER_STATE_CONNECTED);

    AetherState cur = (AetherState)telem.state;
    bool connected  = (cur == AETHER_STATE_CONNECTED);
    bool busy       = (cur == AETHER_STATE_PROVISIONING || cur == AETHER_STATE_SCANNING || cur == AETHER_STATE_CONNECTING);

    // ══════════════════════════════════════════════════════════════════════
    //  1. STATUS BAR + CONNECT BUTTON
    // ══════════════════════════════════════════════════════════════════════
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 10));

        // Status pill
        ImVec4 sc = state_color(cur);
        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        ImGui::Text("FCAE VPN");
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 10);

        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 0.75f, 0.80f, 1.0f));
        ImGui::Text("|");
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 10);

        ImGui::PushStyleColor(ImGuiCol_Text, sc);
        ImGui::Text("%s", state_label(cur));
        ImGui::PopStyleColor();

        if (busy) {
            ImGui::SameLine(0, 8);
            draw_spinner(7.0f, 14, 7.0f);
        }

        // Connect / Disconnect button (right-aligned)
        ImGui::SameLine(ImGui::GetWindowWidth() - 230);
        ImVec4 btn_on  = ImVec4(0.12f, 0.55f, 0.18f, 1.0f);
        ImVec4 btn_off = ImVec4(0.70f, 0.18f, 0.18f, 1.0f);
        ImVec4 btn     = connected ? btn_off : btn_on;
        ImVec4 btn_h   = ImVec4(btn.x + 0.08f, btn.y + 0.08f, btn.z + 0.08f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, btn);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, btn_h);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(btn.x - 0.05f, btn.y - 0.05f, btn.z - 0.05f, 1.0f));

        if (ImGui::Button(connected ? "  DISCONNECT  " : "  CONNECT  ", ImVec2(200, 34))) {
            if (connected || busy) {
                aether_stop();
                g_app.ffi_state.store(AETHER_STATE_DISCONNECTED);
            } else {
                AetherConfig cfg = g_app.to_config();
                aether_start(&cfg);
            }
        }
        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar(2);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ══════════════════════════════════════════════════════════════════════
    //  2. THROUGHPUT: two columns, auto-scaling labels
    // ══════════════════════════════════════════════════════════════════════
    {
        char rate_buf[32];

        float col_w = (ImGui::GetContentRegionAvail().x - 12.0f) * 0.5f;
        ImGui::BeginChild("##dl_col", ImVec2(col_w, 0), ImGuiChildFlags_Borders);
        ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "Download");
        fmt_rate(rate_buf, sizeof(rate_buf), (double)telem.rx_bytes_sec);
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(rate_buf).x);
        ImGui::TextColored(ImVec4(0.30f, 0.80f, 1.00f, 1.0f), "%s", rate_buf);
        ImGui::PlotLines("##rx", g_app.ring.rx_ptr(), PLOT_HISTORY, 0, nullptr, 0.0f, FLT_MAX,
                         ImVec2(0, 70));
        ImGui::EndChild();

        ImGui::SameLine(0, 12);

        ImGui::BeginChild("##ul_col", ImVec2(0, 0), ImGuiChildFlags_Borders);
        ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "Upload");
        fmt_rate(rate_buf, sizeof(rate_buf), (double)telem.tx_bytes_sec);
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(rate_buf).x);
        ImGui::TextColored(ImVec4(1.00f, 0.55f, 0.20f, 1.0f), "%s", rate_buf);
        ImGui::PlotLines("##tx", g_app.ring.tx_ptr(), PLOT_HISTORY, 0, nullptr, 0.0f, FLT_MAX,
                         ImVec2(0, 70));
        ImGui::EndChild();
    }

    ImGui::Spacing();

    // ── Info row ─────────────────────────────────────────────────────────
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.70f, 0.70f, 0.75f, 1.0f));
        const char* mode_str = g_app.mode == 0 ? "Proxy" : "TUN";
        ImGui::Text("Mode: %s", mode_str);
        ImGui::SameLine(0, 20);
        ImGui::Text("Peer: %s", telem.connected_peer[0] ? telem.connected_peer : "-");
        ImGui::SameLine(0, 20);
        ImGui::Text("RTT: %u ms", telem.rtt_ms);

        ImGui::Text("RX Total: ");
        char tbuf[32];
        fmt_total(tbuf, sizeof(tbuf), telem.total_rx);
        ImGui::SameLine();
        ImGui::Text("%s", tbuf);
        ImGui::SameLine(0, 24);
        ImGui::Text("TX Total: ");
        fmt_total(tbuf, sizeof(tbuf), telem.total_tx);
        ImGui::SameLine();
        ImGui::Text("%s", tbuf);
        ImGui::PopStyleColor();
    }

    // ── Address callout ──────────────────────────────────────────────────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.10f, 0.16f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.85f, 0.45f, 1.0f));
        ImGui::BeginChild("##addr", ImVec2(0, 30), ImGuiChildFlags_Borders);

        if (connected) {
            const char* lip = telem.lan_ip[0] ? telem.lan_ip : "127.0.0.1";
            if (g_app.mode == 0) {
                if (g_app.lan_sharing)
                    ImGui::Text("  LAN Gateways:  SOCKS5 %s:%u  |  HTTP %s:%u",
                                lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::Text("  Local:  SOCKS5 127.0.0.1:%u  |  HTTP 127.0.0.1:%u",
                                g_app.socks_port, g_app.http_port);
            } else {
                if (g_app.lan_sharing)
                    ImGui::Text("  TUN Active  |  LAN Gateways:  SOCKS5 %s:%u  |  HTTP %s:%u",
                                lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::Text("  TUN Active (System VPN)  |  SOCKS5 127.0.0.1:%u", g_app.socks_port);
            }
        } else {
            ImGui::Text("  No active tunnel");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ══════════════════════════════════════════════════════════════════════
    //  3. CONFIGURATION TABS
    // ══════════════════════════════════════════════════════════════════════
    if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {

        // ── Tab 1: Protocol ──────────────────────────────────────────────
        if (ImGui::BeginTabItem("Protocol")) {
            ImGui::Spacing();
            ImGui::Text("Transport Protocol");
            ImGui::RadioButton("MASQUE (HTTP/3 QUIC)", &g_app.protocol, 0);
            ImGui::RadioButton("WireGuard (Classic)",   &g_app.protocol, 1);
            ImGui::RadioButton("WARP-in-WARP (Gool)",   &g_app.protocol, 2);
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("Mode");
            ImGui::RadioButton("Proxy (Local Forwarding)", &g_app.mode, 0);
            ImGui::RadioButton("TUN (System VPN)",         &g_app.mode, 1);
            ImGui::Spacing();
            ImGui::Checkbox("LAN Sharing (Allow Local Network)", &g_app.lan_sharing);
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("Options");
            ImGui::Checkbox("HTTP/2 Fallback (--h2)", &g_app.h2_enabled);
            ImGui::Checkbox("Encrypted ClientHello (ECH)", &g_app.ech_enabled);
            ImGui::Checkbox("Quick Reconnect", &g_app.quick_reconnect);
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("Ports");
            ImGui::PushItemWidth(100);
            ImGui::InputScalar("SOCKS5", ImGuiDataType_U16, &g_app.socks_port);
            ImGui::SameLine(0, 20);
            ImGui::InputScalar("HTTP",   ImGuiDataType_U16, &g_app.http_port);
            ImGui::PopItemWidth();
            ImGui::Spacing();
            ImGui::InputText("Force Peer", g_app.force_peer, sizeof(g_app.force_peer));
            ImGui::InputText("Config Path", g_app.config_path, sizeof(g_app.config_path));
            ImGui::EndTabItem();
        }

        // ── Tab 2: Obfuscation ──────────────────────────────────────────
        if (ImGui::BeginTabItem("Obfuscation")) {
            ImGui::Spacing();
            ImGui::Text("Noize Profile (--noize)");
            const char* profiles[] = { "off", "firewall", "balanced", "gfw" };
            int idx = 0;
            for (int i = 0; i < 4; i++)
                if (strcmp(g_app.noize_profile, profiles[i]) == 0) { idx = i; break; }
            if (ImGui::Combo("Profile", &idx, profiles, 4))
                strncpy(g_app.noize_profile, profiles[idx], sizeof(g_app.noize_profile) - 1);
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("TLS ClientHello Fragmentation");
            ImGui::Checkbox("Enable Fragmentation (--fragment)", &g_app.fragment_enabled);
            if (g_app.fragment_enabled) {
                ImGui::PushItemWidth(180);
                ImGui::SliderInt("Chunk Min (B)", &g_app.frag_min_size, 8, 64);
                ImGui::SliderInt("Chunk Max (B)", &g_app.frag_max_size, 16, 128);
                ImGui::SliderInt("Delay Min (ms)", &g_app.frag_min_delay, 0, 20);
                ImGui::SliderInt("Delay Max (ms)", &g_app.frag_max_delay, 1, 50);
                ImGui::PopItemWidth();
            }
            ImGui::EndTabItem();
        }

        // ── Tab 3: Scanner ──────────────────────────────────────────────
        if (ImGui::BeginTabItem("Scanner")) {
            ImGui::Spacing();
            ImGui::Text("Scan Mode (--scan)");
            const char* modes[] = { "Turbo", "Balanced", "Thorough", "Stealth", "Ironclad" };
            ImGui::Combo("Mode", &g_app.scan_mode, modes, 5);
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("IP Version");
            ImGui::RadioButton("IPv4",       &g_app.ip_version, 4);
            ImGui::RadioButton("IPv6",       &g_app.ip_version, 6);
            ImGui::RadioButton("Dual-Stack", &g_app.ip_version, 10);
            ImGui::EndTabItem();
        }

        // ── Tab 4: Logs ─────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Logs")) {
            ImGui::Checkbox("Auto-scroll", &g_app.auto_scroll);
            ImGui::SameLine(0, 20);
            if (ImGui::Button("Clear")) g_app.logs.clear();
            ImGui::Spacing();
            ImGui::BeginChild("##log", ImVec2(0, 0), ImGuiChildFlags_Borders);
            for (auto& [lvl, msg] : g_app.logs) {
                ImVec4 c;
                switch (lvl) {
                    case 1:  c = ImVec4(1.0f, 0.35f, 0.35f, 1.0f); break;
                    case 2:  c = ImVec4(1.0f, 0.80f, 0.25f, 1.0f); break;
                    case 3:  c = ImVec4(0.40f, 0.75f, 1.00f, 1.0f); break;
                    default: c = ImVec4(0.75f, 0.75f, 0.78f, 1.0f); break;
                }
                ImGui::PushStyleColor(ImGuiCol_Text, c);
                ImGui::TextUnformatted(msg.c_str());
                ImGui::PopStyleColor();
            }
            if (g_app.auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::PopStyleVar(2); // WindowPadding, WindowRounding
    ImGui::End();
}
