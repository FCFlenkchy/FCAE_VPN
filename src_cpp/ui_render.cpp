#include "ui_render.h"
#include <fstream>
#include <sstream>

// ── Config persistence ──────────────────────────────────────────────────

static std::string get_config_path() {
#ifdef ANDROID
    return "/data/data/com.fc.fcaevpn/files/FCAE_VPN.cfg";
#else
    return "FCAE_VPN.cfg";
#endif
}

static void save_config() {
    FILE* f = fopen(get_config_path().c_str(), "w");
    if (!f) { snprintf(g_app.save_status, sizeof(g_app.save_status), "Save failed"); return; }
    fprintf(f, "protocol=%d\n", g_app.protocol);
    fprintf(f, "mode=%d\n", g_app.mode);
    fprintf(f, "lan_sharing=%d\n", g_app.lan_sharing);
    fprintf(f, "scan_mode=%d\n", g_app.scan_mode);
    fprintf(f, "ip_version=%d\n", g_app.ip_version);
    fprintf(f, "quick_reconnect=%d\n", g_app.quick_reconnect);
    fprintf(f, "noize_profile=%s\n", g_app.noize_profile);
    fprintf(f, "fragment_enabled=%d\n", g_app.fragment_enabled);
    fprintf(f, "frag_min_size=%d\n", g_app.frag_min_size);
    fprintf(f, "frag_max_size=%d\n", g_app.frag_max_size);
    fprintf(f, "frag_min_delay=%d\n", g_app.frag_min_delay);
    fprintf(f, "frag_max_delay=%d\n", g_app.frag_max_delay);
    fprintf(f, "socks_port=%u\n", g_app.socks_port);
    fprintf(f, "http_port=%u\n", g_app.http_port);
    fprintf(f, "force_peer=%s\n", g_app.force_peer);
    fprintf(f, "config_path=%s\n", g_app.config_path);
    fprintf(f, "h2_enabled=%d\n", g_app.h2_enabled);
    fprintf(f, "ech_enabled=%d\n", g_app.ech_enabled);
    fclose(f);
    snprintf(g_app.save_status, sizeof(g_app.save_status), "Config saved!");
}

static bool load_config() {
    FILE* f = fopen(get_config_path().c_str(), "r");
    if (!f) return false;
    char key[64], val[256];
    while (fscanf(f, "%63[^=]=%255[^\n]\n", key, val) == 2) {
        if (!strcmp(key, "protocol")) g_app.protocol = atoi(val);
        else if (!strcmp(key, "mode")) g_app.mode = atoi(val);
        else if (!strcmp(key, "lan_sharing")) g_app.lan_sharing = atoi(val);
        else if (!strcmp(key, "scan_mode")) g_app.scan_mode = atoi(val);
        else if (!strcmp(key, "ip_version")) g_app.ip_version = atoi(val);
        else if (!strcmp(key, "quick_reconnect")) g_app.quick_reconnect = atoi(val);
        else if (!strcmp(key, "noize_profile")) strncpy(g_app.noize_profile, val, sizeof(g_app.noize_profile)-1);
        else if (!strcmp(key, "fragment_enabled")) g_app.fragment_enabled = atoi(val);
        else if (!strcmp(key, "frag_min_size")) g_app.frag_min_size = atoi(val);
        else if (!strcmp(key, "frag_max_size")) g_app.frag_max_size = atoi(val);
        else if (!strcmp(key, "frag_min_delay")) g_app.frag_min_delay = atoi(val);
        else if (!strcmp(key, "frag_max_delay")) g_app.frag_max_delay = atoi(val);
        else if (!strcmp(key, "socks_port")) g_app.socks_port = (uint16_t)atoi(val);
        else if (!strcmp(key, "http_port")) g_app.http_port = (uint16_t)atoi(val);
        else if (!strcmp(key, "force_peer")) strncpy(g_app.force_peer, val, sizeof(g_app.force_peer)-1);
        else if (!strcmp(key, "config_path")) strncpy(g_app.config_path, val, sizeof(g_app.config_path)-1);
        else if (!strcmp(key, "h2_enabled")) g_app.h2_enabled = atoi(val);
        else if (!strcmp(key, "ech_enabled")) g_app.ech_enabled = atoi(val);
    }
    fclose(f);
    snprintf(g_app.save_status, sizeof(g_app.save_status), "Config loaded!");
    return true;
}

void log_callback(int level, const char* message, void* user_data) {
    (void)user_data;
    g_app.add_log(level, message);
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
    aether_init(log_callback, nullptr);
    load_config();
}

void ui_frame() {
    render_ui();
}

void ui_shutdown() {
    aether_stop();
    aether_free();
}

void render_ui() {
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 16));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar);

    AetherTelemetry telem = {};
    aether_get_telemetry(&telem);
    g_app.telem = telem;
    g_app.ffi_state.store(telem.state);
    g_app.ffi_connected.store(telem.state == AETHER_STATE_CONNECTED);

    AetherState cur = (AetherState)telem.state;
    bool connected  = (cur == AETHER_STATE_CONNECTED);
    bool busy       = (cur == AETHER_STATE_PROVISIONING || cur == AETHER_STATE_SCANNING || cur == AETHER_STATE_CONNECTING);

    // ── 1. STATUS BAR + CONNECT ──────────────────────────────────────────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 10));

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

        if (busy) { ImGui::SameLine(0, 8); draw_spinner(7.0f, 14, 7.0f); }

        ImGui::SameLine(ImGui::GetWindowWidth() - 230);
        ImVec4 btn = connected ? ImVec4(0.70f, 0.18f, 0.18f, 1.0f) : ImVec4(0.12f, 0.55f, 0.18f, 1.0f);
        ImVec4 btn_h(btn.x + 0.08f, btn.y + 0.08f, btn.z + 0.08f, 1.0f);
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

        ImGui::SameLine(0, 8);
        if (ImGui::Button("Save", ImVec2(60, 34))) {
            save_config();
        }
        if (g_app.save_status[0]) {
            ImGui::SameLine(0, 6);
            ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", g_app.save_status);
            g_app.save_status[0] = '\0';
        }

        ImGui::PopStyleVar(2);
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── 2. TRAFFIC STATS ─────────────────────────────────────────────────
    {
        char total_buf[32], rate_buf[32];

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

        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.60f, 1.0f),
            "Peer: %s  |  RTT: %u ms  |  Mode: %s",
            telem.connected_peer[0] ? telem.connected_peer : "-",
            telem.rtt_ms,
            g_app.mode == 0 ? "Proxy" : "TUN");
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
                    ImGui::Text("  LAN Gateways:  SOCKS5 %s:%u  |  HTTP %s:%u", lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::Text("  Local:  SOCKS5 127.0.0.1:%u  |  HTTP 127.0.0.1:%u", g_app.socks_port, g_app.http_port);
            } else {
                if (g_app.lan_sharing)
                    ImGui::Text("  TUN Active  |  LAN: SOCKS5 %s:%u  |  HTTP %s:%u", lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::Text("  TUN Active  |  SOCKS5 127.0.0.1:%u", g_app.socks_port);
            }
        } else {
            ImGui::Text("  No active tunnel");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar();
    }

    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // ── 3. CONFIG TABS ───────────────────────────────────────────────────
    if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {

        if (ImGui::BeginTabItem("Protocol")) {
            ImGui::Spacing();
            ImGui::Text("Transport");
            ImGui::RadioButton("MASQUE (HTTP/3 QUIC)", &g_app.protocol, 0);
            ImGui::RadioButton("WireGuard",             &g_app.protocol, 1);
            ImGui::RadioButton("WARP-in-WARP (Gool)",   &g_app.protocol, 2);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Mode");
            ImGui::RadioButton("Proxy", &g_app.mode, 0);
            ImGui::RadioButton("TUN",   &g_app.mode, 1);
            ImGui::Spacing();
            ImGui::Checkbox("LAN Sharing", &g_app.lan_sharing);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Transport Options");
            ImGui::Checkbox("HTTP/2 Fallback (--h2)", &g_app.h2_enabled);
            ImGui::Checkbox("ECH", &g_app.ech_enabled);
            ImGui::Checkbox("Quick Reconnect", &g_app.quick_reconnect);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            if (g_app.mode == 0) {
                ImGui::Text("Proxy Ports");
                ImGui::PushItemWidth(100);
                ImGui::InputScalar("SOCKS5", ImGuiDataType_U16, &g_app.socks_port);
                ImGui::SameLine(0, 20);
                ImGui::InputScalar("HTTP",   ImGuiDataType_U16, &g_app.http_port);
                ImGui::PopItemWidth();
                ImGui::Spacing();
            }
            ImGui::InputText("Force Peer", g_app.force_peer, sizeof(g_app.force_peer));
            ImGui::InputText("Config Path", g_app.config_path, sizeof(g_app.config_path));
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Obfuscation")) {
            ImGui::Spacing();
            ImGui::Text("Noize Profile");
            const char* profiles[] = { "off", "firewall", "balanced", "gfw" };
            int idx = 0;
            for (int i = 0; i < 4; i++)
                if (strcmp(g_app.noize_profile, profiles[i]) == 0) { idx = i; break; }
            if (ImGui::Combo("Profile", &idx, profiles, 4))
                strncpy(g_app.noize_profile, profiles[idx], sizeof(g_app.noize_profile) - 1);
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
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Scanner")) {
            ImGui::Spacing();
            ImGui::Text("Scan Mode");
            const char* modes[] = { "Turbo", "Balanced", "Thorough", "Stealth", "Ironclad" };
            ImGui::Combo("Mode", &g_app.scan_mode, modes, 5);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("IP Version");
            ImGui::RadioButton("IPv4",       &g_app.ip_version, 4);
            ImGui::RadioButton("IPv6",       &g_app.ip_version, 6);
            ImGui::RadioButton("Dual-Stack", &g_app.ip_version, 10);
            ImGui::EndTabItem();
        }

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

    ImGui::PopStyleVar(2);
    ImGui::End();
}
