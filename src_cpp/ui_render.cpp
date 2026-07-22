#include "ui_render.h"
#include <fstream>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif !defined(ANDROID)
#include <unistd.h>
#endif

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

static void apply_config_kv(const std::string& key, const std::string& val) {
    if (key == "protocol") g_app.protocol = atoi(val.c_str());
    else if (key == "mode") g_app.mode = atoi(val.c_str());
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
    else if (key == "socks_port") g_app.socks_port = (uint16_t)atoi(val.c_str());
    else if (key == "http_port") g_app.http_port = (uint16_t)atoi(val.c_str());
    else if (key == "force_peer")
        snprintf(g_app.force_peer, sizeof(g_app.force_peer), "%s", val.c_str());
    else if (key == "config_path")
        snprintf(g_app.config_path, sizeof(g_app.config_path), "%s", val.c_str());
    else if (key == "h2_enabled") g_app.h2_enabled = atoi(val.c_str()) != 0;
    else if (key == "ech_enabled") g_app.ech_enabled = atoi(val.c_str()) != 0;
    else if (key == "sni")
        snprintf(g_app.sni, sizeof(g_app.sni), "%s", val.c_str());
    else if (key == "ironclad_validate") g_app.ironclad_validate = atoi(val.c_str()) != 0;
    else if (key == "health_interval_secs") g_app.health_interval_secs = atoi(val.c_str());
    else if (key == "health_max_fails") g_app.health_max_fails = atoi(val.c_str());
    else if (key == "health_timeout_secs") g_app.health_timeout_secs = atoi(val.c_str());
    else if (key == "live_validate_secs") g_app.live_validate_secs = atoi(val.c_str());
    else if (key == "logging_enabled") g_app.logging_enabled = atoi(val.c_str()) != 0;
    else if (key == "auto_scroll") g_app.auto_scroll = atoi(val.c_str()) != 0;
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
    fprintf(f, "mode=%d\n", g_app.mode);
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
    fprintf(f, "force_peer=%s\n", g_app.force_peer);
    fprintf(f, "config_path=%s\n", g_app.config_path);
    fprintf(f, "h2_enabled=%d\n", g_app.h2_enabled ? 1 : 0);
    fprintf(f, "ech_enabled=%d\n", g_app.ech_enabled ? 1 : 0);
    fprintf(f, "sni=%s\n", g_app.sni);
    fprintf(f, "ironclad_validate=%d\n", g_app.ironclad_validate ? 1 : 0);
    fprintf(f, "health_interval_secs=%d\n", g_app.health_interval_secs);
    fprintf(f, "health_max_fails=%d\n", g_app.health_max_fails);
    fprintf(f, "health_timeout_secs=%d\n", g_app.health_timeout_secs);
    fprintf(f, "live_validate_secs=%d\n", g_app.live_validate_secs);
    fprintf(f, "logging_enabled=%d\n", g_app.logging_enabled ? 1 : 0);
    fprintf(f, "auto_scroll=%d\n", g_app.auto_scroll ? 1 : 0);
    fclose(f);
    snprintf(g_app.save_status, sizeof(g_app.save_status), "Config saved!");
    g_app.add_log(4, ("[ui] config saved: " + path).c_str());
}

static bool load_config_from(const std::string& path) {
    FILE* f = open_cfg(path, "rb");
    if (!f) return false;

    char line[512];
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

void log_callback(int level, const char* message, void* user_data) {
    (void)user_data;
    if (g_app.logging_enabled) g_app.add_log(level, message);
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
    if (!load_config()) {
        // First run: write defaults next to the executable (or app files on Android).
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
    const float W = io.DisplaySize.x;
    const bool narrow = W < 720.0f;

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(narrow ? 12.0f : 20.0f, narrow ? 10.0f : 16.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##FCAE", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // Throttle telemetry FFI (~4 Hz) — UI still paints at full rate.
    const double now = ImGui::GetTime();
    if (now - g_app.last_telem_t >= 0.25) {
        AetherTelemetry telem = {};
        aether_get_telemetry(&telem);
        g_app.telem = telem;
        g_app.ffi_state.store(telem.state);
        g_app.ffi_connected.store(telem.state == AETHER_STATE_CONNECTED);
        g_app.last_telem_t = now;
    }
    const AetherTelemetry& telem = g_app.telem;

    AetherState cur = (AetherState)telem.state;
    bool connected  = (cur == AETHER_STATE_CONNECTED);
    bool busy       = (cur == AETHER_STATE_PROVISIONING || cur == AETHER_STATE_SCANNING || cur == AETHER_STATE_CONNECTING)
                      || g_app.start_busy.load();
    bool errored    = (cur == AETHER_STATE_ERROR);

    // ── 1. STATUS BAR + ACTIONS ──────────────────────────────────────────
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
        if (btn_w < 100.0f) btn_w = 100.0f;
        if (ImGui::Button(connected || busy ? " DISCONNECT " : " CONNECT ", ImVec2(btn_w, 34))) {
            if (connected || busy || errored) {
                g_app.start_busy.store(false);
                std::thread([] {
                    aether_stop();
                    g_app.ffi_state.store(AETHER_STATE_DISCONNECTED);
                }).detach();
            } else if (!g_app.start_busy.load()) {
                g_app.start_busy.store(true);
                // Snapshot config + own string storage for the worker thread.
                struct Owned {
                    std::string noize, peer, path, sni;
                    AetherConfig c{};
                };
                auto* o = new Owned();
                o->noize = g_app.noize_profile;
                o->peer  = g_app.force_peer;
                o->path  = g_app.config_path;
                o->sni   = g_app.sni;
                o->c = g_app.to_config();
                o->c.noize_profile = o->noize.c_str();
                o->c.force_peer    = o->peer.empty() ? nullptr : o->peer.c_str();
                o->c.config_path   = o->path.c_str();
                o->c.sni           = o->sni.empty() ? nullptr : o->sni.c_str();
                std::thread([o] {
                    (void)aether_start(&o->c);
                    g_app.start_busy.store(false);
                    delete o;
                }).detach();
            }
        }
        ImGui::PopStyleColor(3);

        ImGui::SameLine(0, 6);
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

    if (errored && telem.last_error[0]) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "Error: %s", telem.last_error);
    }

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
        ImGui::TextWrapped("Peer: %s  |  RTT: %u ms  |  Mode: %s",
            telem.connected_peer[0] ? telem.connected_peer : "-",
            telem.rtt_ms,
            g_app.mode == 0 ? "Proxy" : "TUN");
        if (telem.status_message[0]) {
            ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.60f, 1.0f), "%s", telem.status_message);
        }
    }

    // ── Address callout ──────────────────────────────────────────────────
    {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.10f, 0.16f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.85f, 0.45f, 1.0f));
        float addr_h = narrow ? 48.0f : 30.0f;
        ImGui::BeginChild("##addr", ImVec2(0, addr_h), ImGuiChildFlags_Borders);

        if (connected) {
            const char* lip = telem.lan_ip[0] ? telem.lan_ip : "127.0.0.1";
            if (g_app.mode == 0) {
                if (g_app.lan_sharing)
                    ImGui::TextWrapped("LAN Gateways: SOCKS5 %s:%u | HTTP %s:%u", lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::TextWrapped("Local: SOCKS5 127.0.0.1:%u | HTTP 127.0.0.1:%u", g_app.socks_port, g_app.http_port);
            } else {
                if (g_app.lan_sharing)
                    ImGui::TextWrapped("TUN Active | LAN SOCKS5 %s:%u | HTTP %s:%u", lip, g_app.socks_port, lip, g_app.http_port);
                else
                    ImGui::TextWrapped("TUN Active | SOCKS5 127.0.0.1:%u", g_app.socks_port);
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
            ImGui::InputText("Identity file (aether.toml)", g_app.config_path, sizeof(g_app.config_path));
            ImGui::TextDisabled("UI settings: FCAE_VPN.cfg (next to app). Identity: Cloudflare device certs.");
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Obfuscation")) {
            ImGui::BeginChild("##obf_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Noize Profile");
            const char* profiles[] = { "off", "firewall", "balanced", "gfw" };
            int idx = 0;
            for (int i = 0; i < 4; i++)
                if (strcmp(g_app.noize_profile, profiles[i]) == 0) { idx = i; break; }
            if (ImGui::Combo("Profile", &idx, profiles, 4))
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
            const char* modes[] = { "Turbo", "Balanced", "Thorough", "Stealth" };
            if (g_app.scan_mode > 3) g_app.scan_mode = 1;
            ImGui::Combo("Mode", &g_app.scan_mode, modes, 4);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("IP Version");
            ImGui::RadioButton("IPv4",       &g_app.ip_version, 4);
            ImGui::SameLine();
            ImGui::RadioButton("IPv6",       &g_app.ip_version, 6);
            ImGui::SameLine();
            ImGui::RadioButton("Dual-Stack", &g_app.ip_version, 10);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Checkbox("Ironclad validation", &g_app.ironclad_validate);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("MASQUE SNI");
            ImGui::InputText("##sni", g_app.sni, sizeof(g_app.sni));
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Health")) {
            ImGui::BeginChild("##health_scroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
            ImGui::Spacing();
            ImGui::Text("Background health checks");
            ImGui::SliderInt("Interval (s)", &g_app.health_interval_secs, 5, 120);
            ImGui::SliderInt("Max fails", &g_app.health_max_fails, 1, 10);
            ImGui::SliderInt("Probe timeout (s)", &g_app.health_timeout_secs, 2, 30);
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
            ImGui::Text("Pre-connect validation");
            ImGui::SliderInt("Live validate (s)", &g_app.live_validate_secs, 5, 60);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Logs")) {
            ImGui::Checkbox("Logging", &g_app.logging_enabled);
            ImGui::SameLine(0, 12);
            ImGui::Checkbox("Auto-scroll", &g_app.auto_scroll);
            ImGui::SameLine(0, 12);
            if (ImGui::Button("Clear")) g_app.logs.clear();
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

            // Selectable multi-line log view (click lines to select; Ctrl+C via ImGui input)
            ImGui::BeginChild("##log", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 4), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
            ImGuiListClipper clipper;
            clipper.Begin((int)g_app.logs.size());
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    auto& [lvl, msg] = g_app.logs[(size_t)i];
                    ImVec4 c;
                    switch (lvl) {
                        case 1:  c = ImVec4(1.0f, 0.35f, 0.35f, 1.0f); break;
                        case 2:  c = ImVec4(1.0f, 0.80f, 0.25f, 1.0f); break;
                        case 3:  c = ImVec4(0.40f, 0.75f, 1.00f, 1.0f); break;
                        default: c = ImVec4(0.75f, 0.75f, 0.78f, 1.0f); break;
                    }
                    ImGui::PushStyleColor(ImGuiCol_Text, c);
                    ImGui::PushID(i);
                    if (ImGui::Selectable(msg.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                        if (ImGui::IsMouseDoubleClicked(0)) {
                            ImGui::SetClipboardText(msg.c_str());
                            snprintf(g_app.copy_status, sizeof(g_app.copy_status), "Line copied");
                        }
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
                }
            }
            if (g_app.auto_scroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f)
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();

            // Mouse-drag selectable text view (Ctrl+A to select all, Ctrl+C to copy)
            {
                static std::string log_buf;
                log_buf.clear();
                for (auto& [lvl, msg] : g_app.logs) {
                    log_buf += msg;
                    log_buf += '\n';
                }
                // ImGui::InputTextMultiline requires a mutable buffer even with ReadOnly
                static std::vector<char> sel_buf;
                sel_buf.assign(log_buf.begin(), log_buf.end());
                sel_buf.push_back('\0');
                ImGuiInputTextFlags sel_flags = ImGuiInputTextFlags_ReadOnly;
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 2));
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.06f, 0.06f, 0.08f, 1.0f));
                ImGui::InputTextMultiline("##log_sel", sel_buf.data(), sel_buf.size(),
                    ImVec2(-1, 80), sel_flags);
                ImGui::PopStyleColor();
                ImGui::PopStyleVar();
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::EndChild(); // ##tabs_host

    ImGui::PopStyleVar(2);
    ImGui::End();
}
