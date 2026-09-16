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
    // 0 = Aether, 1 = Psiphon (FcaeBackend).
    int  backend         = 0;
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
    bool tor_http_enabled = false;
    int tor_http_port = 1822;
    char force_peer[128] = {};
    // Engine identity file (Cloudflare device certs). Not the UI settings file.
    char config_path[256] = "aether.toml";
    bool h2_enabled      = true;
    bool ech_enabled     = true;

    // MASQUE SNI (empty = default consumer-masque.cloudflareclient.com)
    char sni[128] = {};
    // TUN DNS servers (comma separated per family). The bridge applies them
    // to the OS when the tunnel comes up and restores on down; defaults
    // mirror the Android VpnService hardcode.
    char tun_mtu[8] = "1500";
    char tun_tcp_sndbuf[32] = "256000";
    char tun_tcp_rcvbuf[32] = "256000";
    // Auto-tuning grows the receive buffer up to the kernel cap; on
    // high-latency, lossy links it tends to overshoot and add queueing
    // delay. OFF by default on every platform, opt-in here and on Android.
    bool tun_tcp_auto_tuning = false;
    char tun_dns4[96]  = "1.1.1.1,1.0.0.1";
    char tun_dns6[112] = "2606:4700:4700::1111,2606:4700:4700::1001";
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

    // Verbosity of the aether ENGINE (FcaeEngineLog). 3 = info = default.
    // The FFI's own log callback level is fixed at info and not exposed.
    int  engine_log  = 3;

    // Verbosity of the tun2socks data plane (FcaeT2sLog): 1 = silent ..
    // 5 = debug. The netstack logs a line per connection when verbose,
    // which is noise for daily use; silent still lets error lines through.
    int  t2s_log     = 1;

    // The aether engine's default Tor SOCKS port (config.rs
    // DEFAULT_TOR_SOCKS_PORT). Shown in the field, but an untouched field
    // defers to the engine (to_config() sends 0) instead of pinning the
    // literal, so bumping the engine default re-tunes every saved config.
    static constexpr int kEngineDefaultTorSocksPort = 1821;
    // Tor's own SOCKS listener. Must differ from socks_port/http_port: in
    // Chain mode tor and the engine are both listening.
    int  tor_socks_port = kEngineDefaultTorSocksPort;

    // Psiphon. Config JSON is built automatically (no paste field).
    char psiphon_region[8]    = {0};   // ISO code, "" = auto
    // Learned egress regions (CSV). Persists in the cfg so the region combo
    // starts populated even before this session's first Psiphon handshake;
    // refreshed by the engine poll whenever a non-empty list arrives.
    char psiphon_region_list[512] = {0};
    int  psiphon_transport = 0;        // index into kPsiphonTransports, 0 = auto
    char psiphon_data_dir[512] = {0};
    int  psiphon_socks_port = 1823;    // config.rs DEFAULT_PSIPHON_SOCKS_PORT; 0 also maps to it
    int  psiphon_http_port  = 1824;    // config.rs DEFAULT_PSIPHON_HTTP_PORT
    // Server-entry sources. tunnel-core has exactly three ways to learn its
    // first server entries; with none of them the controller sits on
    // "CandidateServers: count 0" forever and the tunnel never establishes.
    // At least one must be configured.
    // Built by to_config(): the default config JSON with the server-entry
    // fields merged in. to_config() returns a FcaeConfig pointing INTO this
    // string, and the connect worker immediately snapshots it — same
    // process-lifetime pattern as the other char[] fields.
    std::string psiphon_config_json_built;
    // Joined "v4,v6" built by to_config() for FcaeDnsConfig.server.
    char dns_server_built[224] = {0};

    // Tor egress (inside the Aether engine, not a separate backend).
    int  tor_mode    = 0;        // FcaeTorMode
    int  tor_bridges = 0;        // FcaeTorBridges
    char tor_bridge_lines[2048] = {};

    FcaeTelemetry telem = {};
    double last_telem_t = 0.0;

    mutable std::mutex logs_mutex;
    std::vector<std::pair<int, std::string>> logs;
    int  max_logs    = 200;
    bool auto_scroll = true;
    uint64_t logs_revision = 0; // guarded by logs_mutex, including ring eviction
    bool logging_enabled = true;
    bool auto_update_check  = true;
    // Update channel: off = stable slot only; on = pre-releases also compete
    // (engine picks the higher of the two). Default off.
    bool check_prereleases  = false;
    // NOTE: there is no pre-release update channel. Update checks always pass
    // include_prereleases=false (ui_render.cpp), so only stable releases are
    // ever advertised. The old "Include pre-releases" toggle was removed.
    char save_status[128] = {};
    char copy_status[64] = {};

    // Thread-safe: called from Rust FFI callback thread.
    void add_log(int level, const char* msg) {
        if (!msg) return;
        std::string s(msg);
        if (s.size() > 256) s.resize(256);
        std::lock_guard<std::mutex> lock(logs_mutex);
        logs.emplace_back(level, std::move(s));
        ++logs_revision;
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

    void clear_logs() {
        std::lock_guard<std::mutex> lock(logs_mutex);
        logs.clear();
        ++logs_revision;
    }

    // Capture content and revision together, including same-size replacements.
    std::vector<std::pair<int, std::string>> copy_logs(uint64_t& revision) const {
        std::lock_guard<std::mutex> lock(logs_mutex);
        revision = logs_revision;
        return logs;
    }

    /// Build a session config.
    ///
    /// Always starts from fcae_config_default() so struct_size/abi_version are
    /// stamped correctly and any field the UI does not yet expose gets a sane
    /// default instead of a zero.
    uint32_t parsed_tun_mtu() const {
        unsigned mtu = 0;
        bool mtu_valid = tun_mtu[0] != '\0';
        for (const char* p = tun_mtu; *p; ++p) {
            if (*p < '0' || *p > '9') { mtu_valid = false; break; }
            mtu = mtu * 10 + static_cast<unsigned>(*p - '0');
        }
        return mtu_valid && mtu >= 1280 && mtu <= 9000 ? mtu : 0xffffffffu;
    }

    FcaeConfig to_config() {
        FcaeConfig c;
        fcae_config_default(&c);

        c.backend          = (FcaeBackend)backend;
        c.protocol         = (FcaeProtocol)protocol;
        c.mode             = (FcaeMode)mode;
        c.scan_mode        = (FcaeScanMode)scan_mode;
        c.ip_version       = (FcaeIpVersion)ip_version;
        c.sys_profile      = (FcaeSysProfile)sys_profile;
        c.lan_sharing      = lan_sharing;
        c.quick_reconnect  = quick_reconnect;
        c.tun_mtu = parsed_tun_mtu();
        const uint32_t snd = fcae_parse_tcp_buffer_size(tun_tcp_sndbuf);
        const uint32_t rcv = fcae_parse_tcp_buffer_size(tun_tcp_rcvbuf);
        // Never turn malformed UI input into the ABI's zero/default sentinel.
        c.tun_tcp_sndbuf = snd ? snd : 0xffffffffu;
        c.tun_tcp_rcvbuf = rcv ? rcv : 0xffffffffu;
        c.tun_tcp_auto_tuning = tun_tcp_auto_tuning ? 1 : 2;
        c.tun2socks_log_level = (uint64_t)t2s_log;
        // TUN tunnels through the local SOCKS5 listener tun2socks dials, so
        // the checkbox is ignored in that mode: a port is always sent (same
        // rule as Android's FCAEVpnService). Port 0 means "off" for proxy
        // mode only.
        c.socks_port       = (mode == 1 || (backend != 1 && tor_mode != 0))
                                   ? (socks_port != 0 ? socks_port : (uint16_t)1819)
                                   : (socks_enabled ? socks_port : (uint16_t)0);
        c.http_port        = http_enabled ? http_port : 0;
        c.tor_http_port    = tor_http_enabled ? tor_http_port : 0;
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

        // Where does this session's traffic end: protocol Psiphon (backend
        // 1) or egress "Psiphon through the tunnel" (tor_mode 3 on a
        // non-Psiphon protocol). Both end at a Psiphon exit, and Psiphon
        // exits are IPv4-only.
        const bool proto_psiphon  = (backend == 1);
        const bool proto_tor      = (protocol == 4);
        const bool egress_psiphon = (!proto_psiphon && tor_mode == 3);
        const bool psiphon_exit   = (proto_psiphon || egress_psiphon);

        c.dns.sni = sni[0] ? sni : nullptr;
        // TUN DNS override: NULL keeps the bridge's default (no system DNS
        // change); a value is applied on `up` and restored on `down`.
        // In a psiphon_exit session the override carries the v4 servers
        // ONLY: a v6 entry would point the host resolver at an address the
        // v4-only exit cannot reach -- and on a host with native IPv6 the
        // query would LEAVE the tunnel entirely.
        std::snprintf(dns_server_built, sizeof(dns_server_built), "%s%s%s",
                      tun_dns4,
                      (tun_dns4[0] && tun_dns6[0] && !psiphon_exit) ? "," : "",
                      psiphon_exit ? "" : tun_dns6);
        c.dns.server = dns_server_built[0] ? dns_server_built : nullptr;

        c.routing.rules_file   = routes_file[0] ? routes_file : nullptr;
        c.routing.rules_inline = routes_inline[0] ? routes_inline : nullptr;

        c.zero_trust.team_name    = team_name[0] ? team_name : nullptr;
        c.zero_trust.access_token = access_token[0] ? access_token : nullptr;
        c.zero_trust.access_email = access_email[0] ? access_email : nullptr;

        c.engine_log       = (FcaeEngineLog)engine_log;

        // Protocol Psiphon does not apply the egress combo (value kept in
        // the UI for when the user switches back). Protocol Tor DOES combine
        // with egress 3: the chain runs Aether(Tor-only) -> Psiphon via
        // UpstreamProxyURL. Egress index 3 is Psiphon, not a FcaeTorMode.
        // (The flags were computed above; the DNS override needs them too.)
        int tm = tor_mode;
        if (proto_psiphon || egress_psiphon || tm < 0 || tm > 2) tm = 0;
        // Protocol Tor normalises tor.mode to Only inside the runtime no
        // matter what we pass, so keep sending 0 for the non-chain case (a
        // stale Chain value would only produce a normalization warning).
        if (proto_tor) tm = 0;
        c.tor.mode         = (FcaeTorMode)tm;
        c.tor.bridges      = (FcaeTorBridges)tor_bridges;
        c.tor.bridge_lines = tor_bridge_lines[0] ? tor_bridge_lines : nullptr;
        // Field == engine default -> send 0 (defer); explicit edit -> verbatim.
        c.tor.socks_port   = (uint16_t)(tor_socks_port == kEngineDefaultTorSocksPort
                                        ? 0 : tor_socks_port);

        // Egress "Psiphon through the tunnel" keeps Aether as the backend
        // (so WARP comes up first). _reserved[0] tells the supervisor to
        // start Psiphon next with UpstreamProxyURL = Aether SOCKS.
        if (egress_psiphon) {
            c._reserved[0] = 1;
        }

        // Built in-process. Process-lifetime pointer is safe for fcae_start.
        static const char kDefaultPsiphonConfig[] =
            "{\"PropagationChannelId\":\"FFFFFFFFFFFFFFFF\","
            "\"SponsorId\":\"FFFFFFFFFFFFFFFF\","
            "\"ClientVersion\":\"1\","
            "\"TunnelPoolSize\":1,"
            "\"DisableLocalSocksAuth\":true,"
            "\"EmitDiagnosticNotices\":true,"
            "\"UseIndistinguishableTLS\":true}";
        // Splice the server-entry sources into the config object. tunnel-core
        // bootstraps from the embedded list OR RemoteServerListUrl
        // (+RemoteServerListSignaturePublicKey); the all-F sponsor IDs ship
        // no entries by themselves, so without one of these fields Psiphon
        // can never leave CandidateServers count 0.
        std::string json = kDefaultPsiphonConfig;
        // Server-entry sources are no longer user-configurable here: the
        // core falls back to its built-in legacy remote list (+ embedded
        // entries auto-loaded from exe_dir()/psiphon_servers.txt by the
        // start worker, and the legacy-list injection in the psiphon
        // bridge). Only the transport choice needs splicing in.
        json = merge_psiphon_transport(json, psiphon_transport);
        psiphon_config_json_built = json;
        c.psiphon.config_json   = psiphon_config_json_built.c_str();
        c.psiphon.egress_region = psiphon_region[0] ? psiphon_region : nullptr;
        c.psiphon.data_root_dir = psiphon_data_dir[0] ? psiphon_data_dir : nullptr;
        c.psiphon.socks_port    = (uint16_t)psiphon_socks_port;
        c.psiphon.http_port     = (uint16_t)psiphon_http_port;

        return c;
    }

    /// Splice "LimitTunnelProtocols" for the selected transport family.
    /// 0 = Auto: omit the field entirely so tunnel-core uses its full
    /// default protocol set.
    static std::string merge_psiphon_transport(const std::string& json, int selection) {
        static const char* const kGroups[][4] = {
            {nullptr},
            {"SSH", "OSSH", nullptr},                                  // obfuscated SSH
            {"QUIC-OSSH", nullptr},                                    // QUIC
            {"UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
             "UNFRONTED-MEEK-SESSION-TICKET-OSSH", nullptr},
            {"FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH", nullptr},
        };
        if (selection <= 0 || selection >= (int)(sizeof(kGroups) / sizeof(kGroups[0])))
            return json;
        std::string arr = "\"LimitTunnelProtocols\":[";
        bool first = true;
        for (int i = 0; kGroups[selection][i]; ++i) {
            if (!first) arr += ",";
            arr += std::string("\"") + kGroups[selection][i] + "\"";
            first = false;
        }
        arr += "]";
        if (json.find("\"LimitTunnelProtocols\"") != std::string::npos) return json;
        size_t close = json.find_last_of('}');
        if (close == std::string::npos) return json;
        std::string out = json.substr(0, close);
        while (!out.empty() && (out.back() == ' ' || out.back() == '\n' ||
                                out.back() == '\r' || out.back() == '\t')) out.pop_back();
        if (!out.empty() && out.back() == ',') out.pop_back();
        return out + "," + arr + "}";
    }

    /// Splice "key": "value" into a flat Psiphon config JSON object.
    ///
    /// Textual like the Rust side's injectors (this TU deliberately has no
    /// JSON dependency), so the value is JSON-string-escaped first. A field
    /// the caller already set is left alone.
    static std::string merge_psiphon_string_field(
            const std::string& json, const char* key, const char* raw_value) {
        if (!raw_value || !raw_value[0]) return json;
        std::string value;
        value.reserve(strlen(raw_value) + 2);
        for (const char* p = raw_value; *p; ++p) {
            switch (*p) {
                case '"':  value += "\\\""; break;
                case '\\': value += "\\\\"; break;
                case '\n': value += "\\n";  break;
                case '\r': value += "\\r";  break;
                case '\t': value += "\\t";  break;
                default:   value += *p;     break;
            }
        }
        const std::string pair = std::string("\"") + key + "\":\"" + value + "\"";
        if (json.find("\"" + std::string(key) + "\"") != std::string::npos) {
            return json; // already present; do not duplicate
        }
        size_t close = json.find_last_of('}');
        if (close == std::string::npos) return json;
        std::string out = json.substr(0, close);
        // Trim whitespace and a dangling comma before appending.
        while (!out.empty() && (out.back() == ' ' || out.back() == '\n' ||
                                out.back() == '\r' || out.back() == '\t')) out.pop_back();
        if (!out.empty() && out.back() == ',') out.pop_back();
        return out + "," + pair + "}";
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
