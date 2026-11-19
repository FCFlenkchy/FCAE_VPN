#pragma once

#include <cstdint>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <vector>
#include <deque>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>

#include "imgui.h"

extern "C" {
#include "fcae.h"
}

/// The protocol list is the built-in transports followed by one entry per saved
/// core config, so a saved config is pickable everywhere a built-in transport
/// is (main protocol and chain hop alike).
static constexpr int kCoreTransportBase = FCAE_CORE_TRANSPORT_BASE;

/// Largest saved-configs document the engine accepts, mirroring fcae-runtime's
/// library limit. The document is what crosses the ABI, so it is bounded as a
/// whole and not only per config.
static constexpr size_t kMaxCoreDocument = 512 * 1024;

/// Append `text` to `out` as the body of a JSON string (without the quotes).
static inline void core_json_escape_into(std::string& out, const std::string& text) {
    for (unsigned char c : text) {
        switch (c) {
            case '"':
                out.push_back('\\');
                out.push_back('"');
                break;
            case '\\':
                out.push_back('\\');
                out.push_back('\\');
                break;
            case '\n':
                out.push_back('\\');
                out.push_back('n');
                break;
            case '\r':
                out.push_back('\\');
                out.push_back('r');
                break;
            case '\t':
                out.push_back('\\');
                out.push_back('t');
                break;
            default:
                if (c < 0x20) {
                    char escaped[7];
                    std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
                    out += escaped;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
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
    // 0 = Aether, 1 = Psiphon, 2 = Firefox (FcaeBackend).
    int  backend         = 0;
    // Ordered additional exits as protocol-list positions (see
    // transport_labels()); >= kCoreTransportBase names a saved core config.
    std::vector<int> chain_transports;
    std::vector<FcaeChainHop> chain_hops_built;
    // A saved core config: what the "Core configs" editor writes and what the
    // engine reads back through FcaeCore::library.
    struct CoreConfigEntry {
        std::string name;
        // 0 = Xray, 1 = sing-box, 2 = Mihomo.
        int backend = 0;
        // Share link or the core's own config JSON, verbatim.
        std::string text;
        // Bitwise FCAE_CORE_LISTENER_*: what this config can answer on. Cached
        // because reading it parses the document and the UI asks for it on
        // every frame; refreshed when the entry changes.
        uint32_t kinds = FCAE_CORE_LISTENER_SOCKS | FCAE_CORE_LISTENER_HTTP;
        // The ports the config itself names for those listeners, 0 when it names
        // none. A config that pins a port is not overruled by the app default.
        uint16_t pinned_socks_port = 0;
        uint16_t pinned_http_port = 0;
    };
    std::vector<CoreConfigEntry> core_configs;
    // Position in core_configs the main protocol runs; -1 when it runs none.
    int core_selected = -1;
    // Built by to_config(): the library document, the main entry's reference,
    // and one reference per saved-config chain hop. FcaeConfig points into
    // these, so they have to outlive the call.
    std::string core_library_built;
    std::string core_ref_built;
    std::vector<std::string> chain_core_refs_built;
    // Position in core_library_built for each entry of core_configs, or -1 when
    // the entry is not sent: the engine refuses the whole library over one bad
    // entry, so a draft that does not validate is kept on disk and left out
    // here. References are document positions, which is why this mapping
    // exists at all.
    std::vector<int> core_config_doc_index;
    // 0 = Proxy, 1 = TUN. TUN is the product default on every desktop
    // platform (and Android): full-system tunneling out of the box. The
    // device itself is still only raised AFTER the backend reports a live
    // SOCKS endpoint (fcae-runtime session supervisor), never before.
    int  mode            = 1;
    // TUN data-plane engine: 0 = tun2socks (default), 1 = zeptun,
    // 2 = hev-socks5-tunnel
    // (FCAE_TUN_ENGINE_*). Only consumed in TUN mode; the core rejects
    // engines that cannot run on this platform at connect time.
    int  tun_engine      = 0;
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
    static constexpr uint16_t kFirefoxDefaultSocksPort = 1825;
    static constexpr uint16_t kFirefoxDefaultHttpPort = 1826;
    uint16_t firefox_socks_port = kFirefoxDefaultSocksPort;
    uint16_t firefox_http_port  = kFirefoxDefaultHttpPort;
    // The cores get their own pairs. Aether (1819/1820), Tor (1821/1822),
    // Psiphon (1823/1824) and Firefox (1825/1826) already hold theirs, and the
    // engine refuses a listener that would clash with one of them.
    static constexpr uint16_t kXrayDefaultSocksPort   = 1827;
    static constexpr uint16_t kXrayDefaultHttpPort    = 1828;
    static constexpr uint16_t kSingBoxDefaultSocksPort = 1829;
    static constexpr uint16_t kSingBoxDefaultHttpPort  = 1830;
    static constexpr uint16_t kMihomoDefaultSocksPort = 1831;
    static constexpr uint16_t kMihomoDefaultHttpPort = 1832;
    uint16_t mihomo_socks_port = kMihomoDefaultSocksPort;
    uint16_t mihomo_http_port = kMihomoDefaultHttpPort;
    bool mihomo_socks_enabled = true;
    bool mihomo_http_enabled = false;
    uint16_t xray_socks_port    = kXrayDefaultSocksPort;
    uint16_t xray_http_port     = kXrayDefaultHttpPort;
    uint16_t singbox_socks_port = kSingBoxDefaultSocksPort;
    uint16_t singbox_http_port  = kSingBoxDefaultHttpPort;
    bool socks_enabled   = true;
    bool http_enabled    = false;
    bool xray_socks_enabled    = true;
    bool xray_http_enabled     = false;
    bool singbox_socks_enabled = true;
    bool singbox_http_enabled  = false;
    bool firefox_socks_enabled = true;
    bool firefox_http_enabled = false;
    bool psiphon_socks_enabled = true;
    bool psiphon_http_enabled = true;
    bool tor_socks_enabled = true;
    bool tor_http_enabled = false;
    int tor_http_port = 1822;
    char force_peer[128] = {};
    // Outbound proxy every carrier dials through (http/socks5 URL).
    char upstream_proxy[512] = {};
    // Engine identity file (Cloudflare device certs). Not the UI settings file.
    char config_path[256] = "aether.toml";
    bool h2_enabled      = true;
    bool ech_enabled     = true;

    // MASQUE SNI (empty = Aether's v2.4 default www.cloudflare.com).
    char sni[128] = {};
    // Aether engine options (FcaeAether); empty strings take the engine default.
    char ech_dns[256] = {};
    char ech_domain[128] = {};
    char gool_inner[64] = {};
    char tls_ciphers[512] = {};
    char api_address[128] = {};
    char api_host[128] = {};
    char api_sni[128] = {};
    char exit_loc[128] = {};
    char tls_groups[256] = {};
    char tls13_ciphers[512] = {};
    char tls_key_shares[256] = {};
    char tls_sigalgs[512] = {};
    char tls_cert_compression[64] = {};
    char tls_alps[8] = {};
    char tls_trust_anchors[512] = {};
    char tls_server_padding[8] = {};
    bool tls_verify = false;
    bool disable_grease = false;
    bool fragment_sni = false;
    bool enable_grease_sigalgs = false;
    bool enable_ech_grease = false;
    bool disable_ocsp_stapling = false;
    bool disable_sct = false;
    bool disable_session_ticket = false;
    bool disable_extension_permutation = false;
    char tun_mtu[8] = "1500";
    char tun_tcp_sndbuf[32] = "256000";
    char tun_tcp_rcvbuf[32] = "256000";
    // Auto-tuning grows the receive buffer up to the kernel cap; on
    // high-latency, lossy links it tends to overshoot and add queueing
    // delay. OFF by default on every platform, opt-in here and on Android.
    bool tun_tcp_auto_tuning = false;
    // TUN DNS servers (comma separated per family). The bridge applies them
    // to the OS when the tunnel comes up and restores on down; defaults
    // mirror the Android VpnService hardcode.
    char tun_dns4[96]  = "1.1.1.1,1.0.0.1";
    char tun_dns6[112] = "2606:4700:4700::1111,2606:4700:4700::1001";
    // Keep RFC1918 and carrier-grade NAT on the physical interface, so a
    // printer, a NAS or the router's admin page keeps answering while the
    // tunnel is up. ON by default; the tunnel is for public traffic.
    bool tun_exclude_private = true;
    // Zero Trust (Cloudflare Teams)
    char team_name[128] = {};
    char access_token[4096] = {};
    char access_client_id[128] = {};
    char access_client_secret[128] = {};
    char access_email[128] = {};
    // Inline routing rules (comma- or newline-separated)
    char routes_inline[2048] = {};
    int sys_profile       = 0;   // 0=Auto, 1=Low, 2=Medium, 3=High

    // Verbosity of the aether ENGINE (FcaeEngineLog). 3 = info = default.
    // The FFI's own log callback level is fixed at info and not exposed.
    int  engine_log  = 3;

    // Route-core verbosity (FcaeEngineLog; Xray, sing-box, Mihomo).
    // 0 = silent by default; independent of the app's own FFI log level.
    int  core_log    = 0;

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
    char psiphon_region_list[1024] = {0};
    int  psiphon_transport = 0;        // index into kPsiphonTransports, 0 = auto
    char psiphon_data_dir[512] = {0};
    int  psiphon_socks_port = 1823;    // config.rs DEFAULT_PSIPHON_SOCKS_PORT
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

    // Firefox IP Protection. Secrets and pending FxA session state are never
    // persisted in the UI configuration file.
    char firefox_account_id[33] = {};
    char firefox_location[128] = {};
    char firefox_server[256] = {};
    int  firefox_transport = 0; // 0=auto, 1=h2, 2=h1
    char firefox_email[256] = {};
    char firefox_password[1024] = {};
    char firefox_code[256] = {};
    char firefox_pending_id[128] = {};
    char firefox_status[256] = {};
    uint64_t firefox_job = 0;
    uint64_t firefox_captcha_id = 0;
    char firefox_captcha_answer[257] = {};
    char firefox_operation[24] = {};
    bool firefox_totp = false;
    bool firefox_remove_in_flight = false;

    // Tor egress (inside the Aether engine, not a separate backend). Tor is a
    // chain hop, so only its bridges and its own ports live here.
    int  tor_bridges = 0;        // FcaeTorBridges
    char tor_bridge_lines[2048] = {};

    FcaeTelemetry telem = {};
    double last_telem_t = 0.0;

    mutable std::mutex logs_mutex;
    std::deque<std::pair<int, std::string>> logs;
    int  max_logs    = 200;
    bool auto_scroll = true;
    uint64_t logs_revision = 0; // guarded by logs_mutex, including ring eviction
    size_t logs_bytes = 0;
    std::atomic<bool> logging_enabled{true};
    /// UI text scale in percent, applied every frame as style.FontScaleMain on
    /// top of the host's per-monitor DPI factor. Rows size themselves from the
    /// resulting font height, so buttons and spacing grow with the text instead
    /// of clipping it. 100 = as designed; 75..250 is the accepted range, and
    /// the fallback for a display whose scaling the window does not inherit.
    int  ui_scale_percent = 100;
    bool auto_update_check  = true;
    // Update channel: off = stable slot only; on = pre-releases also compete
    // (engine picks the higher of the two). Default off. Toggling the Logs-tab
    // checkbox re-runs the check immediately with the new value; the saved
    // config is what the startup auto-check uses.
    bool check_prereleases  = false;
    char save_status[128] = {};
    char copy_status[64] = {};

    // Thread-safe: called from Rust FFI callback thread.
    void add_log(int level, const char* msg) {
        if (!msg) return;
        std::string s(msg);
        if (s.rfind("[psiphon] {", 0) != 0 && s.size() > 256) s.resize(256);
        std::lock_guard<std::mutex> lock(logs_mutex);
        logs_bytes += s.size();
        logs.emplace_back(level, std::move(s));
        ++logs_revision;
        while ((int)logs.size() > max_logs || (logs_bytes > 2 * 1024 * 1024 && logs.size() > 1)) {
            logs_bytes -= logs.front().second.size();
            logs.pop_front();
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
        logs_bytes = 0;
        ++logs_revision;
    }

    // Capture content and revision together, including same-size replacements.
    /// Refresh `out` only when the log changed since `revision`.
    void sync_logs(uint64_t& revision, std::vector<std::pair<int, std::string>>& out) const {
        std::lock_guard<std::mutex> lock(logs_mutex);
        if (revision == logs_revision) return;
        revision = logs_revision;
        out.assign(logs.begin(), logs.end());
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
            if (mtu > 9000) { mtu_valid = false; break; }
            mtu = mtu * 10 + static_cast<unsigned>(*p - '0');
        }
        return mtu_valid && mtu >= 1280 && mtu <= 9000 ? mtu : 0xffffffffu;
    }

    bool final_listener_is_firefox() const {
        if (!chain_transports.empty()) return chain_transports.back() == 10;
        return backend == 2;
    }

    /// A saved core config by protocol-list position, or nullptr.
    const CoreConfigEntry* core_config_at(int transport) const {
        if (transport < kCoreTransportBase) return nullptr;
        const size_t index = (size_t)(transport - kCoreTransportBase);
        return index < core_configs.size() ? &core_configs[index] : nullptr;
    }

    static int core_backend_id(int selection) { return selection == 2 ? FCAE_BACKEND_MIHOMO : selection == 1 ? FCAE_BACKEND_SINGBOX : FCAE_BACKEND_XRAY; }
    static const char* core_backend_name(int selection) { return selection == 2 ? "Mihomo" : selection == 1 ? "sing-box" : "Xray"; }
    /// Whether the engine may be handed this entry. Its parser rejects the
    /// whole library over one bad entry (that is what makes a config that
    /// saves a config that starts), so the check here is the same one the
    /// editor shows the user.
    static bool core_config_usable(const CoreConfigEntry& entry) {
        if (entry.name.empty() || entry.text.empty()) return false;
        const int32_t target = core_backend_id(entry.backend);
        return fcae_core_check_profile(entry.text.c_str(), target, nullptr, 0);
    }

    /// Where the entry at `transport` ends up in the serialised library, or -1
    /// when nothing is sent for it. Valid only after `build_core_library()`.
    int core_doc_index(int transport) const {
        if (transport < kCoreTransportBase) return -1;
        const size_t index = (size_t)(transport - kCoreTransportBase);
        return index < core_config_doc_index.size() ? core_config_doc_index[(size_t)index] : -1;
    }

    /// Serialise `core_configs` into the document the engine parses. Every
    /// reference in the config is a position in this array, so it is built
    /// from the same vector the positions index.
    void build_core_library() {
        core_library_built.clear();
        core_config_doc_index.assign(core_configs.size(), -1);
        if (core_configs.empty()) return;
        core_library_built += '[';
        int written = 0;
        for (size_t i = 0; i < core_configs.size(); ++i) {
            const CoreConfigEntry& entry = core_configs[i];
            if (!core_config_usable(entry)) continue;
            // Names are references in their own right, so the engine rejects a
            // duplicate and would take the whole library with it. The first
            // entry keeps the name; the editor already flags the rest.
            bool duplicate = false;
            for (size_t j = 0; j < i && !duplicate; ++j) {
                const CoreConfigEntry& other = core_configs[j];
                duplicate = core_config_usable(other) && other.name.size() == entry.name.size()
                    && std::equal(other.name.begin(), other.name.end(), entry.name.begin(),
                                  [](char a, char b) {
                                      return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
                                  });
            }
            if (duplicate) continue;
            // The document as a whole is bounded, and the engine rejects an
            // oversized one outright: leave out the entry that would cross the
            // limit rather than fail the session over a config nobody runs.
            const size_t mark = core_library_built.size();
            if (written) core_library_built += ',';
            core_library_built += "{\"name\":\"";
            core_json_escape_into(core_library_built, entry.name);
            core_library_built += "\",\"backend\":\"";
            core_library_built += entry.backend == 2 ? "mihomo" : entry.backend == 1 ? "sing-box" : "xray";
            core_library_built += "\",\"config\":\"";
            core_json_escape_into(core_library_built, entry.text);
            core_library_built += "\"}";
            if (core_library_built.size() + 1 > kMaxCoreDocument) {
                core_library_built.resize(mark);
                continue;
            }
            core_config_doc_index[i] = written++;
        }
        if (written) core_library_built += ']';
        else core_library_built.clear();
    }

    /// The core the session's final listener belongs to: 3 = Xray, 4 =
    /// sing-box, 0 for every other backend. A chain's last exit decides, and
    /// without a chain the main protocol does.
    int final_listener_core() const {
        int core = 0;
        if (!chain_transports.empty()) {
            const int transport = chain_transports.back();
            if (transport < kCoreTransportBase) return 0;
            const CoreConfigEntry* entry = core_config_at(transport);
            if (!entry) return 0;
            core = core_backend_id(entry->backend);
        } else if (backend >= 3) {
            core = backend;
        } else {
            return 0;
        }
        // A config the engine cannot read is not run at all — to_config() starts
        // the default transport instead — and the listener goes with it.
        const CoreConfigEntry* entry = final_core_config();
        return entry && entry->kinds ? core : 0;
    }

    bool final_listener_is_core() const { return final_listener_core() >= 3; }

    /// The saved config the final hop runs, or nullptr for a built-in transport.
    const CoreConfigEntry* final_core_config() const {
        if (!chain_transports.empty()) return core_config_at(chain_transports.back());
        return core_config_at(kCoreTransportBase + core_selected);
    }

    /// Read one config's capabilities out of the engine and cache them on it.
    static void refresh_core_listeners(CoreConfigEntry& entry) {
        uint32_t socks_port = 0;
        uint32_t http_port = 0;
        entry.kinds = fcae_core_listeners(
            entry.text.c_str(),
            core_backend_id(entry.backend),
            &socks_port, &http_port);
        entry.pinned_socks_port = (uint16_t)socks_port;
        entry.pinned_http_port = (uint16_t)http_port;
    }

    /// Recompute every entry: after a load, an edit, an add or a removal.
    void refresh_core_listeners() {
        for (CoreConfigEntry& entry : core_configs) refresh_core_listeners(entry);
    }

    /// What the session's final listener can be answered on.
    uint32_t final_listener_kinds() const {
        const CoreConfigEntry* entry = final_listener_is_core() ? final_core_config() : nullptr;
        return entry ? entry->kinds
                     : FCAE_CORE_LISTENER_SOCKS | FCAE_CORE_LISTENER_HTTP;
    }

    uint16_t default_listener_socks_port() const {
        switch (final_listener_core()) {
            case 3: return kXrayDefaultSocksPort;
            case 4: return kSingBoxDefaultSocksPort;
            case 5: return kMihomoDefaultSocksPort;
            default: return final_listener_is_firefox() ? kFirefoxDefaultSocksPort : 1819;
        }
    }

    /// A port the config pins outranks the app default, and only the default:
    /// the engine rewrites a native config's listener to whatever the session
    /// asks for, so a value of the user's own is never overruled.
    uint16_t pinned_or(uint16_t configured, uint16_t fallback, bool socks) const {
        const CoreConfigEntry* entry = final_core_config();
        const uint16_t pinned = entry ? (socks ? entry->pinned_socks_port : entry->pinned_http_port) : 0;
        return (configured == fallback && pinned) ? pinned : configured;
    }

    uint16_t listener_socks_port() const {
        switch (final_listener_core()) {
            case 3: return pinned_or(xray_socks_port, kXrayDefaultSocksPort, true);
            case 4: return pinned_or(singbox_socks_port, kSingBoxDefaultSocksPort, true);
            case 5: return pinned_or(mihomo_socks_port, kMihomoDefaultSocksPort, true);
            default: return final_listener_is_firefox() ? firefox_socks_port : socks_port;
        }
    }

    uint16_t listener_http_port() const {
        switch (final_listener_core()) {
            case 3: return pinned_or(xray_http_port, kXrayDefaultHttpPort, false);
            case 4: return pinned_or(singbox_http_port, kSingBoxDefaultHttpPort, false);
            case 5: return pinned_or(mihomo_http_port, kMihomoDefaultHttpPort, false);
            default: return final_listener_is_firefox() ? firefox_http_port : http_port;
        }
    }

    bool listener_socks_requested() const {
        switch (final_listener_core()) {
            case 3: return xray_socks_enabled;
            case 4: return singbox_socks_enabled;
            case 5: return mihomo_socks_enabled;
            default: return final_listener_is_firefox() ? firefox_socks_enabled : socks_enabled;
        }
    }

    bool listener_http_requested() const {
        switch (final_listener_core()) {
            case 3: return xray_http_enabled;
            case 4: return singbox_http_enabled;
            case 5: return mihomo_http_enabled;
            default: return final_listener_is_firefox() ? firefox_http_enabled : http_enabled;
        }
    }

    /// A core config that declares no inbound of a type cannot answer on it, so
    /// the switch does not open a listener nothing serves.
    bool listener_socks_enabled() const {
        return listener_socks_requested()
            && (final_listener_kinds() & FCAE_CORE_LISTENER_SOCKS) != 0;
    }

    bool listener_http_enabled() const {
        return listener_http_requested()
            && (final_listener_kinds() & FCAE_CORE_LISTENER_HTTP) != 0;
    }

    FcaeConfig to_config() {
        FcaeConfig c;
        fcae_config_default(&c);

        // The saved core configs, as the one document the engine validates.
        // Positions are fixed for the whole call, which is what the "#N"
        // references below rely on.
        build_core_library();
        c.core.library    = core_library_built.empty() ? nullptr : core_library_built.c_str();
        c.core.log_level  = (core_log >= 0 && core_log <= 5) ? (FcaeEngineLog)core_log
                                                             : FCAE_ENGINE_LOG_OFF;
        // A core backend with nothing to run is a start that fails, so a config
        // the engine was not sent (a draft, or one that vanished) degrades to the
        // default transport instead of refusing the session.
        const int main_doc = core_doc_index(kCoreTransportBase + core_selected);
        if (backend >= 3 && main_doc < 0) {
            add_log(2, "[ui] the selected saved config is not usable; starting the default transport");
        }
        core_ref_built.clear();
        if (main_doc >= 0) {
            core_ref_built = "#" + std::to_string(main_doc);
            c.core.config_ref = core_ref_built.c_str();
        }

        // A saved config decides its own core, and its profile is the route.
        if (main_doc >= 0 && backend == 3)      c.backend = FCAE_BACKEND_XRAY;
        else if (main_doc >= 0 && backend == 4) c.backend = FCAE_BACKEND_SINGBOX;
        else if (main_doc >= 0 && backend == 5) c.backend = FCAE_BACKEND_MIHOMO;
        else if (backend >= 3)                  c.backend = FCAE_BACKEND_AETHER;
        else c.backend = (backend >= 0 && backend <= 2) ? (FcaeBackend)backend : FCAE_BACKEND_AETHER;

        // A saved-config hop is referenced rather than encoded, so its
        // references are built first and pointed at second: the hop list stays
        // in carrier-to-exit order, in one pass. A position whose config is not
        // in the document is dropped — the engine resolves every reference
        // before it starts anything, so a dangling one refuses the whole
        // session, and re-pointing the hop would route through a config the
        // user did not pick.
        chain_core_refs_built.clear();
        for (int transport : chain_transports) {
            const int doc = core_doc_index(transport);
            if (doc >= 0) chain_core_refs_built.push_back("#" + std::to_string(doc));
        }
        size_t core_ref = 0;
        chain_hops_built.clear();
        chain_hops_built.reserve(chain_transports.size());
        for (int transport : chain_transports) {
            if (core_doc_index(transport) >= 0) {
                FcaeChainHop core_hop{};
                // The referenced entry decides the backend and the profile, so
                // the fallback here stays neutral instead of claiming a core.
                core_hop.backend = FCAE_BACKEND_AETHER;
                core_hop.protocol = FCAE_PROTOCOL_AUTO;
                core_hop.config_ref = chain_core_refs_built[core_ref++].c_str();
                chain_hops_built.push_back(core_hop);
                continue;
            }
            if (transport >= kCoreTransportBase) continue;
            FcaeChainHop hop{};
            hop.backend = transport == 5 ? FCAE_BACKEND_PSIPHON : transport == 10 ? FCAE_BACKEND_FIREFOX : FCAE_BACKEND_AETHER;
            hop.h2_enabled = transport == 1 || transport == 7 || transport == 9;
            switch (transport) {
                case 0: case 1: hop.protocol = FCAE_PROTOCOL_MASQUE; break;
                case 2: hop.protocol = FCAE_PROTOCOL_WIREGUARD; break;
                case 4: hop.protocol = FCAE_PROTOCOL_TOR; break;
                case 5: case 10: hop.protocol = FCAE_PROTOCOL_AUTO; break;
                case 6: case 7: hop.protocol = FCAE_PROTOCOL_MASQUE_IN_MASQUE; break;
                case 8: case 9: hop.protocol = FCAE_PROTOCOL_WARP_IN_MASQUE; break;
                default: hop.protocol = FCAE_PROTOCOL_GOOL; break;
            }
            chain_hops_built.push_back(hop);
        }
        c.chain.hops = chain_hops_built.data();
        c.chain.hop_count = (uint32_t)chain_hops_built.size();
        // A saved config has no transport dimension of its own: the profile
        // carries it, and a stale protocol id must not be layered on top.
        c.protocol         = (main_doc >= 0 || backend >= 3) ? FCAE_PROTOCOL_AUTO
                           : (protocol >= 0 && protocol <= 6) ? (FcaeProtocol)protocol : FCAE_PROTOCOL_MASQUE;
        // Mode is shared by every protocol/backend: once the UI selects TUN,
        // never let a Psiphon/Tor mapping silently turn it back into Proxy.
        c.mode             = mode == 1 ? FCAE_MODE_TUN : FCAE_MODE_PROXY;
        c.scan_mode        = (scan_mode >= 0 && scan_mode <= 4) ? (FcaeScanMode)scan_mode : FCAE_SCAN_BALANCED;
        c.ip_version       = (ip_version == 4 || ip_version == 6 || ip_version == 10) ? (FcaeIpVersion)ip_version : FCAE_IP_V4;
        c.sys_profile      = (sys_profile >= 0 && sys_profile <= 3) ? (FcaeSysProfile)sys_profile : FCAE_PROFILE_AUTO;
        c.lan_sharing      = lan_sharing;
        c.quick_reconnect  = quick_reconnect;
        c.tun_mtu = mode == 1 ? parsed_tun_mtu() : 1500;
        const uint32_t snd = mode == 1 && tun_engine == 0 ? fcae_parse_tcp_buffer_size(tun_tcp_sndbuf) : 256000;
        const uint32_t rcv = mode == 1 && tun_engine == 0 ? fcae_parse_tcp_buffer_size(tun_tcp_rcvbuf) : 256000;
        // Never turn malformed UI input into the ABI's zero/default sentinel.
        c.tun_tcp_sndbuf = snd ? snd : 0xffffffffu;
        c.tun_tcp_rcvbuf = rcv ? rcv : 0xffffffffu;
        c.tun_tcp_auto_tuning = mode == 1 && tun_engine == 0 && tun_tcp_auto_tuning ? 1 : 2;
        c.tun2socks_log_level = (uint64_t)t2s_log;
        c.tun_engine     = (tun_engine > 0 && tun_engine < (int)fcae_tun_engine_count())
                               ? (uint64_t)tun_engine
                               : FCAE_TUN_ENGINE_TUN2SOCKS;
        c.socks_port       = listener_socks_enabled() ? listener_socks_port() : 0;
        c.http_port        = listener_http_enabled() ? listener_http_port() : 0;
        c.tor_http_port    = tor_http_enabled ? tor_http_port : 0;
        c.force_peer       = force_peer[0] ? force_peer : nullptr;
        c.upstream_proxy   = upstream_proxy[0] ? upstream_proxy : nullptr;
        c.config_path      = config_path;

        c.obfuscation.noize_profile    = noize_profile;
        c.obfuscation.fragment_enabled = fragment_enabled;
        c.obfuscation.frag_min_size    = (uint32_t)frag_min_size;
        c.obfuscation.frag_max_size    = (uint32_t)frag_max_size;
        c.obfuscation.frag_min_delay_ms = (uint32_t)frag_min_delay;
        c.obfuscation.frag_max_delay_ms = (uint32_t)frag_max_delay;
        c.obfuscation.h2_enabled       = h2_enabled;
        c.obfuscation.ech_enabled      = ech_enabled;
        c.aether.ech_dns        = ech_dns[0] ? ech_dns : nullptr;
        c.aether.ech_domain     = ech_domain[0] ? ech_domain : nullptr;
        c.aether.gool_inner     = gool_inner[0] ? gool_inner : nullptr;
        c.aether.tls_ciphers    = tls_ciphers[0] ? tls_ciphers : nullptr;
        c.aether.api_address    = api_address[0] ? api_address : nullptr;
        c.aether.api_host       = api_host[0] ? api_host : nullptr;
        c.aether.api_sni        = api_sni[0] ? api_sni : nullptr;
        c.aether.exit_loc       = exit_loc[0] ? exit_loc : nullptr;
        c.dns.tls_groups         = tls_groups[0] ? tls_groups : nullptr;
        c.aether.tls13_ciphers   = tls13_ciphers[0] ? tls13_ciphers : nullptr;
        c.aether.tls_key_shares  = tls_key_shares[0] ? tls_key_shares : nullptr;
        c.aether.tls_sigalgs     = tls_sigalgs[0] ? tls_sigalgs : nullptr;
        c.aether.tls_cert_compression = tls_cert_compression[0] ? tls_cert_compression : nullptr;
        c.aether.tls_alps        = tls_alps[0] ? tls_alps : nullptr;
        c.aether.tls_trust_anchors = tls_trust_anchors[0] ? tls_trust_anchors : nullptr;
        c.aether.tls_server_padding = tls_server_padding[0] ? tls_server_padding : nullptr;
        c.aether.tls_verify     = tls_verify;
        c.aether.disable_grease = disable_grease;
        c.aether.fragment_sni   = fragment_sni;
        c.aether.enable_grease_sigalgs = enable_grease_sigalgs;
        c.aether.enable_ech_grease = enable_ech_grease;
        c.aether.disable_ocsp_stapling = disable_ocsp_stapling;
        c.aether.disable_sct = disable_sct;
        c.aether.disable_session_ticket = disable_session_ticket;
        c.aether.disable_extension_permutation = disable_extension_permutation;

        // Where does this session's traffic end. Psiphon exits are IPv4-only,
        // and an exit is whatever the last hop runs.
        const int final_backend = !chain_hops_built.empty() ? (int)chain_hops_built.back().backend : backend;
        const bool psiphon_exit = (final_backend == FCAE_BACKEND_PSIPHON);

        c.dns.sni = sni[0] ? sni : nullptr;
        // Desktop uses default IPv4 resolvers when this override is empty.
        // Configured DNS is applied on `up` and restored on `down`.
        // In a psiphon_exit session the override carries the v4 servers
        // ONLY: a v6 entry would point the host resolver at an address the
        // v4-only exit cannot reach -- and on a host with native IPv6 the
        // query would LEAVE the tunnel entirely.
        std::snprintf(dns_server_built, sizeof(dns_server_built), "%s%s%s",
                      tun_dns4,
                      (tun_dns4[0] && tun_dns6[0] && !psiphon_exit) ? "," : "",
                      psiphon_exit ? "" : tun_dns6);
        c.dns.server = dns_server_built[0] ? dns_server_built : nullptr;

        c.routing.rules_file   = nullptr;
        c.routing.rules_inline = routes_inline[0] ? routes_inline : nullptr;

        c.zero_trust.team_name    = team_name[0] ? team_name : nullptr;
        c.zero_trust.access_token = access_token[0] ? access_token : nullptr;
        c.zero_trust.access_email = access_email[0] ? access_email : nullptr;

        c.engine_log       = (engine_log >= 0 && engine_log <= 5) ? (FcaeEngineLog)engine_log : FCAE_ENGINE_LOG_INFO;

        // Tor's own mode is not a setting any more: a Tor hop is a chain hop,
        // and the runtime gives it its own mode. Only the bridges and the ports
        // travel from here.
        c.tor.mode         = FCAE_TOR_OFF;
        c.tor.bridges      = (tor_bridges >= 0 && tor_bridges <= 3) ? (FcaeTorBridges)tor_bridges : FCAE_TOR_BRIDGES_NONE;
        c.tor.bridge_lines = tor_bridge_lines[0] ? tor_bridge_lines : nullptr;
        // Field == engine default -> send 0 (defer); explicit edit -> verbatim.
        c.tor.socks_port   = (uint16_t)(tor_socks_port == kEngineDefaultTorSocksPort
                                        ? 0 : tor_socks_port);

        if (mode == 1 && listener_http_enabled()) c._reserved[0] |= FCAE_CONFIG_TUN_HTTP;
        // The bit means "route private ranges in"; the default leaves it clear.
        if (mode == 1 && !tun_exclude_private) c._reserved[0] |= FCAE_CONFIG_TUN_ROUTE_PRIVATE;

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
        // entries auto-loaded from <data folder>/psiphon_servers.txt by the
        // start worker, and the legacy-list injection in the psiphon
        // bridge). Only the transport choice needs splicing in.
        if (!psiphon_socks_enabled) json.insert(json.size() - 1, ",\"DisableLocalSocksProxy\":true");
        if (!psiphon_http_enabled) json.insert(json.size() - 1, ",\"DisableLocalHTTPProxy\":true");
        // Every backend's switches, because a hop in a chain is dialled through
        // its own listener too: a core that only appears in the middle of a
        // route still opens the SOCKS5 and HTTP listeners the user configured.
        // Their ports travel with them for the same reason: a hop is one
        // instance of one core, so it listens where the user pointed that core
        // instead of on a number nobody can configure against.
        const auto port = [](uint16_t value) { return std::to_string((unsigned)value); };
        json.insert(json.size() - 1,
            std::string(",\"FCAEListeners\":{\"aetherSocks\":") + (socks_enabled ? "true" : "false") +
            ",\"aetherHttp\":" + (http_enabled ? "true" : "false") +
            ",\"aetherSocksPort\":" + port(socks_port) +
            ",\"aetherHttpPort\":" + port(http_port) +
            ",\"firefoxSocks\":" + (firefox_socks_enabled ? "true" : "false") +
            ",\"firefoxHttp\":" + (firefox_http_enabled ? "true" : "false") +
            ",\"firefoxSocksPort\":" + port(firefox_socks_port) +
            ",\"firefoxHttpPort\":" + port(firefox_http_port) +
            ",\"torSocks\":" + (tor_socks_enabled ? "true" : "false") +
            ",\"torHttp\":" + (tor_http_enabled ? "true" : "false") +
            ",\"xraySocks\":" + (xray_socks_enabled ? "true" : "false") +
            ",\"xrayHttp\":" + (xray_http_enabled ? "true" : "false") +
            ",\"xraySocksPort\":" + port(xray_socks_port) +
            ",\"xrayHttpPort\":" + port(xray_http_port) +
            ",\"singboxSocks\":" + (singbox_socks_enabled ? "true" : "false") +
            ",\"singboxHttp\":" + (singbox_http_enabled ? "true" : "false") +
            ",\"singboxSocksPort\":" + port(singbox_socks_port) +
            ",\"singboxHttpPort\":" + port(singbox_http_port) +
            ",\"mihomoSocks\":" + (mihomo_socks_enabled ? "true" : "false") +
            ",\"mihomoHttp\":" + (mihomo_http_enabled ? "true" : "false") +
            ",\"mihomoSocksPort\":" + port(mihomo_socks_port) +
            ",\"mihomoHttpPort\":" + port(mihomo_http_port) + "}");
        json = merge_psiphon_transport(json, psiphon_transport);
        psiphon_config_json_built = json;
        c.psiphon.config_json   = psiphon_config_json_built.c_str();
        c.psiphon.egress_region = psiphon_region[0] ? psiphon_region : nullptr;
        c.psiphon.data_root_dir = psiphon_data_dir[0] ? psiphon_data_dir : nullptr;
        c.psiphon.socks_port    = (uint16_t)std::clamp(psiphon_socks_port, 1, 65535);
        c.psiphon.http_port     = (uint16_t)std::clamp(psiphon_http_port, 1, 65535);
        c.firefox.account_id = firefox_account_id[0] ? firefox_account_id : nullptr;
        c.firefox.location = firefox_location[0] ? firefox_location : nullptr;
        c.firefox.server = firefox_server[0] ? firefox_server : nullptr;
        static const char* const kFirefoxTransports[] = {"auto", "h2", "h1"};
        c.firefox.transport = kFirefoxTransports[(firefox_transport >= 0 && firefox_transport <= 2) ? firefox_transport : 0];

        return c;
    }

    /// Splice "LimitTunnelProtocols" for the selected transport.
    /// 0 = Auto: omit the field entirely so tunnel-core uses its full
    /// default protocol set. Every other entry is exactly one protocol,
    /// named with the verbatim constant from tunnel-core's protocol.go
    /// SupportedTunnelProtocols — an unsupported name (or the
    /// client-disabled TAPDANCE-OSSH) fails config validation and the whole
    /// start. Index order is stable across versions so saved configs never
    /// remap; new protocols append. Keep in step with the combo labels in
    /// ui_render.cpp and with PsiphonTunnelService.TRANSPORT_PROTOCOLS.
    static std::string merge_psiphon_transport(const std::string& json, int selection) {
        static const char* const kProtocols[] = {
            nullptr,                                                   // 0: Auto
            "SSH", "OSSH", "TLS-OSSH", "SHADOWSOCKS-OSSH", "QUIC-OSSH",
            "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
            "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            "FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH",
            "FRONTED-MEEK-QUIC-OSSH", "CONJURE-OSSH",
            "INPROXY-WEBRTC-SSH", "INPROXY-WEBRTC-OSSH",
            "INPROXY-WEBRTC-TLS-OSSH", "INPROXY-WEBRTC-SHADOWSOCKS-OSSH",
            "INPROXY-WEBRTC-QUIC-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH",
        };
        if (selection <= 0 || selection >= (int)(sizeof(kProtocols) / sizeof(kProtocols[0])))
            return json;
        if (json.find("\"LimitTunnelProtocols\"") != std::string::npos) return json;
        size_t close = json.find_last_of('}');
        if (close == std::string::npos) return json;
        std::string out = json.substr(0, close);
        while (!out.empty() && (out.back() == ' ' || out.back() == '\n' ||
                                out.back() == '\r' || out.back() == '\t')) out.pop_back();
        if (!out.empty() && out.back() == ',') out.pop_back();
        return out + ",\"LimitTunnelProtocols\":[\"" + kProtocols[selection] + "\"]}";
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
#if defined(ANDROID)
void ui_release_view();
#endif
void render_ui();
void log_callback(FcaeLogLevel level, const char* message, void* user_data);

// A frame is painted only when its content fingerprint changed, on input, or
// while something animates (spinner, animated sponsor card, caret). Platform
// main loops call ui_should_render() before each frame and wait for
// ui_sleep_ms() in between.

/// Should the platform paint a frame now?
/// Polls telemetry and sponsor state when due and returns true when the
/// painted content would differ, for a pending redraw request, a running
/// connect spinner, or while `interacting` is true.
bool ui_should_render(bool interacting);
void ui_autosave_tick();

// Implemented by each desktop renderer (OpenGL or DX11).
ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot);

/// How long (ms) the platform waits before calling ui_should_render() again:
/// one 30 FPS frame while animating, longer when idle or unfocused.
unsigned ui_sleep_ms();

/// Request one extra repaint (call from window event handlers).
void ui_request_redraw();
/// Register the platform window a redraw request must wake (nullptr clears it).
void ui_set_window_handle(void* window);
/// Act on a pending elevation hand-off; called by the frame loop.
void ui_handoff_tick();

/// Bookkeeping after a frame was actually painted. Called by ui_frame().
void ui_note_frame_drawn();

/// Tell the sponsor audio layer whether the native desktop window is visible.
/// Minimized/hidden windows must not keep media audio alive.
void ui_set_window_visible(bool visible);

/// Whether the native window has keyboard focus; unfocused windows poll less.
void ui_set_window_focused(bool focused);

/// Monotonic clock in seconds, shared by the telemetry poll and the render gate.
double ui_now_seconds();
