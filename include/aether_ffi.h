#ifndef AETHER_FFI_H
#define AETHER_FFI_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AETHER_STATE_DISCONNECTED = 0,
    AETHER_STATE_PROVISIONING = 1,
    AETHER_STATE_SCANNING     = 2,
    AETHER_STATE_CONNECTING   = 3,
    AETHER_STATE_CONNECTED    = 4,
    AETHER_STATE_ERROR        = 5
} AetherState;

typedef enum {
    AETHER_MODE_PROXY = 0,
    AETHER_MODE_TUN   = 1
} AetherMode;

typedef struct {
    int protocol;             // 0 = MASQUE (HTTP/3 QUIC), 1 = WireGuard, 2 = WARP-in-WARP (Gool)
    AetherMode mode;          // 0 = Proxy Mode, 1 = TUN Mode
    bool lan_sharing;         // false = bind 127.0.0.1, true = bind 0.0.0.0 & show LAN IP
    int scan_mode;            // 0 = Turbo, 1 = Balanced, 2 = Thorough, 3 = Stealth, 4 = Ironclad
    int ip_version;           // 4 = IPv4, 6 = IPv6, 10 = Dual-Stack (scan + DNS preference)
    bool quick_reconnect;     // Use cached known-good gateway if verified

    // Obfuscation & Fragmentation
    const char* noize_profile;// "off", "firewall", "balanced", "gfw"
    bool fragment_enabled;    // TLS ClientHello fragmentation on HTTP/2 fallback
    uint32_t frag_min_size;   // Default: 16
    uint32_t frag_max_size;   // Default: 32
    uint32_t frag_min_delay;  // Default: 2 (ms)
    uint32_t frag_max_delay;  // Default: 10 (ms)

    uint16_t socks_port;      // Default: 1819
    uint16_t http_port;       // Default: 1820
    const char* force_peer;   // NULL or "ip:port"
    const char* config_path;  // Base config path (e.g., "aether.toml")
    bool h2_enabled;          // MASQUE over HTTP/2 (AETHER_MASQUE_HTTP2)
    bool ech_enabled;         // Encrypted Client Hello (AETHER_ECH=auto)

    // DNS / TLS (optional; NULL or empty = defaults)
    const char* dns_server;   // e.g. "1.1.1.1:53" or "8.8.8.8"
    int dns_mode;             // 0 = UDP classic, 1 = DoH (HTTPS)
    const char* doh_url;      // e.g. "https://cloudflare-dns.com/dns-query"
    int dns_ip_prefer;        // 0 = follow ip_version, 4 = A only, 6 = AAAA only, 10 = dual (AAAA then A)
    const char* tls_groups;   // e.g. "P-256:X25519:P-384" (BoringSSL curves list)
    uint32_t udp_buf_kb;      // UDP socket buffer size in KiB (0 = default 512)
    const char* sni;          // TLS Server Name for MASQUE (NULL = default consumer-masque...)

    // Validation & tunnel health (0 / NULL = engine defaults)
    bool ironclad_validate;       // post-scan real HTTP validation on top candidates
    uint32_t health_interval_secs; // background probe interval (default 20)
    uint32_t health_max_fails;     // consecutive fails before reconnect (default 2)
    uint32_t health_timeout_secs;  // per health probe timeout (default 5)
    uint32_t live_validate_secs;   // pre-SOCKS live validation timeout (default 20)
} AetherConfig;

typedef struct {
    AetherState state;
    AetherMode active_mode;
    bool lan_enabled;
    uint32_t rtt_ms;
    uint64_t rx_bytes_sec;
    uint64_t tx_bytes_sec;
    uint64_t total_rx;
    uint64_t total_tx;
    char connected_peer[64];
    char lan_ip[64];          // Discovered LAN IP (e.g., "192.168.1.100") or "127.0.0.1"
    char status_message[128];
    char last_error[256];
} AetherTelemetry;

typedef void (*AetherLogCallback)(int level, const char* message, void* user_data);

// C-FFI Lifecycle & Controller API
void aether_init(AetherLogCallback log_cb, void* user_data);
bool aether_start(const AetherConfig* config);
void aether_stop(void);
void aether_get_telemetry(AetherTelemetry* out_telemetry);
void aether_set_android_tun_fd(int tun_fd); // Pass Android VpnService file descriptor across JNI
void aether_free(void);

#ifdef __cplusplus
}
#endif

#endif // AETHER_FFI_H
