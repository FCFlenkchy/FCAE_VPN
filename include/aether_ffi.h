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
    int ip_version;           // 4 = IPv4, 6 = IPv6, 10 = Dual-Stack
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
