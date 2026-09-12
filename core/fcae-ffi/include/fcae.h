/*
 * fcae.h — FCAE VPN public C ABI
 *
 * Generated from core/fcae-ffi/abi/src/lib.rs. Regenerate with:
 *     cargo install cbindgen
 *     cbindgen --lang c --crate fcae-abi --output core/fcae-ffi/include/fcae.h
 * (the build script does this automatically when cbindgen is installed;
 *  CI verifies the fingerprint at the bottom of this file).
 *
 * Usage sketch:
 *
 *     FcaeInitOptions opt = {0};
 *     opt.struct_size   = sizeof opt;
 *     opt.abi_version   = FCAE_ABI_VERSION;
 *     opt.log_cb        = on_log;
 *     opt.max_log_level = FCAE_LOG_INFO;
 *     fcae_init(&opt);
 *
 *     FcaeConfig cfg;
 *     fcae_config_default(&cfg);      // always start here
 *     cfg.mode       = FCAE_MODE_TUN;
 *     cfg.socks_port = 1819;
 *     if (fcae_start(&cfg) != FCAE_OK)
 *         fprintf(stderr, "%s\n", fcae_last_error());
 *
 *     FcaeTelemetry t = {0};
 *     t.struct_size = sizeof t;
 *     t.abi_version = FCAE_ABI_VERSION;
 *     fcae_get_telemetry(&t);
 *
 *     fcae_stop();
 *     fcae_shutdown();
 */

#ifndef FCAE_H
#define FCAE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bumped on ANY layout change. Compare with fcae_abi_version() at runtime. */
#define FCAE_ABI_VERSION 5

/* ── Enumerations ──────────────────────────────────────────────────── */

typedef enum {
    FCAE_STATE_DISCONNECTED = 0,
    FCAE_STATE_PROVISIONING = 1,
    FCAE_STATE_SCANNING     = 2,
    FCAE_STATE_CONNECTING   = 3,
    FCAE_STATE_CONNECTED    = 4,
    FCAE_STATE_ERROR        = 5,
    FCAE_STATE_RECONNECTING = 6
} FcaeState;

typedef enum {
    FCAE_BACKEND_AETHER  = 0,
    FCAE_BACKEND_PSIPHON = 1
} FcaeBackend;

/* What a backend supports, so the UI can describe it rather than hardcoding
 * per-backend behaviour.
 *
 * fcae_available_backends() returns bare ids, which cannot express "compiled
 * in but a stub" (Psiphon without psiphon-live) or "ignores scan modes".
 * Iterate fcae_backend_count() and fill one of these per index. */
typedef struct {
    uint32_t        struct_size;
    uint32_t        abi_version;

    FcaeBackend     backend;
    char            id[32];                  /* "aether", "psiphon"        */
    char            display_name[64];        /* for a menu entry           */

    bool            available;               /* registered AND can start   */
    char            unavailable_reason[192]; /* empty when available       */

    bool            supports_socks;
    bool            supports_http_proxy;
    bool            supports_gateway_scanning; /* false for Psiphon        */
    bool            supports_routing_rules;
    bool            requires_privileges;

    uint64_t        _reserved[4];
} FcaeBackendInfo;

typedef enum {
    FCAE_PROTOCOL_MASQUE    = 0,
    FCAE_PROTOCOL_WIREGUARD = 1,
    FCAE_PROTOCOL_GOOL      = 2,
    FCAE_PROTOCOL_AUTO      = 3
} FcaeProtocol;

typedef enum {
    FCAE_MODE_PROXY = 0,
    FCAE_MODE_TUN   = 1
} FcaeMode;

/* Verbosity of the AETHER ENGINE's own logging (AETHER_LOG_LEVEL).
 *
 * Distinct from FcaeLogLevel, which filters what the FFI hands to the host
 * log callback. The FFI itself needs no knob (it always reports at info);
 * the engine is chatty, so its level is exposed. */
typedef enum {
    FCAE_ENGINE_LOG_OFF   = 0,
    FCAE_ENGINE_LOG_ERROR = 1,
    FCAE_ENGINE_LOG_WARN  = 2,
    FCAE_ENGINE_LOG_INFO  = 3,   /* default                                */
    FCAE_ENGINE_LOG_DEBUG = 4,
    FCAE_ENGINE_LOG_TRACE = 5
} FcaeEngineLog;

/* Tor egress, mirroring the engine's own AETHER_TOR modes. Tor lives INSIDE
 * the Aether engine -- it is not a separate backend. */
typedef enum {
    FCAE_TOR_OFF     = 0,
    FCAE_TOR_CHAIN   = 1,  /* tunnel -> tor -> internet                     */
    FCAE_TOR_REVERSE = 2,  /* tor -> tunnel -> internet (MASQUE only)       */
    FCAE_TOR_ONLY    = 3   /* tor alone, no WARP tunnel                     */
} FcaeTorMode;

typedef enum {
    FCAE_TOR_BRIDGES_NONE      = 0,
    FCAE_TOR_BRIDGES_OBFS4     = 1,
    FCAE_TOR_BRIDGES_SNOWFLAKE = 2,
    FCAE_TOR_BRIDGES_CUSTOM    = 3   /* use FcaeTor.bridge_lines            */
} FcaeTorBridges;

typedef enum {
    FCAE_SCAN_TURBO     = 0,
    FCAE_SCAN_BALANCED  = 1,
    FCAE_SCAN_THOROUGH  = 2,
    FCAE_SCAN_STEALTH   = 3,
    FCAE_SCAN_IRONCLAD  = 4
} FcaeScanMode;

typedef enum {
    FCAE_IP_V4   = 4,
    FCAE_IP_V6   = 6,
    FCAE_IP_DUAL = 10
} FcaeIpVersion;

typedef enum {
    FCAE_DNS_UDP = 0,
    FCAE_DNS_DOH = 1
} FcaeDnsMode;

typedef enum {
    FCAE_PROFILE_AUTO   = 0,
    FCAE_PROFILE_LOW    = 1,
    FCAE_PROFILE_MEDIUM = 2,
    FCAE_PROFILE_HIGH   = 3
} FcaeSysProfile;

typedef enum {
    FCAE_LOG_ERROR = 1,
    FCAE_LOG_WARN  = 2,
    FCAE_LOG_INFO  = 3,
    FCAE_LOG_DEBUG = 4
} FcaeLogLevel;

/* Return code for every fallible call. Detail via fcae_last_error(). */
typedef enum {
    FCAE_OK                   = 0,
    FCAE_NOT_INITIALIZED      = 1,
    FCAE_ALREADY_RUNNING      = 2,
    FCAE_NULL_ARGUMENT        = 3,
    FCAE_ABI_MISMATCH         = 4,
    FCAE_INVALID_CONFIG       = 5,
    FCAE_BACKEND_UNAVAILABLE  = 6,
    FCAE_PERMISSION_DENIED    = 7,
    FCAE_START_FAILED         = 8,
    FCAE_TIMEOUT              = 9,
    FCAE_INTERNAL             = 10
} FcaeStatus;

/* ── Configuration ─────────────────────────────────────────────────── */

typedef struct {
    const char *noize_profile;   /* "off"|"light"|"balanced"|"aggressive"  */
    bool        fragment_enabled;
    uint32_t    frag_min_size;
    uint32_t    frag_max_size;
    uint32_t    frag_min_delay_ms;
    uint32_t    frag_max_delay_ms;
    bool        h2_enabled;      /* MASQUE over HTTP/2                     */
    bool        ech_enabled;     /* Encrypted Client Hello                 */
} FcaeObfuscation;

typedef struct {
    const char    *server;       /* "1.1.1.1:53"; NULL = default           */
    FcaeDnsMode    mode;
    const char    *doh_url;      /* required when mode == FCAE_DNS_DOH     */
    FcaeIpVersion  ip_prefer;
    const char    *tls_groups;   /* "P-256:X25519:P-384"                   */
    const char    *sni;
} FcaeDnsConfig;

typedef struct {
    const char *rules_file;
    const char *rules_inline;    /* "[direct]a,b [block]c"                 */
} FcaeRouting;

typedef struct {
    const char *team_name;
    const char *access_token;
    const char *access_email;
} FcaeZeroTrust;

/* Reserved for the Psiphon backend; ignored by other backends. */
typedef struct {
    const char *config_json;
    const char *embedded_server_list;
    const char *egress_region;
    const char *data_root_dir;
} FcaePsiphon;

/* Tor egress configuration. Consumed by the Aether backend only. */
typedef struct {
    FcaeTorMode     mode;
    FcaeTorBridges  bridges;
    const char     *bind;          /* NULL = 127.0.0.1:1820                */
    const char     *state_dir;     /* NULL = under data_dir                */
    const char     *bridge_lines;  /* newline-separated, for CUSTOM        */
    const char     *pt_path;       /* pluggable transport binary, or NULL  */
} FcaeTor;

typedef struct {
    uint32_t        struct_size;   /* = sizeof(FcaeConfig)                 */
    uint32_t        abi_version;   /* = FCAE_ABI_VERSION                   */

    FcaeBackend     backend;
    FcaeProtocol    protocol;
    FcaeMode        mode;
    FcaeScanMode    scan_mode;
    FcaeIpVersion   ip_version;
    FcaeSysProfile  sys_profile;

    bool            lan_sharing;
    bool            quick_reconnect;
    uint16_t        socks_port;    /* 0 disables (TUN forces an internal)  */
    uint16_t        http_port;     /* 0 disables; must differ from socks   */
    const char     *force_peer;    /* "ip:port" or NULL to scan            */
    const char     *config_path;
    const char     *data_dir;
    uint32_t        udp_buf_kb;    /* 64..8192, or 0 for default           */
    FcaeEngineLog   engine_log;   /* engine verbosity; default INFO       */

    FcaeObfuscation obfuscation;
    FcaeDnsConfig   dns;
    FcaeRouting     routing;
    FcaeZeroTrust   zero_trust;
    FcaePsiphon     psiphon;
    FcaeTor         tor;

    const char     *tun_name;      /* NULL = "FCAE_VPN"                    */
    uint32_t        tun_mtu;       /* 576..9000, or 0 for 1500             */
    int32_t         tun_fd;        /* Android VpnService fd, else -1       */

    uint64_t        _reserved[4];
} FcaeConfig;

/* ── Telemetry ─────────────────────────────────────────────────────── */

typedef struct {
    uint32_t    struct_size;
    uint32_t    abi_version;

    FcaeState   state;
    FcaeBackend backend;
    FcaeMode    active_mode;
    bool        lan_enabled;

    uint32_t    rtt_ms;
    uint64_t    rx_bytes_sec;
    uint64_t    tx_bytes_sec;
    uint64_t    total_rx;
    uint64_t    total_tx;
    uint64_t    uptime_secs;
    uint32_t    reconnect_count;

    char        connected_peer[64];
    char        lan_ip[64];
    char        status_message[128];
    char        last_error[256];

    uint64_t    _reserved[4];
} FcaeTelemetry;

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    bool     update_available;
    bool     check_in_progress;
    bool     check_done;
    bool     is_prerelease;
    char     latest_version[32];
    char     release_date[32];
    char     release_notes[1024];
    char     download_url[512];
    char     status_message[256];
} FcaeUpdateInfo;

/* ── Callbacks ─────────────────────────────────────────────────────── */

/* Invoked from arbitrary threads; `message` is only valid for the call. */
typedef void (*FcaeLogCallback)(FcaeLogLevel level, const char *message, void *user_data);

/* Invoked on every state transition, from arbitrary threads. */
typedef void (*FcaeStateCallback)(FcaeState state, void *user_data);

typedef struct {
    uint32_t          struct_size;
    uint32_t          abi_version;
    FcaeLogCallback   log_cb;
    FcaeStateCallback state_cb;       /* optional; NULL to poll instead    */
    void             *user_data;      /* must outlive the library          */
    FcaeLogLevel      max_log_level;
    const char       *native_lib_dir; /* Android; optional                 */
    uint64_t          _reserved[4];
} FcaeInitOptions;

/* ── API ───────────────────────────────────────────────────────────── */

/* Fill `out` with defaults and the correct struct_size/abi_version.
 * Always use this instead of zeroing a FcaeConfig yourself. */
FcaeStatus fcae_config_default(FcaeConfig *out);

/* Initialise the library. Idempotent. */
FcaeStatus fcae_init(const FcaeInitOptions *options);

/* Start a session. Returns once the worker is spawned; poll telemetry
 * (or use state_cb) for progress. */
FcaeStatus fcae_start(const FcaeConfig *config);

/* Stop the session. Blocks until the TUN device is down and routes/DNS
 * have been restored. */
FcaeStatus fcae_stop(void);

bool       fcae_is_running(void);

/* `out->struct_size` and `out->abi_version` must be set before calling. */
FcaeStatus fcae_get_telemetry(FcaeTelemetry *out);

/* Android: hand over the VpnService descriptor. The library dups it and
 * closes only its own copy, so ParcelFileDescriptor stays the owner. */
FcaeStatus fcae_set_tun_fd(int32_t fd);

/* True if the process can create a TUN device (admin/root). */
bool       fcae_is_privileged(void);

/* Message for the last failing call. Owned by the library; valid until
 * the next failing call. Never NULL. */
const char *fcae_last_error(void);

/* ABI version this binary was built with. */
uint32_t   fcae_abi_version(void);

/* Writes up to `max` compiled-in backend ids into `out`; returns the
 * total count. Pass NULL/0 to query the count only. */
uint32_t   fcae_available_backends(FcaeBackend *out, uint32_t max);

/* Describe backend `index` (0 .. fcae_backend_count()-1). Call after
 * fcae_init(): backends register during init. Returns FCAE_INVALID_CONFIG if
 * the index is out of range. */
FcaeStatus fcae_backend_info(uint32_t index, FcaeBackendInfo *out);

/* How many backends fcae_backend_info() can describe. */
uint32_t   fcae_backend_count(void);

/* Release everything. fcae_init() must be called again afterwards. */
FcaeStatus fcae_shutdown(void);

/* ── Update checking ───────────────────────────────────────────────── */

/* Start an async check; poll with fcae_poll_update(). No-op if one is
 * already running. */
FcaeStatus fcae_check_update_async(const char *current_version,
                                   bool include_prereleases);

/* Evaluate a manifest the host fetched itself (Android does its HTTP in
 * Kotlin, where DNS is reliable). */
FcaeStatus fcae_check_update_from_json(const char *current_version,
                                       const char *json,
                                       bool include_prereleases);

/* FCAE_OK once a check has finished (successfully or not);
 * FCAE_TIMEOUT while one is still in flight.
 * `out->struct_size` and `out->abi_version` must be set before calling. */
FcaeStatus fcae_poll_update(FcaeUpdateInfo *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FCAE_H */

/* fcae-abi-fingerprint: 0xed18462b5ae255d1 */
