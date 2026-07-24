// FCAE VPN — Android JNI bridge (Kotlin UI controls the in-process engine)
#include <jni.h>
#include <android/log.h>
#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>

#include "../include/aether_ffi.h"

#define LOG_TAG "FCAE_VPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static std::mutex g_log_mu;
static std::deque<std::string> g_logs;
static constexpr size_t kMaxLogs = 30;
static std::atomic<bool> g_inited{false};

static void jni_log_cb(int level, const char* message, void* /*user*/) {
    if (!message) return;
    std::lock_guard<std::mutex> lock(g_log_mu);
    char prefix = 'I';
    if (level == 1) prefix = 'E';
    else if (level == 2) prefix = 'W';
    else if (level == 4) prefix = 'D';
    std::string line;
    line.push_back(prefix);
    line += " ";
    line += message;
    g_logs.push_back(std::move(line));
    while (g_logs.size() > kMaxLogs) {
        g_logs.pop_front();
    }
    if (level <= 2) {
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "%s", message);
    } else {
        LOGI("%s", message);
    }
}

static void ensure_init() {
    if (g_inited) return;
    aether_init(jni_log_cb, nullptr);
    g_inited = true;
    LOGI("aether_init via JNI");
}

static std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return {};
    const char* p = env->GetStringUTFChars(s, nullptr);
    if (!p) return {};
    std::string out(p);
    env->ReleaseStringUTFChars(s, p);
    return out;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeInit(JNIEnv*, jclass) {
    ensure_init();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeStart(
    JNIEnv* env,
    jclass,
    jint protocol,
    jint mode,
    jboolean lanSharing,
    jint scanMode,
    jint ipVersion,
    jboolean quickReconnect,
    jstring noizeProfile,
    jboolean fragmentEnabled,
    jint fragMinSize,
    jint fragMaxSize,
    jint fragMinDelay,
    jint fragMaxDelay,
    jint socksPort,
    jint httpPort,
    jstring forcePeer,
    jstring configPath,
    jboolean h2Enabled,
    jboolean echEnabled,
    jstring sni,
    jboolean ironcladValidate,
    jint healthIntervalSecs,
    jint healthMaxFails,
    jint healthTimeoutSecs,
    jint liveValidateSecs
) {
    ensure_init();

    std::string noizeOwned = jstr(env, noizeProfile);
    if (noizeOwned.empty()) noizeOwned = "balanced";
    std::string peerOwned = jstr(env, forcePeer);
    std::string cfgOwned = jstr(env, configPath);
    if (cfgOwned.empty()) cfgOwned = "aether.toml";
    std::string sniOwned = jstr(env, sni);

    AetherConfig cfg = {};
    cfg.protocol = protocol;
    cfg.mode = (AetherMode)mode;
    cfg.lan_sharing = lanSharing == JNI_TRUE;
    cfg.scan_mode = scanMode;
    cfg.ip_version = ipVersion;
    cfg.quick_reconnect = quickReconnect == JNI_TRUE;
    cfg.noize_profile = noizeOwned.c_str();
    cfg.fragment_enabled = fragmentEnabled == JNI_TRUE;
    cfg.frag_min_size = (uint32_t)fragMinSize;
    cfg.frag_max_size = (uint32_t)fragMaxSize;
    cfg.frag_min_delay = (uint32_t)fragMinDelay;
    cfg.frag_max_delay = (uint32_t)fragMaxDelay;
    cfg.socks_port = (uint16_t)socksPort;
    cfg.http_port = (uint16_t)httpPort;
    cfg.force_peer = peerOwned.empty() ? nullptr : peerOwned.c_str();
    cfg.config_path = cfgOwned.c_str();
    cfg.h2_enabled = h2Enabled == JNI_TRUE;
    cfg.ech_enabled = echEnabled == JNI_TRUE;
    cfg.sni = sniOwned.empty() ? nullptr : sniOwned.c_str();
    cfg.ironclad_validate = ironcladValidate == JNI_TRUE;
    cfg.health_interval_secs = healthIntervalSecs > 0 ? (uint32_t)healthIntervalSecs : 0;
    cfg.health_max_fails = healthMaxFails > 0 ? (uint32_t)healthMaxFails : 0;
    cfg.health_timeout_secs = healthTimeoutSecs > 0 ? (uint32_t)healthTimeoutSecs : 0;
    cfg.live_validate_secs = liveValidateSecs > 0 ? (uint32_t)liveValidateSecs : 0;

    bool ok = aether_start(&cfg);
    LOGI("aether_start -> %s", ok ? "ok" : "fail");
    return ok ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeStop(JNIEnv*, jclass) {
    if (!g_inited) return;
    // aether_stop() is non-blocking: sets shutdown flag, closes TUN fds,
    // updates telemetry.  Safe to call from any thread.
    aether_stop();
    LOGI("aether_stop");
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeFree(JNIEnv*, jclass) {
    if (!g_inited) return;
    // aether_free() joins the engine thread and tears down the FFI layer.
    // Must NOT be called while nativeStop() is running on another thread
    // (the core STOP_GUARD prevents concurrent stop+free).
    aether_free();
    g_inited = false;
    LOGI("aether_free");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetStatusJson(JNIEnv* env, jclass) {
    ensure_init();
    AetherTelemetry t = {};
    aether_get_telemetry(&t);

    char buf[768];
    snprintf(buf, sizeof(buf),
        "{\"state\":%u,\"rtt\":%u,\"rx\":%llu,\"tx\":%llu,\"totalRx\":%llu,\"totalTx\":%llu,"
        "\"peer\":\"%s\",\"lan\":\"%s\",\"status\":\"%s\",\"error\":\"%s\"}",
        (unsigned)t.state,
        (unsigned)t.rtt_ms,
        (unsigned long long)t.rx_bytes_sec,
        (unsigned long long)t.tx_bytes_sec,
        (unsigned long long)t.total_rx,
        (unsigned long long)t.total_tx,
        t.connected_peer[0] ? t.connected_peer : "",
        t.lan_ip[0] ? t.lan_ip : "",
        t.status_message[0] ? t.status_message : "",
        t.last_error[0] ? t.last_error : ""
    );
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetLogs(JNIEnv* env, jclass) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::string all;
    all.reserve(g_logs.size() * 64);
    for (const auto& l : g_logs) {
        all += l;
        all.push_back('\n');
    }
    return env->NewStringUTF(all.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeClearLogs(JNIEnv*, jclass) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    g_logs.clear();
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeSetTunFd(JNIEnv*, jclass, jint fd) {
    ensure_init();
    aether_set_android_tun_fd((int)fd);
    LOGI("TUN fd %d", (int)fd);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeGetTrafficStats(JNIEnv* env, jclass) {
    ensure_init();
    AetherTelemetry telem = {};
    // Use cached rates so we don't steal window data from the UI poll.
    aether_get_cached_telemetry(&telem);
    // [0]=rx bytes/sec, [1]=tx bytes/sec, [2]=exact cumulative rx bytes,
    // [3]=exact cumulative tx bytes.
    jlongArray out = env->NewLongArray(4);
    if (!out) return nullptr;
    jlong vals[4] = {
        (jlong)telem.rx_bytes_sec,
        (jlong)telem.tx_bytes_sec,
        (jlong)telem.total_rx,
        (jlong)telem.total_tx
    };
    env->SetLongArrayRegion(out, 0, 4, vals);
    return out;
}
