// FCAE VPN — Android JNI bridge (Kotlin UI controls the in-process engine)
#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../include/aether_ffi.h"

#define LOG_TAG "FCAE_VPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static std::mutex g_log_mu;
static std::vector<std::string> g_logs;
static constexpr size_t kMaxLogs = 120;
static bool g_inited = false;

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
    if (g_logs.size() > kMaxLogs) {
        g_logs.erase(g_logs.begin(), g_logs.begin() + (g_logs.size() - kMaxLogs));
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
    jboolean echEnabled
) {
    ensure_init();

    const char* noize = "balanced";
    std::string noizeOwned;
    if (noizeProfile) {
        const char* p = env->GetStringUTFChars(noizeProfile, nullptr);
        if (p) {
            noizeOwned = p;
            noize = noizeOwned.c_str();
            env->ReleaseStringUTFChars(noizeProfile, p);
        }
    }

    std::string peerOwned;
    const char* peer = nullptr;
    if (forcePeer) {
        const char* p = env->GetStringUTFChars(forcePeer, nullptr);
        if (p && p[0]) {
            peerOwned = p;
            peer = peerOwned.c_str();
        }
        if (p) env->ReleaseStringUTFChars(forcePeer, p);
    }

    std::string cfgOwned = "aether.toml";
    if (configPath) {
        const char* p = env->GetStringUTFChars(configPath, nullptr);
        if (p && p[0]) cfgOwned = p;
        if (p) env->ReleaseStringUTFChars(configPath, p);
    }

    AetherConfig cfg = {};
    cfg.protocol = protocol;
    cfg.mode = (AetherMode)mode;
    cfg.lan_sharing = lanSharing == JNI_TRUE;
    cfg.scan_mode = scanMode;
    cfg.ip_version = ipVersion;
    cfg.quick_reconnect = quickReconnect == JNI_TRUE;
    cfg.noize_profile = noize;
    cfg.fragment_enabled = fragmentEnabled == JNI_TRUE;
    cfg.frag_min_size = (uint32_t)fragMinSize;
    cfg.frag_max_size = (uint32_t)fragMaxSize;
    cfg.frag_min_delay = (uint32_t)fragMinDelay;
    cfg.frag_max_delay = (uint32_t)fragMaxDelay;
    cfg.socks_port = (uint16_t)socksPort;
    cfg.http_port = (uint16_t)httpPort;
    cfg.force_peer = peer;
    cfg.config_path = cfgOwned.c_str();
    cfg.h2_enabled = h2Enabled == JNI_TRUE;
    cfg.ech_enabled = echEnabled == JNI_TRUE;

    bool ok = aether_start(&cfg);
    LOGI("aether_start -> %s", ok ? "ok" : "fail");
    return ok ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeStop(JNIEnv*, jclass) {
    ensure_init();
    aether_stop();
    LOGI("aether_stop");
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
    // crude escape: strip quotes inside strings already avoided by using empty or simple text
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

// Service helpers (same library)
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
    aether_get_telemetry(&telem);
    jlongArray out = env->NewLongArray(2);
    if (!out) return nullptr;
    jlong vals[2] = {(jlong)telem.rx_bytes_sec, (jlong)telem.tx_bytes_sec};
    env->SetLongArrayRegion(out, 0, 2, vals);
    return out;
}
