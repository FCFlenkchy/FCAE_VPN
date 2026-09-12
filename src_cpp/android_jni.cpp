// FCAE VPN — Android JNI bridge (Kotlin UI controls the in-process engine)
#include <jni.h>
#include <android/log.h>
#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>

#include "fcae.h"

#define LOG_TAG "FCAE_VPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static std::mutex g_log_mu;
static std::deque<std::string> g_logs;
static constexpr size_t kMaxLogs = 30;
static std::atomic<bool> g_inited{false};

// ── Psiphon socket protection ───────────────────────────────────────────
//
// Psiphon dials out while our TUN is up, so every socket it opens must be
// excluded from the VPN via VpnService.protect(fd) or it tries to reach the
// internet through our own tunnel and never connects.
//
// The callback arrives on a Go goroutine with no JNIEnv, so the VM pointer is
// cached at JNI_OnLoad and the thread is attached on demand.
static JavaVM*  g_vm = nullptr;
static jobject  g_vpn_service = nullptr;   // global ref to the VpnService
static jmethodID g_protect_mid = nullptr;
static std::mutex g_protect_mu;

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

// Returns 1 on success, 0 on failure, matching the C ABI's contract.
static int psiphon_protect(int fd) {
    std::lock_guard<std::mutex> lock(g_protect_mu);
    if (!g_vm || !g_vpn_service || !g_protect_mid) {
        // No service registered (desktop-style run, or called after
        // teardown). Report success: there is no VPN to escape from.
        return 1;
    }

    JNIEnv* env = nullptr;
    bool attached = false;
    if (g_vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            LOGE("psiphon_protect: could not attach thread");
            return 0;
        }
        attached = true;
    }

    jboolean ok = env->CallBooleanMethod(g_vpn_service, g_protect_mid, (jint)fd);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        ok = JNI_FALSE;
    }

    if (attached) {
        g_vm->DetachCurrentThread();
    }
    return ok == JNI_TRUE ? 1 : 0;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeRegisterVpnService(JNIEnv* env, jobject thiz) {
    std::lock_guard<std::mutex> lock(g_protect_mu);
    if (g_vpn_service) {
        env->DeleteGlobalRef(g_vpn_service);
        g_vpn_service = nullptr;
    }
    g_vpn_service = env->NewGlobalRef(thiz);
    jclass cls = env->GetObjectClass(thiz);
    // VpnService.protect(int) -> boolean
    g_protect_mid = env->GetMethodID(cls, "protect", "(I)Z");
    env->DeleteLocalRef(cls);
    if (!g_protect_mid) {
        env->ExceptionClear();
        LOGE("could not resolve VpnService.protect(int)");
        return;
    }
    fcae_set_psiphon_protect(psiphon_protect);
    LOGI("psiphon socket protection registered");
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeUnregisterVpnService(JNIEnv* env, jclass) {
    fcae_set_psiphon_protect(nullptr);
    std::lock_guard<std::mutex> lock(g_protect_mu);
    if (g_vpn_service) {
        env->DeleteGlobalRef(g_vpn_service);
        g_vpn_service = nullptr;
    }
    g_protect_mid = nullptr;
}

static void jni_log_cb(FcaeLogLevel level, const char* message, void* /*user*/) {
    if (!message) return;
    std::lock_guard<std::mutex> lock(g_log_mu);
    char prefix = 'I';
    if (level == FCAE_LOG_ERROR) prefix = 'E';
    else if (level == FCAE_LOG_WARN) prefix = 'W';
    else if (level == FCAE_LOG_DEBUG) prefix = 'D';
    std::string line;
    line.push_back(prefix);
    line += " ";
    line += message;
    g_logs.push_back(std::move(line));
    while (g_logs.size() > kMaxLogs) {
        g_logs.pop_front();
    }
    if (level <= FCAE_LOG_WARN) {
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "%s", message);
    } else {
        LOGI("%s", message);
    }
}

// Re-initialises transparently after a previous fcae_shutdown().
//
// fcae_init() is itself re-entrant now (it re-attaches the log callback and
// state hook when the runtime already exists), so calling this after a
// shutdown genuinely revives the library rather than silently no-opping.
static void ensure_init() {
    if (g_inited) return;
    FcaeInitOptions opt = {};
    opt.struct_size   = sizeof(opt);
    opt.abi_version   = FCAE_ABI_VERSION;
    opt.log_cb        = jni_log_cb;
    opt.state_cb      = nullptr;
    opt.user_data     = nullptr;
    opt.max_log_level = FCAE_LOG_INFO;
    if (fcae_init(&opt) != FCAE_OK) {
        LOGE("fcae_init failed: %s", fcae_last_error());
        return;
    }
    g_inited = true;
    LOGI("fcae_init via JNI (abi v%u)", fcae_abi_version());
}

/// Read a telemetry snapshot.
///
/// The getters below used to each make their own FFI call, so one UI refresh
/// cost ten round-trips and could observe ten *different* snapshots — the
/// displayed RX and TX could come from different sampling windows. One call
/// per getter is still made (the JNI surface is per-field), but each now goes
/// through this single correctly-stamped helper.
static FcaeTelemetry telemetry_snapshot() {
    FcaeTelemetry t = {};
    t.struct_size = sizeof(t);
    t.abi_version = FCAE_ABI_VERSION;
    fcae_get_telemetry(&t);
    return t;
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

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeSetNativeLibDir(JNIEnv* env, jclass, jstring path) {
    std::string p = jstr(env, path);
    if (!p.empty()) {
        setenv("AETHER_NATIVE_LIB_DIR", p.c_str(), 1);
        LOGI("Native library dir set to %s", p.c_str());
    }
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
    jint sysProfile,
    jstring teamName,
    jstring accessToken,
    jstring accessEmail,
    jstring routesFile,
    jstring routesInline,
    jint torMode,
    jint torBridges,
    jstring torBridgeLines,
    jint engineLog,
    jint backend,
    jint torSocksPort,
    jstring psiphonConfig,
    jstring psiphonRegion,
    jint psiphonSocksPort,
    jint psiphonHttpPort
) {
    ensure_init();

    std::string noizeOwned = jstr(env, noizeProfile);
    if (noizeOwned.empty()) noizeOwned = "balanced";
    std::string peerOwned = jstr(env, forcePeer);
    std::string cfgOwned = jstr(env, configPath);
    if (cfgOwned.empty()) cfgOwned = "aether.toml";
    std::string sniOwned = jstr(env, sni);
    std::string teamOwned = jstr(env, teamName);
    std::string tokenOwned = jstr(env, accessToken);
    std::string emailOwned = jstr(env, accessEmail);
    std::string routesOwned = jstr(env, routesFile);
    std::string routesInlineOwned = jstr(env, routesInline);
    std::string torLinesOwned = jstr(env, torBridgeLines);
    std::string psiCfgOwned = jstr(env, psiphonConfig);
    std::string psiRegionOwned = jstr(env, psiphonRegion);

    FcaeConfig cfg;
    fcae_config_default(&cfg);

    cfg.backend = (FcaeBackend)backend;
    cfg.protocol = (FcaeProtocol)protocol;
    cfg.mode = (FcaeMode)mode;
    cfg.lan_sharing = lanSharing == JNI_TRUE;
    cfg.scan_mode = (FcaeScanMode)scanMode;
    cfg.ip_version = (FcaeIpVersion)ipVersion;
    cfg.quick_reconnect = quickReconnect == JNI_TRUE;
    cfg.socks_port = (uint16_t)socksPort;
    cfg.http_port = (uint16_t)httpPort;
    cfg.force_peer = peerOwned.empty() ? nullptr : peerOwned.c_str();
    cfg.config_path = cfgOwned.c_str();
    cfg.sys_profile = (FcaeSysProfile)sysProfile;

    cfg.obfuscation.noize_profile     = noizeOwned.c_str();
    cfg.obfuscation.fragment_enabled  = fragmentEnabled == JNI_TRUE;
    cfg.obfuscation.frag_min_size     = (uint32_t)fragMinSize;
    cfg.obfuscation.frag_max_size     = (uint32_t)fragMaxSize;
    cfg.obfuscation.frag_min_delay_ms = (uint32_t)fragMinDelay;
    cfg.obfuscation.frag_max_delay_ms = (uint32_t)fragMaxDelay;
    cfg.obfuscation.h2_enabled        = h2Enabled == JNI_TRUE;
    cfg.obfuscation.ech_enabled       = echEnabled == JNI_TRUE;

    cfg.dns.sni = sniOwned.empty() ? nullptr : sniOwned.c_str();

    cfg.zero_trust.team_name    = teamOwned.empty() ? nullptr : teamOwned.c_str();
    cfg.zero_trust.access_token = tokenOwned.empty() ? nullptr : tokenOwned.c_str();
    cfg.zero_trust.access_email = emailOwned.empty() ? nullptr : emailOwned.c_str();

    cfg.routing.rules_file   = routesOwned.empty() ? nullptr : routesOwned.c_str();
    cfg.routing.rules_inline = routesInlineOwned.empty() ? nullptr : routesInlineOwned.c_str();

    // Tor is an egress inside the Aether engine, not a separate backend, so
    // it rides along on the same config struct. The state dir is left NULL so
    // the core puts it under data_dir (app-private storage).
    cfg.tor.mode         = (FcaeTorMode)torMode;
    cfg.tor.bridges      = (FcaeTorBridges)torBridges;
    cfg.tor.bridge_lines = torLinesOwned.empty() ? nullptr : torLinesOwned.c_str();

    // Verbosity of the aether engine itself. The FFI's own log callback stays
    // at info regardless -- this only changes how much the engine emits.
    cfg.engine_log = (FcaeEngineLog)engineLog;

    // Tor's own listener, kept off the engine's and Psiphon's ports.
    cfg.tor.socks_port = (uint16_t)torSocksPort;

    // Psiphon. Its datastore must be writable and app-private; the Kotlin
    // side passes filesDir, which is exactly that.
    if (!psiCfgOwned.empty()) cfg.psiphon.config_json = psiCfgOwned.c_str();
    if (!psiRegionOwned.empty()) cfg.psiphon.egress_region = psiRegionOwned.c_str();
    cfg.psiphon.socks_port = (uint16_t)psiphonSocksPort;
    cfg.psiphon.http_port = (uint16_t)psiphonHttpPort;

    // The data directory is a real config field now, not a smuggled env var.
    std::string dataDir;
    std::string psiDataDir;
    if (!cfgOwned.empty()) {
        size_t last_slash = cfgOwned.find_last_of('/');
        if (last_slash != std::string::npos) {
            dataDir = cfgOwned.substr(0, last_slash);
            cfg.data_dir = dataDir.c_str();
            // Psiphon keeps its own datastore; give it a subdirectory of the
            // app-private dir rather than sharing the engine's.
            psiDataDir = dataDir + "/psiphon";
            cfg.psiphon.data_root_dir = psiDataDir.c_str();
        }
    }

    // The VpnService fd was handed over by nativeSetTunFd; passing -1 here
    // keeps the value the bridge already holds.
    cfg.tun_fd = -1;

    // The MTU must match the one FCAEVpnService.Builder.setMtu() used when it
    // established the interface. Leaving it at 0 let the core default to 1500
    // independently of whatever the Builder picked: when the two disagreed,
    // gVisor built segments the interface silently dropped, so the tunnel came
    // up and passed no traffic. Keep this in sync with kVpnServiceMtu in
    // FCAEVpnService.java.
    cfg.tun_mtu = (cfg.mode == FCAE_MODE_TUN) ? 1500 : 0;

    FcaeStatus st = fcae_start(&cfg);
    if (st != FCAE_OK) {
        LOGE("fcae_start failed (%d): %s", (int)st, fcae_last_error());
        return JNI_FALSE;
    }
    LOGI("fcae_start -> ok");
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeStop(JNIEnv*, jclass) {
    if (!g_inited) return;
    // fcae_stop() is synchronous: the TUN device is released and the engine
    // threads are joined before it returns. On Android that means the
    // VpnService fd is free by the time Java tears the service down.
    if (fcae_stop() != FCAE_OK) {
        LOGE("fcae_stop: %s", fcae_last_error());
    }
    LOGI("fcae_stop");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativePsiphonRegions(JNIEnv* env, jclass) {
    ensure_init();
    // Empty until Psiphon has connected once: the region list arrives in a
    // post-handshake notice, so the UI offers "Auto" and refreshes later.
    char buf[1024] = {0};
    fcae_psiphon_regions(buf, (uint32_t)sizeof(buf));
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeStopBegin(JNIEnv*, jclass) {
    if (!g_inited) return;
    // Frees the TUN device and our dup of the VpnService fd right away; the
    // blocking join happens later in nativeStop().
    if (fcae_stop_begin() != FCAE_OK) {
        LOGE("fcae_stop_begin: %s", fcae_last_error());
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeFree(JNIEnv*, jclass) {
    if (!g_inited) return;
    // fcae_shutdown() stops any running session first, then releases the
    // library. Safe from the Java cleanup thread.
    fcae_shutdown();
    g_inited = false;
    LOGI("fcae_shutdown");
}

// ── Structured telemetry: individual getters replace the old JSON round-trip ──

extern "C" JNIEXPORT jint JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetState(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jint)t.state;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetRxBps(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jlong)t.rx_bytes_sec;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetTxBps(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jlong)t.tx_bytes_sec;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetTotalRx(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jlong)t.total_rx;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetTotalTx(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jlong)t.total_tx;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetRttMs(JNIEnv*, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return (jint)t.rtt_ms;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetPeer(JNIEnv* env, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return env->NewStringUTF(t.connected_peer[0] ? t.connected_peer : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetLanIp(JNIEnv* env, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return env->NewStringUTF(t.lan_ip[0] ? t.lan_ip : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetStatusMsg(JNIEnv* env, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return env->NewStringUTF(t.status_message[0] ? t.status_message : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeGetLastError(JNIEnv* env, jclass) {
    ensure_init();
    FcaeTelemetry t = telemetry_snapshot();
    return env->NewStringUTF(t.last_error[0] ? t.last_error : "");
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
    if (fcae_set_tun_fd((int)fd) != FCAE_OK) {
        LOGE("fcae_set_tun_fd: %s", fcae_last_error());
    }
    LOGI("TUN fd %d", (int)fd);
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeGetTrafficStats(JNIEnv* env, jclass) {
    ensure_init();
    // Live rates, so the notification keeps showing current data while the
    // app is backgrounded and the UI poll is stopped.
    FcaeTelemetry telem = telemetry_snapshot();
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

// ── Version checker JNI ──────────────────────────────────────────────────

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeCheckForUpdates(JNIEnv* env, jclass, jstring currentVersion, jboolean includePrereleases) {
    ensure_init();
    const char* ver = env->GetStringUTFChars(currentVersion, nullptr);
    fcae_check_update_async(ver, includePrereleases == JNI_TRUE);
    LOGI("Version check started (current=%s, prereleases=%s)", ver,
         includePrereleases == JNI_TRUE ? "on" : "off");
    env->ReleaseStringUTFChars(currentVersion, ver);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativePollUpdate(JNIEnv* env, jclass) {
    ensure_init();

    // Find the FcaeUpdateInfo class
    jclass cls = env->FindClass("com/fc/fcaevpn/FcaeUpdateInfo");
    if (!cls) return nullptr;

    // Get field IDs
    jfieldID fid_available = env->GetFieldID(cls, "updateAvailable", "Z");
    jfieldID fid_inProgress = env->GetFieldID(cls, "checkInProgress", "Z");
    jfieldID fid_done = env->GetFieldID(cls, "checkDone", "Z");
    jfieldID fid_latest = env->GetFieldID(cls, "latestVersion", "Ljava/lang/String;");
    jfieldID fid_notes = env->GetFieldID(cls, "releaseNotes", "Ljava/lang/String;");
    jfieldID fid_dl = env->GetFieldID(cls, "downloadUrl", "Ljava/lang/String;");
    jfieldID fid_status = env->GetFieldID(cls, "statusMessage", "Ljava/lang/String;");
    jfieldID fid_isPre = env->GetFieldID(cls, "isPrerelease", "Z");
    jfieldID fid_date = env->GetFieldID(cls, "releaseDate", "Ljava/lang/String;");

    // Create object
    jobject obj = env->AllocObject(cls);

    FcaeUpdateInfo info = {};
    info.struct_size = sizeof(info);
    info.abi_version = FCAE_ABI_VERSION;
    fcae_poll_update(&info);

    env->SetBooleanField(obj, fid_available, info.update_available ? JNI_TRUE : JNI_FALSE);
    env->SetBooleanField(obj, fid_inProgress, info.check_in_progress ? JNI_TRUE : JNI_FALSE);
    env->SetBooleanField(obj, fid_done, info.check_done ? JNI_TRUE : JNI_FALSE);
    env->SetObjectField(obj, fid_latest, env->NewStringUTF(info.latest_version));
    env->SetObjectField(obj, fid_notes, env->NewStringUTF(info.release_notes));
    env->SetObjectField(obj, fid_dl, env->NewStringUTF(info.download_url));
    env->SetObjectField(obj, fid_status, env->NewStringUTF(info.status_message));
    env->SetBooleanField(obj, fid_isPre, info.is_prerelease ? JNI_TRUE : JNI_FALSE);
    env->SetObjectField(obj, fid_date, env->NewStringUTF(info.release_date));

    return obj;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fc_fcaevpn_NativeEngine_nativeCheckUpdateFromJson(JNIEnv* env, jclass, jstring currentVersion, jstring json, jboolean includePrereleases) {
    ensure_init();
    const char* ver = env->GetStringUTFChars(currentVersion, nullptr);
    const char* js = env->GetStringUTFChars(json, nullptr);

    bool ok = (fcae_check_update_from_json(ver, js, includePrereleases == JNI_TRUE) == FCAE_OK);

    env->ReleaseStringUTFChars(currentVersion, ver);
    env->ReleaseStringUTFChars(json, js);

    LOGI("Version check from JSON: %s", ok ? "OK" : "FAIL");
    return ok ? JNI_TRUE : JNI_FALSE;
}
