package com.fc.fcaevpn

object NativeEngine {
    // Process-wide command ordering, shared by the activity and both owners.
    // StopBegin remains immediate; starts and cleanup must not overtake one another.
    @JvmField val lifecycleExecutor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "FCAE-Lifecycle").apply { isDaemon = true }
    }

    init {
        // tun2socks Go runtime. Must load before the Rust JNI library, which
        // references t2s_* symbols. Psiphon is not in this .so (official AAR
        // when re-enabled). Do not swallow this error: a missing bridge is a
        // packaging/build failure, not an optional runtime feature.
        System.loadLibrary("fcae_go_bridge")

        System.loadLibrary("fcaevpn_native")

    }

    /**
     * Force this object's initialiser to run, loading the native libraries.
     *
     * Callers that only use JNI methods declared on *another* class (such as
     * FCAEVpnService) would otherwise never touch NativeEngine, so nothing
     * would have loaded libfcaevpn_native.so and their first native call
     * would throw UnsatisfiedLinkError.
     */
    @JvmStatic
    fun ensureLoaded() {
        // Referencing the object is enough; `init` has already run by here.
    }

    @JvmStatic external fun nativeInit()
    @JvmStatic external fun nativeSetNativeLibDir(path: String)
    @JvmStatic external fun nativeStart(
        protocol: Int,
        mode: Int,
        lanSharing: Boolean,
        scanMode: Int,
        ipVersion: Int,
        quickReconnect: Boolean,
        noizeProfile: String,
        fragmentEnabled: Boolean,
        fragMinSize: Int,
        fragMaxSize: Int,
        fragMinDelay: Int,
        fragMaxDelay: Int,
        socksPort: Int,
        httpPort: Int,
        forcePeer: String,
        configPath: String,
        h2Enabled: Boolean,
        echEnabled: Boolean,
        sni: String,
        sysProfile: Int,
        teamName: String,
        accessToken: String,
        accessEmail: String,
        routesFile: String,
        routesInline: String,
        // Tor egress. torMode: 0=off 1=chain 2=reverse 3=only.
        // torBridges: 0=none 1=obfs4 2=snowflake 3=custom.
        torMode: Int,
        torBridges: Int,
        torBridgeLines: String,
        // Aether engine verbosity: 0=off 1=error 2=warn 3=info 4=debug 5=trace.
        // Not the FFI's own log level -- that stays at info.
        engineLog: Int,
        // 0 = Aether, 1 = Psiphon (FcaeBackend).
        backend: Int,
        // Tor's own SOCKS listener; must differ from socksPort/httpPort.
        // 0 = defer to the engine default (config.rs DEFAULT_TOR_SOCKS_PORT);
        // do not substitute a literal here.
        torSocksPort: Int,
        torHttpPort: Int,
        psiphonThroughTunnel: Boolean,
        // Psiphon config JSON (the whole object, not a path), "" if unused.
        psiphonConfig: String,
        // ISO country code, or "" for automatic.
        psiphonRegion: String,
        // Psiphon's own proxy ports; 0 lets Psiphon choose.
        psiphonSocksPort: Int,
        psiphonHttpPort: Int,
        tunTcpSndbuf: Int,
        tunTcpRcvbuf: Int,
        tunTcpAutoTuning: Boolean,
        // tun2socks data-plane log level (FcaeT2sLog): 0=default(silent)
        // 1=silent 2=error 3=warn 4=info 5=debug.
        t2sLog: Int,
        // TUN data-plane engine (FCAE_TUN_ENGINE_*): 0 = tun2socks (default),
        // 1 = zeptun, 2 = hev-socks5-tunnel. Only consumed in TUN mode.
        tunEngine: Int,
        tunMtu: Int,
        // TUN DNS servers from the UI (comma separated) or "" for defaults.
        // Fed to the core so the in-tunnel Psiphon gateway queries THESE
        // resolvers; the same list also populates the TUN builder.
        tunDnsServers: String,
    ): Boolean
    @JvmStatic external fun nativePsiphonAttachRequest(): String
    @JvmStatic external fun nativePsiphonAttachComplete(id: Long, socks: Int, http: Int)
    @JvmStatic external fun nativeParseTcpBufferSize(text: String): Int
    @JvmStatic external fun nativeStop()

    /**
     * Cancel the session and drop the TUN fds without waiting for Go or the
     * worker thread. Returns in ~1ms; follow with nativeStop() to reap.
     */
    @JvmStatic external fun nativeStopBegin()

    /** TUN down, session/backend stay up. Pair with [nativeResumeTun]. */
    @JvmStatic external fun nativePauseTun(): Boolean

    /** Re-raise TUN on a live paused session after a fresh VpnService fd. */
    @JvmStatic external fun nativeResumeTun(): Boolean

    /** True while a session is alive and its TUN data plane is paused. */
    @JvmStatic external fun nativeTunPaused(): Boolean
    @JvmStatic external fun nativeFree()
    /// Psiphon egress regions as comma-separated ISO codes, or "" before the
    /// first successful connect.
    @JvmStatic external fun nativePsiphonRegions(): String
    @JvmStatic external fun nativeGetLogs(): String
    @JvmStatic external fun nativeClearLogs()
    /** Inject a host-side line (Psiphon AAR notices live in :psiphon). */
    @JvmStatic external fun nativeAppendLog(line: String)

    // ── TUN engine enumeration ───────────────────────────────────────
    // No engine start required: availability is a compile-/platform-time
    // property, queried by the UI while the engine is down.
    @JvmStatic external fun nativeTunEngineCount(): Int
    /** "display_name|unavailable_reason"; reason is "" when available. */
    @JvmStatic external fun nativeTunEngineInfo(index: Int): String

    // ── Structured telemetry getters ──
    @JvmStatic external fun nativeGetState(): Int
    @JvmStatic external fun nativeGetRxBps(): Long
    @JvmStatic external fun nativeGetTxBps(): Long
    @JvmStatic external fun nativeGetTotalRx(): Long
    @JvmStatic external fun nativeGetTotalTx(): Long
    @JvmStatic external fun nativeGetRttMs(): Int
    @JvmStatic external fun nativeGetPeer(): String
    @JvmStatic external fun nativeGetLanIp(): String
    @JvmStatic external fun nativeGetStatusMsg(): String
    @JvmStatic external fun nativeGetLastError(): String

    // ── version checker ─────────────────────────────────────────────
    @JvmStatic external fun nativeCheckForUpdates(currentVersion: String, includePrereleases: Boolean)
    @JvmStatic external fun nativePollUpdate(): FcaeUpdateInfo
    @JvmStatic external fun nativeCheckUpdateFromJson(currentVersion: String, json: String, includePrereleases: Boolean): Boolean
}

/**
 * Mirrors the C FcaeUpdateInfo struct in core/fcae-ffi/include/fcae.h.
 * Returned by [NativeEngine.nativePollUpdate].
 */
data class FcaeUpdateInfo(
    val updateAvailable: Boolean = false,
    val checkInProgress: Boolean = false,
    val checkDone: Boolean = false,
    val latestVersion: String = "",
    val releaseNotes: String = "",
    val downloadUrl: String = "",
    val statusMessage: String = "",
    /** The offered version is a pre-release (shown as BETA in the UI). */
    val isPrerelease: Boolean = false,
    val releaseDate: String = ""
)
