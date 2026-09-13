package com.fc.fcaevpn

object NativeEngine {
    init {
        // Load the Go bridges BEFORE libfcaevpn_native.so.
        //
        // tun2socks_bridge is a hard dependency (always needed for TUN).
        // psiphon_bridge is a soft dependency — its Go runtime init can
        // crash natively (SIGSEGV) on some Android devices, and Java
        // try/catch cannot catch native signals.  If it fails, weak C
        // stubs in android_jni.cpp take over and Psiphon reports as
        // unavailable.  Catch Throwable (not just UnsatisfiedLinkError)
        // because Go's runtime can surface errors as various types.
        try {
            System.loadLibrary("tun2socks_bridge")
        } catch (_: Throwable) {
            // Not packaged in this build/ABI — fine.
        }
        try {
            System.loadLibrary("psiphon_bridge")
        } catch (_: Throwable) {
            // Missing, wrong ABI, or Go runtime init failed.  Weak stubs
            // in android_jni.cpp provide safe defaults.
        }
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
        torSocksPort: Int,
        // Psiphon config JSON (the whole object, not a path), "" if unused.
        psiphonConfig: String,
        // ISO country code, or "" for automatic.
        psiphonRegion: String,
        // Psiphon's own proxy ports; 0 lets Psiphon choose.
        psiphonSocksPort: Int,
        psiphonHttpPort: Int,
    ): Boolean
    @JvmStatic external fun nativeStop()

    /**
     * Cancel the session and drop the TUN device without waiting for the
     * worker thread. Returns in milliseconds, so the VPN interface (and the
     * status-bar key icon) goes away immediately; follow with nativeStop()
     * to reap the session.
     */
    @JvmStatic external fun nativeStopBegin()
    @JvmStatic external fun nativeFree()
    /// Psiphon egress regions as comma-separated ISO codes, or "" before the
    /// first successful connect.
    @JvmStatic external fun nativePsiphonRegions(): String
    @JvmStatic external fun nativeGetLogs(): String
    @JvmStatic external fun nativeClearLogs()

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
