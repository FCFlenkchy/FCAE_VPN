package com.fc.fcaevpn

object NativeEngine {
    init {
        // Load the Go bridges BEFORE libfcaevpn_native.so.
        //
        // tun2socks is built as a c-shared .so on Android (Go rejects
        // c-archive there), so libfcaevpn_native.so has a DT_NEEDED entry for
        // it. Android's loader does resolve that from the APK's native lib
        // dir, but only once the library is actually present; loading it
        // explicitly first turns an obscure dlopen failure deep inside
        // loadLibrary("fcaevpn_native") into a clear, attributable error.
        //
        // Wrapped in try/catch: these are optional (a build without the tun
        // feature has no bridge), and if one is genuinely missing the failure
        // surfaces on the main library load below.
        for (dep in arrayOf("tun2socks_bridge", "psiphon_bridge")) {
            try {
                System.loadLibrary(dep)
            } catch (_: UnsatisfiedLinkError) {
                // Not packaged in this build/ABI — fine, see above.
            }
        }
        System.loadLibrary("fcaevpn_native")
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
    ): Boolean
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeFree()
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
