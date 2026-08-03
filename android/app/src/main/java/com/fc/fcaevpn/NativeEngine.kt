package com.fc.fcaevpn

object NativeEngine {
    init {
        System.loadLibrary("fcaevpn_native")
    }

    @JvmStatic external fun nativeInit()
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
        ironcladValidate: Boolean,
        healthIntervalSecs: Int,
        healthMaxFails: Int,
        healthTimeoutSecs: Int,
        liveValidateSecs: Int,
        sysProfile: Int,
        teamName: String,
        accessToken: String,
        accessEmail: String,
        routesFile: String,
        routesInline: String,
    ): Boolean
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeFree()
    @JvmStatic external fun nativeGetStatusJson(): String
    @JvmStatic external fun nativeGetLogs(): String
    @JvmStatic external fun nativeClearLogs()

    // ── version checker ─────────────────────────────────────────────
    @JvmStatic external fun nativeCheckForUpdates(currentVersion: String)
    @JvmStatic external fun nativePollUpdate(): AetherUpdateInfo
}

/**
 * Mirrors the C AetherUpdateInfo struct in aether_ffi.h.
 * Returned by [NativeEngine.nativePollUpdate].
 */
data class AetherUpdateInfo(
    val updateAvailable: Boolean = false,
    val checkInProgress: Boolean = false,
    val checkDone: Boolean = false,
    val latestVersion: String = "",
    val releaseNotes: String = "",
    val downloadUrl: String = "",
    val statusMessage: String = ""
)
