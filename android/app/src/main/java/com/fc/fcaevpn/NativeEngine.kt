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
    ): Boolean
    @JvmStatic external fun nativeStop()
    @JvmStatic external fun nativeFree()
    @JvmStatic external fun nativeGetStatusJson(): String
    @JvmStatic external fun nativeGetLogs(): String
    @JvmStatic external fun nativeClearLogs()
}
