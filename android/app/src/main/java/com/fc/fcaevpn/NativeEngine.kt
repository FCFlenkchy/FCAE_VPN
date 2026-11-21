package com.fc.fcaevpn

import android.content.Context
import android.content.Intent

object NativeEngine {
    // Process-wide command ordering, shared by the activity and both owners.
    // StopBegin remains immediate; starts and cleanup must not overtake one another.
    @JvmField val lifecycleExecutor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "FCAE-Lifecycle").apply { isDaemon = true }
    }

    @Volatile private var loadFailure: String? = null

    init {
        // Loading can fail when an APK is missing an ABI-specific native
        // payload. Never let that poison this class: Android turns a failed
        // object initialiser into NoClassDefFoundError at every later service
        // call, which hides the actual loader error and crashes the process.
        try {
            System.loadLibrary("fcae_go_bridge")
            System.loadLibrary("fcaevpn_native")
            nativeConfigureLogFile(FCAEApplication.logFilePath())
            Loaded.value = true
        } catch (t: Throwable) {
            loadFailure = t.toString()
            android.util.Log.e("FCAE_VPN", "native libraries unavailable", t)
        }
    }

    /**
     * Whether the libraries are in this process. A nested object is its own
     * class, so reading it does not run the loader above: callers that only
     * need to know whether an engine CAN exist here (the widget, in a process
     * the launcher just started) ask this instead of paying for the load.
     */
    object Loaded {
        @JvmField @Volatile var value = false
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
    fun ensureLoaded(): Boolean = Loaded.value

    /** Loader failure retained for the service log when a packaged ABI is missing. */
    @JvmStatic
    fun nativeLoadFailure(): String = loadFailure.orEmpty()

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
        // 0 = Aether, 1 = Psiphon, 2 = Firefox (FcaeBackend).
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
        // Aether engine options (FcaeAether); "" takes the engine default.
        echDns: String,
        echDomain: String,
        goolInner: String,
        tlsCiphers: String,
        apiAddress: String,
        apiHost: String,
        apiSni: String,
        exitLoc: String,
        tls13Ciphers: String,
        tlsGroups: String,
        tlsKeyShares: String,
        tlsSigalgs: String,
        tlsCertCompression: String,
        tlsAlps: String,
        tlsTrustAnchors: String,
        tlsServerPadding: String,
        tlsVerify: Boolean,
        disableGrease: Boolean,
        enableGreaseSigalgs: Boolean,
        enableEchGrease: Boolean,
        disableOcspStapling: Boolean,
        disableSct: Boolean,
        disableSessionTicket: Boolean,
        disableExtensionPermutation: Boolean,
        fragmentSni: Boolean,
        // Outbound proxy URL (http/socks5) or "" for direct.
        upstreamProxy: String,
        // Ordered additional exits as protocol-list positions. 0-10 are the
        // built-in transports; 11 and up name a saved core config by position.
        chainTransports: IntArray,
        // Every saved Xray/sing-box config as one JSON array document
        // ({"name","backend","config"} objects), or "" when there are none.
        coreConfigs: String,
        // The saved config the main protocol runs: "#<index>", or "" when the
        // main protocol is a built-in transport.
        coreConfigId: String,
        firefoxAccountId: String,
        firefoxLocation: String,
        firefoxServer: String,
        firefoxTransport: String,
        // The route core's own verbosity (FcaeEngineLog):
        // 0=silent 1=error 2=warn 3=info 4=debug 5=trace. Silent by default:
        // Xray and sing-box write a line per connection at info.
        coreLog: Int,
    ): Boolean

    @JvmStatic external fun nativePsiphonAttachRequest(): String
    @JvmStatic external fun nativePsiphonAttachComplete(id: Long, socks: Int, http: Int)
    /** Why [text] is not a usable upstream proxy, or "" when it is (or empty). */
    @JvmStatic external fun nativeCheckUpstreamProxy(text: String): String
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
    /** Inject a host-side line from the Psiphon service. */
    @JvmStatic external fun nativeAppendLog(line: String)
    @JvmStatic private external fun nativeConfigureLogFile(path: String)

    @JvmStatic external fun nativeGetState(): Int
    @JvmStatic external fun nativeGetRttMs(): Int

    /**
     * First protocol-list position that names a saved Xray/sing-box config (its
     * position in the saved list). Mirrors FCAE_CORE_TRANSPORT_BASE in fcae.h,
     * which the native side uses for the same mapping.
     */
    const val CORE_TRANSPORT_BASE = 11

    /**
     * Most saved configs a session may carry; mirrors the runtime's limit. It is
     * not a number the UI shows or enforces: the document's byte limit is what a
     * real library runs into, and this is the parse bound behind it.
     */
    const val MAX_CORE_CONFIGS = 1000

    /** Largest single saved config, in bytes; mirrors the runtime's limit. */
    const val MAX_CORE_CONFIG_BYTES = 128 * 1024

    /**
     * Largest saved-configs document, in bytes; mirrors the runtime's limit. It
     * is one Intent extra, so it also has to stay inside a Binder transaction.
     */
    const val MAX_CORE_DOCUMENT_BYTES = 512 * 1024

    @JvmStatic
    fun parseChainTransports(value: String?): IntArray = value.orEmpty()
        .split(',')
        .mapNotNull { it.trim().toIntOrNull() }
        .toIntArray()

    @JvmStatic
    fun encodeChainTransports(transports: IntArray): String = transports.joinToString(",")

    @JvmStatic
    fun sessionChainTransports(session: Intent): IntArray {
        // Do not filter missing saved-config hops: only the runtime can validate
        // the complete route, and dropping a hop would change the user's exit.
        session.getIntArrayExtra("chainTransports")?.let { return it }
        val count = session.getIntExtra("chainCount", 0).coerceIn(0, 3)
        return IntArray(count) { index ->
            when (session.getIntExtra("chainExit$index", 0)) {
                1 -> 5
                2 -> 10
                else -> 0
            }
        }
    }

        /**
         * Start a session from a canonical session intent (the extras the UI writes
         * and [FCAEVpnService] persists), so a headless start hands the engine
         * exactly what an app start does. Runs on [lifecycleExecutor].
         */
    @JvmStatic
    fun startSession(context: Context, session: Intent): Boolean {
        if (!ensureLoaded()) return false
        val mode = if (session.getIntExtra("mode", 1) == 1) 1 else 0
        val socks = session.getIntExtra("socksPort", 1819)
        // Preserve the choice verbatim. Missing/invalid references must fail
        // validation, not select a different carrier on a headless restart.
        val coreConfigs = session.getStringExtra("coreConfigs").orEmpty()
        val coreConfigId = session.getStringExtra("coreConfigId").orEmpty()
        nativeInit()
        try {
            nativeSetNativeLibDir(context.applicationInfo.nativeLibraryDir)
        } catch (_: Throwable) {
        }
        return nativeStart(
            protocol = session.getIntExtra("protocol", 0),
            mode = mode,
            lanSharing = session.getBooleanExtra("lanSharing", false),
            scanMode = session.getIntExtra("scanMode", 0),
            ipVersion = session.getIntExtra("ipVersion", 4),
            quickReconnect = session.getBooleanExtra("quickReconnect", false),
            noizeProfile = session.getStringExtra("noizeProfile").orEmpty().ifEmpty { "balanced" },
            fragmentEnabled = session.getBooleanExtra("fragmentEnabled", false),
            fragMinSize = session.getIntExtra("fragMinSize", 16),
            fragMaxSize = session.getIntExtra("fragMaxSize", 32),
            fragMinDelay = session.getIntExtra("fragMinDelay", 2),
            fragMaxDelay = session.getIntExtra("fragMaxDelay", 10),
            socksPort = socks,
            httpPort = if (mode == 1 && !session.getBooleanExtra("tunHttpEnabled", false)) 0
                else session.getIntExtra("httpPort", 1820),
            forcePeer = session.getStringExtra("forcePeer").orEmpty(),
            configPath = session.getStringExtra("configPath").orEmpty().ifEmpty { "aether.toml" },
            h2Enabled = session.getBooleanExtra("h2Enabled", true),
            echEnabled = session.getBooleanExtra("echEnabled", true),
            sni = session.getStringExtra("sni").orEmpty(),
            sysProfile = session.getIntExtra("sysProfile", 0),
            teamName = session.getStringExtra("teamName").orEmpty(),
            accessToken = session.getStringExtra("accessToken").orEmpty(),
            accessEmail = session.getStringExtra("accessEmail").orEmpty(),
            routesFile = "",
            routesInline = session.getStringExtra("routesInline").orEmpty(),
            torMode = session.getIntExtra("torMode", 0),
            torBridges = session.getIntExtra("torBridges", 0),
            torBridgeLines = session.getStringExtra("torBridgeLines").orEmpty(),
            engineLog = session.getIntExtra("engineLog", 3),
            backend = session.getIntExtra("backend", 0),
            torSocksPort = session.getIntExtra("torSocksPort", 0),
            torHttpPort = session.getIntExtra("torHttpPort", 0),
            psiphonThroughTunnel = session.getBooleanExtra("psiphonThroughTunnel", false),
            psiphonConfig = session.getStringExtra("psiphonConfig").orEmpty(),
            psiphonRegion = session.getStringExtra("psiphonRegion").orEmpty(),
            psiphonSocksPort = session.getIntExtra("psiphonSocksPort", 0),
            psiphonHttpPort = session.getIntExtra("psiphonHttpPort", 0),
            tunTcpSndbuf = session.getIntExtra("tunTcpSndbuf", 256000),
            tunTcpRcvbuf = session.getIntExtra("tunTcpRcvbuf", 256000),
            tunTcpAutoTuning = session.getBooleanExtra("tunTcpAutoTuning", false),
            t2sLog = session.getIntExtra("t2sLog", 0),
            tunEngine = session.getIntExtra("tunEngine", 0),
            tunMtu = session.getIntExtra("tunMtu", 1500),
            // TUN DNS is a TUN concern and the VpnService reads it from settings
            // itself; a proxy session has no interface to configure.
            tunDnsServers = "",
            echDns = session.getStringExtra("echDns").orEmpty(),
            echDomain = session.getStringExtra("echDomain").orEmpty(),
            goolInner = session.getStringExtra("goolInner").orEmpty(),
            tlsCiphers = session.getStringExtra("tlsCiphers").orEmpty(),
            apiAddress = session.getStringExtra("apiAddress").orEmpty(),
            apiHost = session.getStringExtra("apiHost").orEmpty(),
            apiSni = session.getStringExtra("apiSni").orEmpty(),
            exitLoc = session.getStringExtra("exitLoc").orEmpty(),
            tls13Ciphers = session.getStringExtra("tls13Ciphers").orEmpty(),
            tlsGroups = session.getStringExtra("tlsGroups").orEmpty(),
            tlsKeyShares = session.getStringExtra("tlsKeyShares").orEmpty(),
            tlsSigalgs = session.getStringExtra("tlsSigalgs").orEmpty(),
            tlsCertCompression = session.getStringExtra("tlsCertCompression").orEmpty(),
            tlsAlps = session.getStringExtra("tlsAlps").orEmpty(),
            tlsTrustAnchors = session.getStringExtra("tlsTrustAnchors").orEmpty(),
            tlsServerPadding = session.getStringExtra("tlsServerPadding").orEmpty(),
            tlsVerify = session.getBooleanExtra("tlsVerify", false),
            disableGrease = session.getBooleanExtra("disableGrease", false),
            enableGreaseSigalgs = session.getBooleanExtra("enableGreaseSigalgs", false),
            enableEchGrease = session.getBooleanExtra("enableEchGrease", false),
            disableOcspStapling = session.getBooleanExtra("disableOcspStapling", false),
            disableSct = session.getBooleanExtra("disableSct", false),
            disableSessionTicket = session.getBooleanExtra("disableSessionTicket", false),
            disableExtensionPermutation = session.getBooleanExtra("disableExtensionPermutation", false),
            fragmentSni = session.getBooleanExtra("fragmentSni", false),
            upstreamProxy = session.getStringExtra("upstreamProxy").orEmpty(),
            chainTransports = sessionChainTransports(session),
            coreConfigs = coreConfigs,
            coreConfigId = coreConfigId,
            coreLog = session.getIntExtra("coreLog", 0),
            firefoxAccountId = session.getStringExtra("firefoxAccountId").orEmpty(),
            firefoxLocation = session.getStringExtra("firefoxLocation").orEmpty(),
            firefoxServer = session.getStringExtra("firefoxServer").orEmpty(),
            firefoxTransport = session.getStringExtra("firefoxTransport").orEmpty().ifEmpty { "auto" },
        )
    }

    // Native sponsor audio needs the application Context, not an Activity.
    @JvmStatic external fun nativeSponsorInitAndroidContext(context: android.content.Context)
}
