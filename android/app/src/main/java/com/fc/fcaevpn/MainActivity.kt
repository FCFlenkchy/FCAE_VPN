package com.fc.fcaevpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.content.SharedPreferences
import android.widget.ArrayAdapter
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var connecting = false
    @Volatile private var engineRunning = false
    private var pendingAfterVpnPermission = false
    @Volatile private var pendingPsiSocks = 0
    @Volatile private var pendingPsiHttp = 0
    @Volatile private var pendingPsiLan = ""
    private var lastLogHash = 0L
    private var disconnecting = false
    @Volatile private var connectionEpoch = 0L
    @Volatile private var vpnActive = false
    private var wasAtBottom = true
    private var logTouchActive = false
    private var logTouchStartY = 0f
    private var inForeground = false

    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private lateinit var peerText: TextView
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var btnConnect: MaterialButton
    private lateinit var btnCheckUpdates: MaterialButton
    private lateinit var updateStatus: TextView
    private var updateAvailableInfo: FcaeUpdateInfo? = null
    private lateinit var spinnerProtocol: Spinner
    private lateinit var spinnerMode: Spinner
    private lateinit var spinnerScan: Spinner
    private lateinit var spinnerIpVersion: Spinner
    private lateinit var spinnerNoize: Spinner
    private lateinit var spinnerTor: Spinner
    private lateinit var spinnerTorBridges: Spinner
    private lateinit var textTorHint: android.widget.TextView
    private lateinit var editTorBridgeLines: android.widget.EditText
    private lateinit var spinnerEngineLog: Spinner
    private lateinit var editTorSocksPort: android.widget.EditText
    private lateinit var spinnerPsiphonRegion: Spinner
    private lateinit var spinnerPsiphonTransport: Spinner
    private lateinit var editPsiphonSocksPort: android.widget.EditText
    private lateinit var editPsiphonHttpPort: android.widget.EditText
    /// Regions currently offered, index 0 always "Auto" (empty code).
    private var psiphonRegionCodes: List<String> = listOf("")
    /// Region chosen before the list was known, restored once it arrives.
    private var savedPsiphonRegion: String = ""
    private var applyingRegionList = false
    private var pendingRegionCodes: List<String>? = null
    private lateinit var switchEch: SwitchMaterial
    private lateinit var switchQuick: SwitchMaterial
    private lateinit var switchLan: SwitchMaterial
    private lateinit var switchLogging: SwitchMaterial
    private lateinit var switchSocks: SwitchMaterial
    private lateinit var switchTorHttp: SwitchMaterial
    private lateinit var editTorHttpPort: android.widget.EditText
    private lateinit var switchHttp: SwitchMaterial
    private lateinit var switchAutoUpdate: SwitchMaterial
    private lateinit var switchPreReleases: SwitchMaterial
    private lateinit var spinnerSysprofile: Spinner
    private lateinit var editSni: android.widget.EditText
    private lateinit var editForcePeer: android.widget.EditText
    private lateinit var editSocksPort: android.widget.EditText
    private lateinit var editHttpPort: android.widget.EditText
    private lateinit var editTunDnsV4: android.widget.EditText
    private lateinit var editTunDnsV6: android.widget.EditText
    private lateinit var editTeam: android.widget.EditText
    private lateinit var editAccessToken: android.widget.EditText
    private lateinit var editAccessEmail: android.widget.EditText
    private lateinit var editRoutesFile: android.widget.EditText
    private lateinit var editRoutesInline: android.widget.EditText
    private lateinit var outerScroll: ScrollView

    /// True when this build came from a pre-release workflow run: its own
    /// version carries a suffix (v1.4.0-beta.2 vs v1.3.2). Drives the channel
    /// label in the header and in the update dialog.
    private val buildIsPrerelease = BuildConfig.APP_VERSION.contains('-')

    private val bgExecutor = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        val t = Thread(r, "bgExecutor")
        t.isDaemon = true
        t
    }
    private val pollBusy = AtomicBoolean(false)
    private lateinit var prefs: SharedPreferences

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK && pendingAfterVpnPermission) {
            pendingAfterVpnPermission = false
            if (isPsiphonSelected()) startPsiphon() else startTunServiceWithConfig()
        } else {
            pendingAfterVpnPermission = false
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    @Volatile private var lastBroadcastGeneration = 0L
    // Set to true by disconnectAll().  Cleared by connectClicked().
    // When set, the receiver ignores disconnect broadcasts — they belong
    // to the previous cycle and would override the optimistic connect UI.
    private var userInitiatedDisconnect = false
    // Notification Stop/Start own the UI until the next command.
    @Volatile private var commandPaused = false
    @Volatile private var commandConnecting = false

    // Latest psiphon tunnel telemetry from PsiphonTunnelService
    // (BROADCAST_STATS). The Aether engine getters return nothing on the
    // psiphon-only path, so the stats line and RTT are fed from here.
    @Volatile private var psiRttMs = 0
    @Volatile private var psiUpBps = 0L
    @Volatile private var psiDownBps = 0L
    @Volatile private var psiTotalUp = 0L
    @Volatile private var psiTotalDown = 0L

    private fun resetPsiStats() {
        psiRttMs = 0
        psiUpBps = 0L
        psiDownBps = 0L
        psiTotalUp = 0L
        psiTotalDown = 0L
    }

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action?.startsWith("com.fc.fcaevpn.PSI_") == true &&
                !PsiphonTunnelService.isCurrentBroadcast(intent)) return
            if (intent.getBooleanExtra("cleanupComplete", false)) {
                val generation = intent.getLongExtra("generation", -1)
                val epoch = connectionEpoch
                NativeEngine.lifecycleExecutor.execute {
                    handler.post {
                        if (epoch != connectionEpoch || generation != FCAEVpnService.sGeneration.get()) return@post
                        disconnecting = false
                        updateButton()
                    }
                }
                return
            }
            when (intent.action) {
                // Staged psiphon progress (like the Tor bootstrap phases):
                // only repaints the status line while a psiphon connect is
                // still in flight — READY/FAILED own the terminal states.
                PsiphonTunnelService.BROADCAST_STAGE -> {
                    val label = intent.getStringExtra(PsiphonTunnelService.EXTRA_STAGE_LABEL) ?: return
                    handler.post {
                        // commandConnecting covers the egress chain, where
                        // 'connecting' already flipped off when the Aether
                        // state hit Connected before psiphon finished.
                        if ((connecting || commandConnecting)
                                && (isPsiphonSelected() || isEgressPsiphon())) {
                            // Same status vocabulary as the other protocols —
                            // the label is already the full staged phrase.
                            statusText.text = label
                            statusText.setTextColor(COLOR_PROGRESS)
                        }
                    }
                }
                PsiphonTunnelService.BROADCAST_STATS -> {
                    // Tunnel telemetry from :psiphon — owns the stats line on
                    // every psiphon path (the engine getters are empty there).
                    pendingPsiLan = intent.getStringExtra(PsiphonTunnelService.EXTRA_LAN) ?: ""
                    pendingPsiSocks = intent.getIntExtra(PsiphonTunnelService.EXTRA_SOCKS, pendingPsiSocks)
                    pendingPsiHttp = intent.getIntExtra(PsiphonTunnelService.EXTRA_HTTP, pendingPsiHttp)
                    psiRttMs = intent.getIntExtra(PsiphonTunnelService.EXTRA_RTT, 0)
                    psiUpBps = intent.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0L)
                    psiDownBps = intent.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L)
                    psiTotalUp = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L)
                    psiTotalDown = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L)
                    if (vpnActive && (isPsiphonSelected() || isEgressPsiphon())) {
                        handler.post {
                            if (isPsiphonSelected()) peerText.text = psiphonEndpointText()
                            statsText.text =
                                "↓ ${fmt(psiDownBps)}/s (${fmt(psiTotalDown)})  |  ↑ ${fmt(psiUpBps)}/s (${fmt(psiTotalUp)})  |  RTT ${if (psiRttMs > 0) "${psiRttMs}ms" else "—"}"
                        }
                    }
                }
                PsiphonTunnelService.BROADCAST_READY -> {
                    val socks = intent.getIntExtra(PsiphonTunnelService.EXTRA_SOCKS, 0)
                    val http = intent.getIntExtra(PsiphonTunnelService.EXTRA_HTTP, 0)
                    val regions = intent.getStringExtra(PsiphonTunnelService.EXTRA_REGIONS)
                    val regionsOnly = intent.getBooleanExtra("regionsOnly", false)
                    handler.post {
                        if (!regions.isNullOrBlank()) {
                            applyPsiphonRegionList(regions)
                        }
                        if (regionsOnly || userInitiatedDisconnect) return@post
                        pendingPsiSocks = socks
                        pendingPsiHttp = http
                        pendingPsiLan = intent.getStringExtra(PsiphonTunnelService.EXTRA_LAN) ?: ""
                        if (isEgressPsiphon()) {
                            handler.post(poll)
                            return@post
                        }
                        connecting = false
                        engineRunning = true
                        vpnActive = true
                        updateButton()
                        statusText.text = if (isTunModeSelected()) "ESTABLISHING PSIPHON TUN" else "CONNECTED (PSIPHON PROXY)"
                        statusText.setTextColor(COLOR_CONNECTED)
                        // Surface psiphon's actual proxy endpoints here too —
                        // pure-psiphon mode never polls the engine, so this
                        // and BROADCAST_STATS are the only UI updates.
                        if (!isTunModeSelected() && socks > 0) {
                            peerText.text = psiphonEndpointText()
                        }
                        if (isPsiphonSelected() && isTunModeSelected() && socks > 0) {
                            startTunServiceWithConfig()
                        }
                    }
                }
                PsiphonTunnelService.BROADCAST_FAILED -> {
                    val err = intent.getStringExtra(PsiphonTunnelService.EXTRA_ERROR) ?: "Psiphon failed"
                    handler.post {
                        connecting = false
                        engineRunning = false
                        vpnActive = false
                        updateButton()
                        statusText.text = "ERROR: $err"
                        statusText.setTextColor(COLOR_ERROR)
                        Toast.makeText(this@MainActivity, err, Toast.LENGTH_LONG).show()
                    }
                }
                PsiphonTunnelService.BROADCAST_STOPPED -> {
                    resetPsiStats()
                    handler.post {
                        if (userInitiatedDisconnect) return@post
                        connecting = false
                        engineRunning = false
                        vpnActive = false
                        updateButton()
                        statusText.text = "DISCONNECTED"
                    }
                }
                PsiphonTunnelService.BROADCAST_LOG -> {
                    val chunk = intent.getStringExtra(PsiphonTunnelService.EXTRA_LOG) ?: return
                    handler.post { ingestPsiphonLog(chunk) }
                }
                FCAEVpnService.BROADCAST_VPN_DISCONNECTED,
                FCAEVpnService.BROADCAST_VPN_STATE_CHANGED -> {
                    val isRunning = intent.getBooleanExtra("running", false)
                    val isPaused = intent.getBooleanExtra("paused", false)
                    val isConnecting = intent.getBooleanExtra("connecting", false)
                    val gen = intent.getLongExtra("generation", 0)

                    handler.post {
                        // Ignore stale broadcasts from a previous
                        // connect/disconnect cycle.
                        if (gen < lastBroadcastGeneration) return@post

                        if (isConnecting) {
                            userInitiatedDisconnect = false
                            commandPaused = false
                            commandConnecting = true
                            lastBroadcastGeneration = gen
                            connecting = true
                            engineRunning = false
                            vpnActive = true
                            updateButton()
                            statusText.text = "CONNECTING"
                            statusText.setTextColor(COLOR_PROGRESS)
                            handler.removeCallbacks(poll)
                            handler.post(poll)
                        } else if (isRunning) {
                            userInitiatedDisconnect = false
                            commandPaused = false
                            commandConnecting = false
                            lastBroadcastGeneration = gen
                            connecting = false
                            engineRunning = true
                            vpnActive = true
                            updateButton()
                            handler.removeCallbacks(poll)
                            handler.post(poll)
                        } else if (isPaused) {
                            userInitiatedDisconnect = false
                            commandPaused = true
                            commandConnecting = false
                            lastBroadcastGeneration = gen
                            connecting = false
                            engineRunning = false
                            vpnActive = false
                            updateButton()
                            statusText.text = "STOPPED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
                            statsText.text = ""
                            handler.removeCallbacks(poll)
                        } else if (!isRunning && !isPaused) {

                            lastBroadcastGeneration = gen
                            commandPaused = false
                            commandConnecting = false
                            connecting = false
                            engineRunning = false
                            vpnActive = false
                            updateButton()
                            statusText.text = "DISCONNECTED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
                            statsText.text = ""
                            peerText.text = ""
                            handler.removeCallbacks(poll)
                        }
                    }
                }
            }
        }
    }

    private val poll = object : Runnable {
        override fun run() {
            if (!vpnActive) return
            if (!pollBusy.compareAndSet(false, true)) {
                handler.postDelayed(this, currentPollInterval())
                return
            }
            bgExecutor.execute {
                try {
                    // Guard: vpnActive (UI thread).  Also check engineRunning
                    // for TUN mode, but in proxy mode engineRunning is set
                    // optimistically — rely on native state to update it.
                    if (!vpnActive) {
                        handler.post { pollBusy.set(false) }
                        return@execute
                    }
                    // Use structured getters instead of JSON round-trip.
                    // Saves ~1 KB alloc per poll tick.
                    val state = NativeEngine.nativeGetState()
                    // On psiphon paths the engine's prober owns no RTT; fall
                    // back to the tunnel probe broadcast from :psiphon.
                    val rttNative = NativeEngine.nativeGetRttMs()
                    val rtt = if (rttNative == 0 && psiRttMs > 0
                            && (isPsiphonSelected() || isEgressPsiphon())) psiRttMs else rttNative
                    val rx = NativeEngine.nativeGetRxBps()
                    val tx = NativeEngine.nativeGetTxBps()
                    val totalRx = NativeEngine.nativeGetTotalRx()
                    val totalTx = NativeEngine.nativeGetTotalTx()
                    val peer = NativeEngine.nativeGetPeer()
                    val lan = NativeEngine.nativeGetLanIp()
                    val statusMsg = NativeEngine.nativeGetStatusMsg()
                    val errMsg = NativeEngine.nativeGetLastError()
                    val logs = if (switchLogging.isChecked) NativeEngine.nativeGetLogs() else ""

                    // Adaptive polling: if idle (no traffic) for 5+ consecutive
                    // ticks, slow down from 1s to 2s to save JNI crossings.
                    if (rx == 0L && tx == 0L) {
                        idleTicks++
                    } else {
                        idleTicks = 0
                    }

                    handler.post { applyStatus(state, rtt, rx, tx, totalRx, totalTx, peer, lan, statusMsg, errMsg, logs) }
                } catch (e: Throwable) {
                    handler.post {
                        statusText.text = "UI error: ${e.message}"
                    }
                } finally {
                    pollBusy.set(false)
                }
            }
            handler.postDelayed(this, currentPollInterval())
        }
    }

    private var idleTicks = 0

    private fun currentPollInterval(): Long {
        // After 5 idle ticks at 1s, switch to 2s to reduce JNI overhead.
        // Resets to 1s as soon as traffic resumes.
        return if (idleTicks >= 5) 2000L else POLL_INTERVAL_MS
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        activityAlive = true
        setContentView(R.layout.activity_main)
        prefs = getSharedPreferences("aether_vpn", MODE_PRIVATE)

        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)
        peerText = findViewById(R.id.peerText)
        logText = findViewById(R.id.logText)
        logScroll = findViewById(R.id.logScroll)
        btnConnect = findViewById(R.id.btnConnect)
        btnCheckUpdates = findViewById(R.id.btnCheckUpdates)
        updateStatus = findViewById(R.id.updateStatus)
        spinnerProtocol = findViewById(R.id.spinnerProtocol)
        spinnerMode = findViewById(R.id.spinnerMode)
        spinnerScan = findViewById(R.id.spinnerScan)
        spinnerIpVersion = findViewById(R.id.spinnerIpVersion)
        spinnerNoize = findViewById(R.id.spinnerNoize)
        spinnerTor = findViewById(R.id.spinnerTor)
        spinnerTorBridges = findViewById(R.id.spinnerTorBridges)
        textTorHint = findViewById(R.id.textTorHint)
        editTorBridgeLines = findViewById(R.id.editTorBridgeLines)
        spinnerEngineLog = findViewById(R.id.spinnerEngineLog)
        editTorSocksPort = findViewById(R.id.editTorSocksPort)
        spinnerPsiphonRegion = findViewById(R.id.spinnerPsiphonRegion)
        spinnerPsiphonTransport = findViewById(R.id.spinnerPsiphonTransport)
        editPsiphonSocksPort = findViewById(R.id.editPsiphonSocksPort)
        editPsiphonHttpPort = findViewById(R.id.editPsiphonHttpPort)
        switchEch = findViewById(R.id.switchEch)
        switchQuick = findViewById(R.id.switchQuick)
        switchLan = findViewById(R.id.switchLan)
        switchLogging = findViewById(R.id.switchLogging)
        switchSocks = findViewById(R.id.switchSocks)
        switchHttp = findViewById(R.id.switchHttp)
        switchHttp.text = "Aether HTTP proxy"
        switchTorHttp = findViewById(R.id.switchTorHttp)
        editTorHttpPort = findViewById(R.id.editTorHttpPort)
        switchAutoUpdate = findViewById(R.id.switchAutoUpdate)
        switchPreReleases = findViewById(R.id.switchPreReleases)
        spinnerSysprofile = findViewById(R.id.spinnerSysprofile)
        editSni = findViewById(R.id.editSni)
        editForcePeer = findViewById(R.id.editForcePeer)
        editSocksPort = findViewById(R.id.editSocksPort)
        editHttpPort = findViewById(R.id.editHttpPort)
        editTunDnsV4 = findViewById(R.id.editTunDnsV4)
        editTunDnsV6 = findViewById(R.id.editTunDnsV6)
        editTeam = findViewById(R.id.editTeam)
        editAccessToken = findViewById(R.id.editAccessToken)
        editAccessEmail = findViewById(R.id.editAccessEmail)
        editRoutesFile = findViewById(R.id.editRoutesFile)
        editRoutesInline = findViewById(R.id.editRoutesInline)
        outerScroll = findViewById(R.id.outerScroll)

        // Tapping anywhere outside an EditText clears its focus and moves
        // focus to the decor view, preventing the system from immediately
        // re-assigning focus back to the same field.
        outerScroll.setOnTouchListener { _, _ ->
            val focused = currentFocus
            if (focused is android.widget.EditText) {
                focused.clearFocus()
                window.decorView.requestFocus()
                val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                imm.hideSoftInputFromWindow(focused.windowToken, 0)
            }
            false
        }

        // Bulletproof: whenever any EditText loses focus, explicitly hide its
        // cursor.  This covers every focus-loss path (taps outside, back
        // button, keyboard dismissal, spinner selection) regardless of how
        // the focus was moved.
        val editTexts = listOf(editSni, editForcePeer, editSocksPort, editHttpPort, editTorHttpPort,
            editTeam, editAccessToken, editAccessEmail, editRoutesFile, editRoutesInline)
        for (et in editTexts) {
            et.setOnFocusChangeListener { view, hasFocus ->
                (view as android.widget.EditText).isCursorVisible = hasFocus
            }
        }
        spinnerProtocol.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            // H2 is folded into the MASQUE entries (used to be the separate
            // "HTTP/2 fallback" switch). Positions map to core protocol +
            // h2Enabled via the helpers below — the FFI/start intents keep
            // taking exactly the same fields as before.
            // 4 = Tor and 5 = Psiphon are peers of the WARP transports from
            // the user's point of view ("how do I get out?"), even though
            // internally Tor is an engine egress and Psiphon is a separate
            // backend. The helpers below translate a position into the
            // (backend, protocol, torMode) triple the FFI wants.
            listOf(
                "MASQUE (HTTP/3)", "MASQUE (HTTP/2)", "WireGuard", "WARP-in-WARP",
                "Tor", "Psiphon", "MASQUE-in-MASQUE (HTTP/3)", "MASQUE-in-MASQUE (HTTP/2)",
            ),
        )
        spinnerMode.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Proxy (SOCKS/HTTP)", "TUN (system VPN)"),
        )
        spinnerScan.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Turbo", "Balanced", "Thorough", "Stealth", "Ironclad"),
        )
        spinnerIpVersion.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("IPv4", "IPv6", "Dual Stack (IPv4+IPv6)"),
        )
        // Obfuscation/noize types must match the Aether engine/core profiles
        // (aethernoize::from_profile). "firewall"/"gfw" are legacy aliases that
        // the core collapses into "balanced"/"aggressive"; expose the four
        // distinct types the core actually distinguishes. Index 2 = "balanced"
        // keeps the saved default (prefs.getInt("noize", 2)) aligned with the
        // core's default of "balanced".
        spinnerNoize.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("off", "light", "balanced", "aggressive"),
        )
        spinnerSysprofile.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Auto", "Low", "Medium", "High"),
        )
        // Tor is an egress inside the Aether engine (AETHER_TOR), not a
        // separate backend. Positions map 1:1 onto FcaeTorMode.
        // "Tor only" is deliberately NOT here: it is the Tor entry of the
        // protocol list above, so it appears once.
        spinnerTor.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf(
                "Off",
                "Tor through the tunnel",
                "Tunnel through Tor (MASQUE only)",
                "Psiphon through the tunnel",
            ),
        )
        // Positions map 1:1 onto FcaeTorBridges.
        spinnerTorBridges.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("No bridges", "obfs4", "snowflake", "Custom lines"),
        )
        // Psiphon transport families. Index maps 1:1 onto
        // PsiphonTunnelService.transportProtocols(); 0 = Auto leaves
        // LimitTunnelProtocols unset (tunnel-core tries its full set).
        spinnerPsiphonTransport.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Auto", "SSH (OSSH)", "QUIC", "Unfronted meek", "Fronted meek"),
        )
        // Verbosity of the aether ENGINE. Positions map 1:1 onto
        // FcaeEngineLog; index 3 = info is the default.
        spinnerEngineLog.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Off", "Error", "Warn", "Info (default)", "Debug", "Trace"),
        )
        spinnerTorBridges.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                applyTorLock()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        // Record a region pick the moment it happens. Without this a later
        // refreshPsiphonRegions()/broadcast re-applied the OLD saved value and
        // the spinner snapped back, so selecting a region "didn't work".
        spinnerPsiphonRegion.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                if (applyingRegionList || position != spinnerPsiphonRegion.selectedItemPosition) return
                savedPsiphonRegion = psiphonRegionCodes.getOrElse(position) { savedPsiphonRegion }
                prefs.edit().putString("psiphonRegion", savedPsiphonRegion).apply()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        spinnerTor.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                applyTorLock()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        // loadSettings() reads ~40 views and, through refreshPsiphonRegions(),
        // makes the app's first native call. A failure anywhere in there used
        // to propagate out of onCreate and kill the process before any UI
        // existed, which looks like "crashes on open" with no clue why.
        //
        // None of it is load-bearing for showing the window: every value has a
        // default. So report the cause and carry on with defaults rather than
        // dying.
        try {
            loadSettings()
        } catch (t: Throwable) {
            android.util.Log.e("FCAE_VPN", "loadSettings failed; using defaults", t)
            Toast.makeText(this, "Settings failed to load: ${t.message}", Toast.LENGTH_LONG).show()
        }
        applyTorLock()

        // Running build, spelled out: version + which channel it is. A build
        // Compact "ver · type": a pre-release build stamps "-prerelease" into
        // the version itself, so show the base version and let the single
        // type word carry the channel — no duplication, no "(BETA)" shout.
        findViewById<TextView>(R.id.versionText).apply {
            val baseVersion = BuildConfig.APP_VERSION.substringBefore('-')
            text = "$baseVersion  \u00b7  ${if (buildIsPrerelease) "pre-release" else "release"}"
            setTextColor(Color.parseColor(if (buildIsPrerelease) "#FFF0B429" else "#FF8A93A6"))
        }

        // Mode changes re-evaluate the tor hint (and nothing else: no control
        // is ever locked or re-pointed; TUN simply ignores the SOCKS switch,
        // which the service forces on for tun2socks anyway).
        spinnerMode.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                applyModeSocksLock()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        applyModeSocksLock()

        // The protocol list owns "Tor only", so the tor hint (which port
        // carries tor traffic in proxy mode) must refresh on protocol change
        // too, not just on the egress spinner.
        spinnerProtocol.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>?,
                view: android.view.View?,
                position: Int,
                id: Long
            ) {
                // Gray unavailable egress entries (Psiphon protocol locks the
                // combo; Tor protocol grays the two Tor entries). Do not reset
                // the combo — restoring protocol restores the pick.
                applyTorLock()
                updateTorHint()
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }
        updateTorHint()

        onBackPressedDispatcher.addCallback(this, backPressedCallback)

        logText.text = ""
        lastLogHash = 0L

        btnConnect.setOnClickListener {
            if (vpnActive || engineRunning || connecting) disconnectAll() else connectClicked()
        }

        findViewById<MaterialButton>(R.id.btnLatestLogs).setOnClickListener {
            logText.clearFocus()
            if (logText.text is android.text.Spannable)
                android.text.Selection.removeSelection(logText.text as android.text.Spannable)
            logTouchActive = false
            wasAtBottom = true
            if (switchLogging.isChecked) renderLogs(try { NativeEngine.nativeGetLogs() } catch (_: Throwable) { logText.text.toString() })
            logScroll.requestLayout()
            logScroll.invalidate()
        }
        findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener {
            NativeEngine.nativeClearLogs()
            wasAtBottom = true
            logText.text = ""
            lastLogHash = 0L
        }

        findViewById<MaterialButton>(R.id.btnCopyLogs).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("FCAE Logs", logText.text)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show()
        }

        btnCheckUpdates.setOnClickListener {
            // If update check already completed and update is available,
            // show the dialog instead of checking again.
            val cached = updateAvailableInfo
            if (cached != null && cached.updateAvailable) {
                showUpdateDialog(cached)
            } else {
                checkForUpdates()
            }
        }

        updateButton()

        // Run after text layout/focus scrolling, not in a posted runnable that
        // can observe the old child height. Only a drag pauses following; a
        // tap/focus change must not silently turn it off.
        logScroll.viewTreeObserver.addOnPreDrawListener {
            if (!logTouchActive && !logText.hasSelection()) {
                val bottom = logBottom()
                if (logScroll.scrollY >= bottom - logBottomTolerance()) wasAtBottom = true
                if (wasAtBottom) logScroll.scrollTo(0, bottom)
            }
            true
        }

        val filter = IntentFilter().apply {
            addAction(FCAEVpnService.BROADCAST_VPN_DISCONNECTED)
            addAction(FCAEVpnService.BROADCAST_VPN_STATE_CHANGED)
            addAction(PsiphonTunnelService.BROADCAST_READY)
            addAction(PsiphonTunnelService.BROADCAST_FAILED)
            addAction(PsiphonTunnelService.BROADCAST_STOPPED)
            addAction(PsiphonTunnelService.BROADCAST_LOG)
            addAction(PsiphonTunnelService.BROADCAST_STAGE)
            addAction(PsiphonTunnelService.BROADCAST_STATS)
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnStateReceiver, filter)
        }

        // Init native engine on background thread, then check if VPN is already
        // running (e.g. service started from notification while app was closed,
        // or proxy mode engine was left running from a previous session).
        bgExecutor.execute {
            try {
                NativeEngine.nativeInit()
            } catch (e: Throwable) {
                handler.post {
                    Toast.makeText(this, "Native lib failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
                return@execute
            }

            // Query native state — if engine is running, sync UI to it.
            // Do NOT call nativeStop() here: if the service is keeping the
            // engine alive we must NOT kill it, and if the engine is truly
            // stale the user can disconnect from the UI.
            try {
                val state = NativeEngine.nativeGetState()
                // 1..4 = running, 6 = Reconnecting (session alive, the engine
                // is recovering on its own). Anything else is terminal.
                if (state in 1..4 || state == 6) {
                    handler.post {
                        vpnActive = true
                        engineRunning = true
                        connecting = state in 1..3 || state == 6
                        updateButton()
                        handler.post(poll)
                    }
                } else if (state == 0 || state == 5) {
                    // Engine is not running — ensure UI reflects that
                    handler.post {
                        vpnActive = false
                        engineRunning = false
                        connecting = false
                        updateButton()
                    }
                }
            } catch (_: Throwable) {
                // If we can't query state, assume disconnected
                handler.post {
                    vpnActive = false
                    engineRunning = false
                    connecting = false
                    updateButton()
                }
            }

            // Auto-trigger update check once on app open if enabled
            handler.post {
                if (switchAutoUpdate.isChecked) {
                    checkForUpdates()
                }
            }
        }
    }

    /** Catch the back button: if an EditText is focused, clear its focus
     *  first (which also hides the blinking cursor) before propagating
     *  the event to finish the activity. */
    private val backPressedCallback = object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
            val focused = currentFocus
            if (focused is android.widget.EditText) {
                clearEditTextFocus()
                return  // Consume the event — don't finish the activity yet
            }
            isEnabled = false
            onBackPressedDispatcher.onBackPressed()
            isEnabled = true
        }
    }

    override fun onPause() {
        super.onPause()
        inForeground = false
        logTouchActive = false
        // Clear any EditText focus so the blinking cursor doesn't stay
        // visible after the keyboard is dismissed.
        clearEditTextFocus()
        // Stop the JNI status/log poll while the UI is invisible — it was
        // previously only gated on vpnActive, so it kept firing every 5s
        // (JNI calls + TextView updates) even when the app was backgrounded.
        // The foreground service notification already covers the
        // "still connected" signal while we're not visible.
        handler.removeCallbacks(poll)
        saveSettings()
    }

    override fun onResume() {
        super.onResume()
        inForeground = true
        // Resume polling immediately if a tunnel is active, instead of
        // waiting up to the next tick or for a broadcast.
        // Check both vpnActive AND check native state to catch proxy mode
        // connections that are still alive after backgrounding.
        if (vpnActive || engineRunning) {
            // Verify the engine is actually still running before resuming poll
            bgExecutor.execute {
                try {
                    val state = NativeEngine.nativeGetState()
                    handler.post {
                        // 6 = Reconnecting is a live session: keep the UI
                        // active instead of resetting to DISCONNECTED while
                        // the engine is still recovering.
                        if (state in 1..4 || state == 6) {
                            vpnActive = true
                            engineRunning = true
                            connecting = state in 1..3 || state == 6
                            updateButton()
                            handler.removeCallbacks(poll)
                            // Force an immediate poll tick to refresh UI instantly
                            handler.post(poll)
                        } else {
                            // Engine died while we were in background
                            vpnActive = false
                            engineRunning = false
                            connecting = false
                            updateButton()
                            statusText.text = "DISCONNECTED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
                            statsText.text = ""
                            peerText.text = ""
                        }
                    }
                } catch (_: Throwable) {
                    handler.post {
                        vpnActive = false
                        engineRunning = false
                        connecting = false
                        updateButton()
                        statusText.text = "DISCONNECTED"
                        statusText.setTextColor(Color.parseColor("#8A93A6"))
                        statsText.text = ""
                        peerText.text = ""
                    }
                }
            }
        } else {
            // Even if no local flag is set, double-check native state
            // in case the engine was started externally (e.g., from notification)
            bgExecutor.execute {
                try {
                    val state = NativeEngine.nativeGetState()
                    if (state in 1..4 || state == 6) {
                        handler.post {
                            vpnActive = true
                            engineRunning = true
                            connecting = state in 1..3 || state == 6
                            updateButton()
                            handler.removeCallbacks(poll)
                            handler.post(poll)
                        }
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    /** Clear focus from any currently focused EditText and dismiss the soft
     *  keyboard.  Requests focus on the root layout so the system doesn't
     *  immediately re-assign focus back to the same EditText, which would
     *  leave the blinking text cursor (|) visible. */
    private fun clearEditTextFocus() {
        val focused = currentFocus
        if (focused is android.widget.EditText) {
            focused.clearFocus()
            // Move focus to the decor view (root) so the EditText cannot
            // immediately regain focus.
            window.decorView.requestFocus()
            val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.hideSoftInputFromWindow(focused.windowToken, 0)
        }
    }

    override fun onDestroy() {
        handler.removeCallbacks(poll)
        try { unregisterReceiver(vpnStateReceiver) } catch (_: Throwable) {}
        // In proxy mode, the engine is kept alive by ProxyNotification foreground service.
        // Do NOT stop it here — the proxy should continue running in the background.
        // In TUN mode, FCAEVpnService manages its own lifecycle.
        activityAlive = false
        super.onDestroy()
    }

    private fun isTunModeSelected(): Boolean = spinnerMode.selectedItemPosition == 1

    /**
     * SOCKS5 is mandatory in TUN mode: tun2socks dials the engine's local SOCKS5
     * listener for every connection (and the core also starts an internal SOCKS5
     * on 1819 when TUN is active). So while TUN is selected the SOCKS5 switch is
     * forced ON and grayed out, and the port field is locked too — the same
     * auto/locked behaviour the desktop UI has for its SOCKS5 checkbox.
     * Switching back to Proxy mode restores the user's own choice.
     */
    private fun applyModeSocksLock() {
        if (!::spinnerMode.isInitialized || !::switchSocks.isInitialized) return
        // No lock, no forced value: in TUN mode FCAEVpnService forces the
        // local SOCKS5 listener tun2socks dials ((mode==1 && port==0) ->
        // 1819), so the switch is simply ignored there.
        switchSocks.text = "SOCKS5 proxy"
        // The tor hint depends on which mode is active.
        updateTorHint()
    }

    /**
     * The egress combo and every Tor knob (bridges, bridge lines) stay fully
     * interactive in every combo: values the current mode/protocol cannot
     * use are simply ignored downstream, never grayed and never re-pointed
     * (round-12 policy, same as desktop).
     */
    private fun applyTorLock() {
        if (!::spinnerTor.isInitialized || !::spinnerTorBridges.isInitialized) return
        ensureEgressAdapter()
        updateTorHint()
    }

    /**
     * One-time plain adapter for the egress combo. Nothing is disabled,
     * nothing is gray: the four entries always render and select normally,
     * and combos the current protocol cannot use are ignored downstream.
     * Guarded on adapter==null so the selection is never disturbed.
     */
    private fun ensureEgressAdapter() {
        if (!::spinnerTor.isInitialized || spinnerTor.adapter != null) return
        val labels = listOf(
            "Off",
            "Tor through the tunnel",
            "Tunnel through Tor (MASQUE only)",
            "Psiphon through the tunnel",
        )
        val a = android.widget.ArrayAdapter(
            this, android.R.layout.simple_spinner_item, labels)
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerTor.adapter = a
    }

    /**
     * In TUN mode the traffic is routed to the right port internally, but in
     * proxy mode the user dials the ports by hand -- say which one actually
     * carries tor traffic, or the tor setting looks broken (they dial the
     * tunnel's plain port and wonder why it is not tor'ed).
     */
    private fun updateTorHint() {
        if (!::textTorHint.isInitialized || !::spinnerMode.isInitialized ||
            !::spinnerProtocol.isInitialized || !::spinnerTor.isInitialized) return
        val hint = if (spinnerMode.selectedItemPosition != 0) {
            "" // TUN mode: routing is automatic
        } else if (isPsiphonProtocol()) {
            "Psiphon reaches its servers on its own; tun2socks uses Psiphon SOCKS. Egress is unused."
        } else if (isTorOnly() && isEgressPsiphon()) {
            // user -> Psiphon -> Tor -> internet: the AAR dials its servers
            // through the Tor-only engine SOCKS (UpstreamProxyURL).
            "Psiphon chains through the Tor-only tunnel (UpstreamProxyURL): Tor first, then Psiphon exits."
        } else if (isEgressPsiphon()) {
            "Aether connects first; Psiphon then dials through Aether SOCKS (UpstreamProxyURL)."
        } else when (spinnerTor.selectedItemPosition) {
            1 -> "Proxy mode: point SOCKS clients at the Tor SOCKS port; the tunnel's own ports stay plain (un-tor'ed)."
            2 -> "Proxy mode: use the tunnel's SOCKS/HTTP ports as usual; tor is the carrier underneath them."
            else -> if (isTorOnly())
                "Proxy mode: dial the Tor SOCKS port; Tor has no WARP tunnel. Egress can chain Psiphon through it."
            else ""
        }
        textTorHint.text = hint
        textTorHint.visibility =
            if (hint.isEmpty()) android.view.View.GONE else android.view.View.VISIBLE
    }

    private fun saveSettings() {
        prefs.edit().apply {
            putInt("protocol", coreProtocolFromSelection())
            putInt("mode", spinnerMode.selectedItemPosition)
            putInt("scan", spinnerScan.selectedItemPosition)
            putInt("ipVersion", spinnerIpVersion.selectedItemPosition)
            putInt("noize", spinnerNoize.selectedItemPosition)
            putInt("tor", spinnerTor.selectedItemPosition)
            putInt("torBridges", spinnerTorBridges.selectedItemPosition)
            putString("torBridgeLines", editTorBridgeLines.text.toString().trim())
            putInt("engineLog", spinnerEngineLog.selectedItemPosition)
            putInt("backend", if (isPsiphonProtocol()) 1 else 0)
            putString("torSocksPort", editTorSocksPort.text.toString().trim())
            putString("psiphonRegion", selectedPsiphonRegion())
            putInt("psiphonTransport", selectedPsiphonTransportIndex())
            putString("psiphonSocksPort", editPsiphonSocksPort.text.toString().trim())
            putString("psiphonHttpPort", editPsiphonHttpPort.text.toString().trim())
            putBoolean("h2", h2FromSelection())
            putBoolean("ech", switchEch.isChecked)
            putBoolean("quick", switchQuick.isChecked)
            putBoolean("lan", switchLan.isChecked)
            putBoolean("logging", switchLogging.isChecked)
            putBoolean("socks", switchSocks.isChecked)
            putBoolean("torHttp", switchTorHttp.isChecked)
            putString("torHttpPort", editTorHttpPort.text.toString())
            putBoolean("http", switchHttp.isChecked)
            putBoolean("autoUpdate", switchAutoUpdate.isChecked)
            putBoolean("checkPreReleases", switchPreReleases.isChecked)
            putString("sni", editSni.text.toString().trim())
            putString("forcePeer", editForcePeer.text.toString().trim())
            putInt("sysprofile", spinnerSysprofile.selectedItemPosition)
            putString("socksPort", editSocksPort.text.toString())
            putString("httpPort", editHttpPort.text.toString())
            putString("tunDnsV4", editTunDnsV4.text.toString().trim())
            putString("tunDnsV6", editTunDnsV6.text.toString().trim())
            putString("team", editTeam.text.toString().trim())
            putString("accessToken", editAccessToken.text.toString().trim())
            putString("accessEmail", editAccessEmail.text.toString().trim())
            putString("routesFile", editRoutesFile.text.toString().trim())
            putString("routesInline", editRoutesInline.text.toString().trim())
            apply()
        }
    }

    private fun loadSettings() {
        spinnerProtocol.setSelection(
            selectionPositionFromPrefs(
                prefs.getInt("protocol", 0),
                prefs.getBoolean("h2", true),
                prefs.getInt("backend", 0),
            ))
        spinnerMode.setSelection(prefs.getInt("mode", 1))
        spinnerScan.setSelection(prefs.getInt("scan", 0))
        spinnerIpVersion.setSelection(prefs.getInt("ipVersion", 0))
        spinnerNoize.setSelection(prefs.getInt("noize", 2))
        // "Tor only" left the egress list: it is the Tor entry of the
        // protocol list now (position 4). A saved egress position of 3 (the
        // old "Tor only") maps back onto the protocol list, so an existing
        // setup keeps the same effective config. Psiphon ignores the tor
        // fields entirely, so there is nothing to migrate for that backend
        // -- the egress entry just resets to Off.
        val savedTor = prefs.getInt("tor", 0)
        if (savedTor > 3) {
            // Pre-Psiphon-egress: 3+ was the old "Tor only" egress entry.
            if (prefs.getInt("backend", 0) != 1) {
                spinnerProtocol.setSelection(4)
            }
            spinnerTor.setSelection(0)
        } else {
            // Restore the pick verbatim, whatever the protocol: entries the
            // protocol cannot use are ignored downstream, never re-pointed.
            spinnerTor.setSelection(savedTor.coerceIn(0, 3))
        }
        spinnerTorBridges.setSelection(prefs.getInt("torBridges", 0))
        editTorBridgeLines.setText(prefs.getString("torBridgeLines", ""))
        spinnerEngineLog.setSelection(prefs.getInt("engineLog", 3))
        editTorSocksPort.setText(prefs.getString("torSocksPort", "1821"))
        editPsiphonSocksPort.setText(prefs.getString("psiphonSocksPort", "0"))
        editPsiphonHttpPort.setText(prefs.getString("psiphonHttpPort", "0"))
        savedPsiphonRegion = prefs.getString("psiphonRegion", "") ?: ""
        refreshPsiphonRegions()
        spinnerPsiphonTransport.setSelection(prefs.getInt("psiphonTransport", 0).coerceIn(0, 4))
        switchEch.isChecked = prefs.getBoolean("ech", true)
        switchQuick.isChecked = prefs.getBoolean("quick", false)
        switchLan.isChecked = prefs.getBoolean("lan", false)
        switchLogging.isChecked = prefs.getBoolean("logging", true)
        switchSocks.isChecked = prefs.getBoolean("socks", true)
        switchTorHttp.isChecked = prefs.getBoolean("torHttp", false)
        editTorHttpPort.setText(prefs.getString("torHttpPort", "1822"))
        switchHttp.isChecked = prefs.getBoolean("http", true)
        switchAutoUpdate.isChecked = prefs.getBoolean("autoUpdate", true)
        switchPreReleases.isChecked = prefs.getBoolean("checkPreReleases", false)
        editSni.setText(prefs.getString("sni", ""))
        editForcePeer.setText(prefs.getString("forcePeer", ""))
        spinnerSysprofile.setSelection(prefs.getInt("sysprofile", 0))
        editSocksPort.setText(prefs.getString("socksPort", "1819"))
        editHttpPort.setText(prefs.getString("httpPort", "1820"))
        editTunDnsV4.setText(prefs.getString("tunDnsV4", FCAEVpnService.DEFAULT_TUN_DNS_V4))
        editTunDnsV6.setText(prefs.getString("tunDnsV6", FCAEVpnService.DEFAULT_TUN_DNS_V6))
        editTeam.setText(prefs.getString("team", ""))
        editAccessToken.setText(prefs.getString("accessToken", ""))
        editAccessEmail.setText(prefs.getString("accessEmail", ""))
        editRoutesFile.setText(prefs.getString("routesFile", ""))
        editRoutesInline.setText(prefs.getString("routesInline", ""))
    }

    private fun connectClicked() {
        if (disconnecting || connecting || engineRunning || vpnActive) return
        if (switchTorHttp.isChecked && (editTorHttpPort.text.toString().toIntOrNull() ?: 0) !in 1..65535) {
            editTorHttpPort.error = "Use a port from 1 to 65535"
            return
        }
        connectionEpoch++
        userInitiatedDisconnect = false
        commandPaused = false
        commandConnecting = true
        pendingPsiSocks = 0
        pendingPsiHttp = 0
        pendingPsiLan = ""
        if (isPsiphonSelected()) {
            if (isTunModeSelected()) {
                val prep = VpnService.prepare(this)
                if (prep != null) {
                    pendingAfterVpnPermission = true
                    vpnPermissionLauncher.launch(prep)
                    return
                }
            }
            startPsiphon()
            return
        }
        val mode = spinnerMode.selectedItemPosition
        if (mode == 1) {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                pendingAfterVpnPermission = true
                vpnPermissionLauncher.launch(prep)
                return
            }
            startTunServiceWithConfig()
        } else {
            startEngine()
        }
    }

    private fun startPsiphon() {
        startPsiphonWithUpstream(null)
    }

    /** AAR start. `upstream` is socks5://127.0.0.1:<aether> for through-tunnel. */
    private fun startPsiphonWithUpstream(upstream: String?) {
        if (upstream == null) {
            connecting = true
            vpnActive = true
            updateButton()
            saveSettings()
            resetPsiStats()
            statusText.text = "CONNECTING"
            statusText.setTextColor(COLOR_PROGRESS)
        }
        ingestPsiphonLog(
            if (upstream.isNullOrBlank()) "connecting"
            else "connecting through $upstream"
        )
        val i = Intent(this, PsiphonTunnelService::class.java)
        i.action = PsiphonTunnelService.ACTION_START
        i.putExtra("psiphonRegion", selectedPsiphonRegion())
        i.putExtra("psiphonTransport", selectedPsiphonTransportIndex())
        i.putExtra("lanSharing", switchLan.isChecked)
        i.putExtra("psiphonSocksPort", if (pendingPsiSocks > 0) pendingPsiSocks else editPsiphonSocksPort.text.toString().toIntOrNull() ?: 0)
        i.putExtra("psiphonHttpPort", if (pendingPsiHttp > 0) pendingPsiHttp else editPsiphonHttpPort.text.toString().toIntOrNull() ?: 0)
        if (!upstream.isNullOrBlank()) i.putExtra("upstreamProxy", upstream)
        if (upstream.isNullOrBlank()) {
            val owner = Intent(this, ProxyNotification::class.java).setAction(ProxyNotification.ACTION_PSIPHON)
            i.extras?.let { owner.putExtras(it) }
            startForegroundService(owner)
        } else {
            PsiphonTunnelService.startBound(this, i)
        }
    }

    private fun startTunServiceWithConfig() {
        // Cancel any pending disconnect fallback — we're connecting now.
        connecting = true
        vpnActive = true
        updateButton()
        saveSettings()
        val i = Intent(this, FCAEVpnService::class.java)
        i.action = FCAEVpnService.ACTION_START
        i.putExtra("protocol", coreProtocolFromSelection())
        i.putExtra("mode", spinnerMode.selectedItemPosition)
        i.putExtra("scanMode", spinnerScan.selectedItemPosition)
        i.putExtra("ipVersion", spinnerIpVersionToInt())
        i.putExtra("quickReconnect", switchQuick.isChecked)
        i.putExtra("h2Enabled", h2FromSelection())
        i.putExtra("echEnabled", switchEch.isChecked)
        i.putExtra("lanSharing", switchLan.isChecked)
        i.putExtra("configPath", filesDir.resolve("aether.toml").absolutePath)
        i.putExtra("sni", editSni.text.toString().trim())
        i.putExtra("socksPort", if (switchSocks.isChecked || isEgressPsiphon() || effectiveTorMode() in 1..2) editSocksPort.text.toString().toIntOrNull() ?: 1819 else 0)
        i.putExtra("httpPort", if (switchHttp.isChecked) editHttpPort.text.toString().toIntOrNull() ?: 1820 else 0)
        i.putExtra("noizeProfile", spinnerNoize.selectedItem.toString())
        i.putExtra("forcePeer", editForcePeer.text.toString().trim())
        i.putExtra("sysProfile", spinnerSysprofile.selectedItemPosition)
        i.putExtra("teamName", editTeam.text.toString().trim())
        i.putExtra("accessToken", editAccessToken.text.toString().trim())
        i.putExtra("accessEmail", editAccessEmail.text.toString().trim())
        i.putExtra("routesFile", editRoutesFile.text.toString().trim())
        i.putExtra("routesInline", editRoutesInline.text.toString().trim())
        i.putExtra("torMode", effectiveTorMode())
        i.putExtra("torBridges", spinnerTorBridges.selectedItemPosition)
        i.putExtra("torBridgeLines", editTorBridgeLines.text.toString().trim())
        i.putExtra("engineLog", spinnerEngineLog.selectedItemPosition)
        i.putExtra("backend", backendFromSelection())
        i.putExtra("torSocksPort", deferredTorSocksPort())
        i.putExtra("torHttpPort", if (switchTorHttp.isChecked) editTorHttpPort.text.toString().toIntOrNull() ?: 1822 else 0)
        i.putExtra("psiphonThroughTunnel", isEgressPsiphon())
        i.putExtra("psiphonConfig", org.json.JSONObject().put("FCAETransport", selectedPsiphonTransportIndex()).toString())
        i.putExtra("psiphonRegion", selectedPsiphonRegion())
        // Prefer the LIVE AAR ports: when this start is the Protocol=Psiphon
        // "raise TUN" step, the AAR already picked random ports and
        // pendingPsiSocks/pendingPsiHttp hold them. Reading only the edit
        // fields sent 0 here, the native Psiphon attach backend refused with
        // "Start PsiphonTunnelService first and pass its SOCKS port", and the
        // tunnel looked dead even though Psiphon was up.
        i.putExtra("psiphonSocksPort", if (pendingPsiSocks > 0) pendingPsiSocks else editPsiphonSocksPort.text.toString().toIntOrNull() ?: 0)
        i.putExtra("psiphonHttpPort", if (pendingPsiHttp > 0) pendingPsiHttp else editPsiphonHttpPort.text.toString().toIntOrNull() ?: 0)
        startForegroundService(i)
        // Poll is started by the VPN_STATE_CHANGED broadcast from the service
        // AFTER nativeStart() succeeds — NOT here, to avoid calling native
        // methods while the previous engine is still tearing down.
    }

    private fun startEngine() {
        // Cancel any pending disconnect fallback — we're connecting now.
        connecting = true
        vpnActive = true
        engineRunning = false  // will become true once poll confirms connected
        updateButton()
        saveSettings()

        // Start proxy notification foreground service for bandwidth stats
        val proxyIntent = Intent(this, ProxyNotification::class.java)
        proxyIntent.action = ProxyNotification.ACTION_START
        startForegroundService(proxyIntent)

        val protocol = coreProtocolFromSelection()
        val mode = spinnerMode.selectedItemPosition
        val scanMode = spinnerScan.selectedItemPosition
        val ipVersion = spinnerIpVersionToInt()
        val quick = switchQuick.isChecked
        val h2 = h2FromSelection()
        val ech = switchEch.isChecked
        val lan = switchLan.isChecked
        val sni = editSni.text.toString().trim()
        val cfgPath = filesDir.resolve("aether.toml").absolutePath
        // Extract ALL UI values on the main thread — never read Views from bg.
        val noizeProfile = spinnerNoize.selectedItem.toString()
        val socksPort = if (switchSocks.isChecked || isEgressPsiphon() || effectiveTorMode() in 1..2) editSocksPort.text.toString().toIntOrNull() ?: 1819 else 0
        val httpPort = if (switchHttp.isChecked) editHttpPort.text.toString().toIntOrNull() ?: 1820 else 0
        val forcePeer = editForcePeer.text.toString().trim()
        val sysProfile = spinnerSysprofile.selectedItemPosition
        val teamName = editTeam.text.toString().trim()
        val accessToken = editAccessToken.text.toString().trim()
        val accessEmail = editAccessEmail.text.toString().trim()
        val routesFile = editRoutesFile.text.toString().trim()
        val routesInline = editRoutesInline.text.toString().trim()
        val torMode = effectiveTorMode()
        val torBridges = spinnerTorBridges.selectedItemPosition
        val torBridgeLines = editTorBridgeLines.text.toString().trim()
        val engineLog = spinnerEngineLog.selectedItemPosition
        val backend = backendFromSelection()
        val torSocksPort = deferredTorSocksPort()
        val torHttpPort = if (switchTorHttp.isChecked) editTorHttpPort.text.toString().toIntOrNull() ?: 1822 else 0
        val throughPsiphon = isEgressPsiphon()
        val psiphonConfig = org.json.JSONObject().put("FCAETransport", selectedPsiphonTransportIndex()).toString()
        val psiphonRegion = selectedPsiphonRegion()
        val psiphonSocksPort = editPsiphonSocksPort.text.toString().toIntOrNull() ?: 0
        val psiphonHttpPort = editPsiphonHttpPort.text.toString().toIntOrNull() ?: 0

        val epoch = connectionEpoch
        NativeEngine.lifecycleExecutor.execute {
            if (epoch != connectionEpoch) return@execute
            // Schedule previous cleanup. Native start enforces the reaper
            // barrier; nativeStop itself returns before cleanup is finished.
            try { NativeEngine.nativeStop() } catch (_: Throwable) {}

            if (epoch != connectionEpoch) return@execute
            val ok = try {
                NativeEngine.nativeStart(
                    protocol = protocol,
                    mode = mode,
                    lanSharing = lan,
                    scanMode = scanMode,
                    ipVersion = ipVersion,
                    quickReconnect = quick,
                    noizeProfile = noizeProfile,
                    fragmentEnabled = false,
                    fragMinSize = 16,
                    fragMaxSize = 32,
                    fragMinDelay = 2,
                    fragMaxDelay = 10,
                    socksPort = socksPort,
                    httpPort = httpPort,
                    forcePeer = forcePeer,
                    configPath = cfgPath,
                    h2Enabled = h2,
                    echEnabled = ech,
                    sni = sni,
                    sysProfile = sysProfile,
                    teamName = teamName,
                    accessToken = accessToken,
                    accessEmail = accessEmail,
                    routesFile = routesFile,
                    routesInline = routesInline,
                    torMode = torMode,
                    torBridges = torBridges,
                    torBridgeLines = torBridgeLines,
                    engineLog = engineLog,
                    backend = backend,
                    torSocksPort = torSocksPort,
                    torHttpPort = torHttpPort,
                    psiphonThroughTunnel = throughPsiphon,
                    psiphonConfig = psiphonConfig,
                    psiphonRegion = psiphonRegion,
                    psiphonSocksPort = psiphonSocksPort,
                    psiphonHttpPort = psiphonHttpPort,
                )
            } catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Start failed: ${e.message}", Toast.LENGTH_LONG).show() }
                false
            }
            if (epoch != connectionEpoch) {
                try { NativeEngine.nativeStop() } catch (_: Throwable) {}
                return@execute
            }
            handler.post {
                if (epoch != connectionEpoch) return@post
                if (!ok) {
                    connecting = false
                    vpnActive = false
                    engineRunning = false
                    // Stop proxy notification service since engine failed
                    try { stopService(Intent(this@MainActivity, ProxyNotification::class.java)) } catch (_: Throwable) {}
                    Toast.makeText(this, "Failed to start engine", Toast.LENGTH_SHORT).show()
                } else {
                    // In proxy mode, there's no service broadcast to set engineRunning=true.
                    // Set it optimistically so the poll starts. The poll itself will
                    // update engineRunning based on actual native state.
                    engineRunning = true
                    handler.post(poll)
                }
                updateButton()
            }
        }
    }

    private fun disconnectAll() {
    if (disconnecting) return
    disconnecting = true
    connectionEpoch++
    userInitiatedDisconnect = true
    commandPaused = false
    commandConnecting = false

    // 1. UI updates happen INSTANTLY on main thread
    vpnActive = false
    engineRunning = false
    connecting = false
    handler.removeCallbacks(poll)
    updateButton()
    
    statusText.text = "DISCONNECTED"
    statusText.setTextColor(Color.parseColor("#8A93A6"))
    statsText.text = ""
    peerText.text = ""

    try {
        PsiphonTunnelService.stopBound(this)
    } catch (_: Throwable) {}

    // 2. Trigger disconnect on a background thread
    val currentMode = spinnerMode.selectedItemPosition
    val psiphonBooting = pendingPsiSocks == 0 && isPsiphonSelected()
    Thread({
        if (currentMode == 1) {
            // TUN mode: fullShutdown() handles nativeStop + nativeFree
            val hadVpnService = FCAEVpnService.disconnectNow()
            if (!hadVpnService && !psiphonBooting) ProxyNotification.notifyCleanupComplete(this)
            if (psiphonBooting) {
                val stop = Intent(this, ProxyNotification::class.java).setAction(ProxyNotification.ACTION_STOP)
                try { startForegroundService(stop) } catch (e: Exception) {
                    android.util.Log.w("FCAE", "Cannot deliver proxy Stop", e)
                    ProxyNotification.notifyCleanupComplete(this)
                }
            }
        } else {
            // Proxy mode: stopProxy() handles nativeStop + nativeFree.
            //
            // startForegroundService, not startService: (a) startService from
            // a backgrounded app is blocked on Android 12+, and the old
            // catch-all silently swallowed that — the engine kept running
            // while the UI showed DISCONNECTED; (b) if the notification
            // service already died (watchdog teardown, system reclaim), this
            // restarts it, stopProxy() runs, and its disconnect broadcast
            // reaches the UI — self-healing a stuck "CONNECTED" state.
            try {
                val i = Intent(this, ProxyNotification::class.java)
                i.action = ProxyNotification.ACTION_STOP
                startForegroundService(i)
            } catch (_: Throwable) {}
        }
    }, "Disconnect-Background").start()
}

    private fun checkForUpdates() {
        btnCheckUpdates.isEnabled = false
        btnCheckUpdates.text = "Checking..."
        updateStatus.visibility = android.view.View.VISIBLE
        updateStatus.text = "Checking for updates..."
        updateAvailableInfo = null  // Clear cached info on new check

        // Use the core's native async update checker (reqwest-based HTTP fetch).
        // The core spawns a background tokio runtime, fetches version.json from
        // GitHub, parses it, and stores the result. We poll with nativePollUpdate().
        // Channel gate is the user's toggle: off = stable slot only; on = both
        // slots compete and the higher version wins (engine: compare_versions).
        NativeEngine.nativeCheckForUpdates(BuildConfig.APP_VERSION, switchPreReleases.isChecked)

        // Poll for result on a background thread
        Thread {
            try {
                // Wait up to ~15 seconds for the check to complete.
                // Poll FIRST, then sleep — the old loop slept 500ms before
                // its first look, so even an instant result took 500ms+ to
                // show. 333ms cadence keeps the result display snappy.
                var info: FcaeUpdateInfo? = null
                for (i in 0..45) {
                    val poll = NativeEngine.nativePollUpdate()
                    if (poll.checkDone) {
                        info = poll
                        break
                    }
                    Thread.sleep(333)
                }
                if (info == null) {
                    val poll = NativeEngine.nativePollUpdate()
                    info = poll
                }

                handler.post {
                    btnCheckUpdates.isEnabled = true
                    if (info.updateAvailable) {
                        btnCheckUpdates.text = if (info.isPrerelease) "Pre-release!" else "Update Available!"
                        btnCheckUpdates.setTextColor(COLOR_UPDATE_AVAILABLE)
                        updateStatus.text = info.statusMessage
                        // Don't auto-show dialog — just update the button.
                        // User clicks the button to open the dialog.
                        updateAvailableInfo = info
                    } else if (info.checkDone) {
                        btnCheckUpdates.text = "Check for Updates"
                        btnCheckUpdates.setTextColor(COLOR_UPDATE_IDLE)
                        updateStatus.text = "Up to date (${info.statusMessage})"
                        updateAvailableInfo = null
                    } else {
                        btnCheckUpdates.text = "Check for Updates"
                        btnCheckUpdates.setTextColor(COLOR_UPDATE_IDLE)
                        updateStatus.text = "Check timed out"
                        updateAvailableInfo = null
                    }
                }
            } catch (e: Throwable) {
                handler.post {
                    btnCheckUpdates.isEnabled = true
                    btnCheckUpdates.text = "Check for Updates"
                    btnCheckUpdates.setTextColor(COLOR_UPDATE_IDLE)
                    updateStatus.text = "Update check failed: ${e.message}"
                }
            }
        }.start()
    }

    private fun showUpdateDialog(info: FcaeUpdateInfo) {
        val msg = buildString {
            append("Current: ${BuildConfig.APP_VERSION}  (${if (buildIsPrerelease) "pre-release" else "release"})\n")
            append("Latest: ${info.latestVersion}  (${if (info.isPrerelease) "pre-release" else "release"})\n")
            if (info.releaseDate.isNotEmpty()) append("Released: ${info.releaseDate}\n")
            append("\n")
            if (info.releaseNotes.isNotEmpty()) {
                append("Release Notes:\n${info.releaseNotes}\n\n")
            }
            if (info.downloadUrl.isNotEmpty()) {
                append("Download: ${info.downloadUrl}")
            }
        }
        val dialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Update Available")
            .setMessage(msg)
            .setPositiveButton("Open Release Page") { _, _ ->
                if (info.downloadUrl.isNotEmpty()) {
                    try {
                        val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(info.downloadUrl))
                        startActivity(intent)
                    } catch (_: Throwable) {
                        Toast.makeText(this, "Cannot open URL", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Close", null)
            .create()
        // Allow dismissing by tapping outside the dialog
        dialog.setCanceledOnTouchOutside(true)
        dialog.show()
        // Force the message and button text to white (theme default was dark blue)
        dialog.findViewById<TextView>(android.R.id.message)?.setTextColor(Color.WHITE)
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE)?.setTextColor(Color.CYAN)
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEGATIVE)?.setTextColor(Color.CYAN)
    }

    /** AAR notices arrive from :psiphon. The engine log deque lives here. */
    private fun ingestPsiphonLog(chunk: String) {
        if (chunk.isBlank()) return
        try { NativeEngine.nativeAppendLog(chunk) } catch (_: Throwable) {}
        if (!::switchLogging.isInitialized || !switchLogging.isChecked) return
        val logs = try { NativeEngine.nativeGetLogs().takeLast(MAX_LOG_CHARS) } catch (_: Throwable) { return }
        renderLogs(logs)
    }

    private fun logBottomTolerance() = (4 * resources.displayMetrics.density).toInt()

    private fun logBottom(): Int {
        val child = logScroll.getChildAt(0) ?: return 0
        val viewport = logScroll.height - logScroll.paddingTop - logScroll.paddingBottom
        return (child.height - viewport).coerceAtLeast(0)
    }

    override fun dispatchTouchEvent(event: android.view.MotionEvent): Boolean {
        if (::logScroll.isInitialized) {
            when (event.actionMasked) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    val location = IntArray(2)
                    logScroll.getLocationOnScreen(location)
                    logTouchActive = event.rawX >= location[0] &&
                        event.rawX < location[0] + logScroll.width &&
                        event.rawY >= location[1] && event.rawY < location[1] + logScroll.height
                    logTouchStartY = event.rawY
                    // The log ScrollView is nested inside the settings scroll.
                    // Keep drags in this pane instead of letting its parent
                    // intercept them after a tap has focused the selectable text.
                    if (logTouchActive) logScroll.parent.requestDisallowInterceptTouchEvent(true)
                }
                android.view.MotionEvent.ACTION_MOVE -> {
                    if (logTouchActive && kotlin.math.abs(event.rawY - logTouchStartY) >
                        android.view.ViewConfiguration.get(this).scaledTouchSlop) {
                        wasAtBottom = false
                    }
                }
                android.view.MotionEvent.ACTION_UP, android.view.MotionEvent.ACTION_CANCEL -> {
                    logTouchActive = false
                    logScroll.parent.requestDisallowInterceptTouchEvent(false)
                }
            }
        }
        return super.dispatchTouchEvent(event)
    }

    /** Both native polling and AAR notices use this one layout-safe path. */
    private fun renderLogs(logs: String) {
        // Keep selection stable while copying. The native ring still receives
        // every notice; the next poll catches up when interaction ends.
        if (logTouchActive || logText.hasSelection()) return
        val shown = logs.takeLast(MAX_LOG_CHARS)
        val h = shown.hashCode().toLong()
        if (h == lastLogHash) return
        lastLogHash = h
        logText.text = shown
        // The pre-draw listener follows using the newly laid-out child height.
    }

    private fun applyStatus(
        state: Int,
        rtt: Int,
        rx: Long,
        tx: Long,
        totalRx: Long,
        totalTx: Long,
        peer: String,
        lan: String,
        statusMsg: String,
        errMsg: String,
        logs: String
    ) {
        try {
            // Update engine state based on native telemetry.
            // In proxy mode, this is the ONLY source of truth — there are no
            // service broadcasts. In TUN mode, broadcasts may also update
            // these, but the poll always has the freshest data.
            if (commandPaused) {
                // Notification Stop owns the UI until Start/Disconnect.
                engineRunning = false
                connecting = false
                vpnActive = false
                statusText.text = "STOPPED"
                statusText.setTextColor(Color.parseColor("#8A93A6"))
                updateButton()
                return
            }
            if (vpnActive) {
                // State 6 = Reconnecting: the session is still alive and the
                // engine is recovering the tunnel on its own. Treat it as an
                // active session (button stays DISCONNECT), not a dead one —
                // showing CONNECT here invited a second session on top of a
                // live one.
                engineRunning = state in 1..4 || state == 6
                connecting = state in 1..3 || state == 6 || commandConnecting
                // Psiphon reports its egress regions only after a successful
                // handshake, so this is the first moment the real list can be
                // read. Cheap and idempotent: it no-ops unless the set changed.
                if (state == 4 && (isPsiphonSelected() || isEgressPsiphon())) refreshPsiphonRegions()
                // Detect engine stopped while we thought it was active.
                // 0 = idle/stopped, 5 = terminal error. The FFI keeps state
                // 5 sticky after the session thread ends, so without the 5
                // check vpnActive would survive a dead engine and the first
                // tap on the (CONNECT-looking) button would call
                // disconnectAll() instead of connecting.
                if ((state == 0 || state == 5) && !userInitiatedDisconnect && !commandConnecting) {
                    // Engine died on its own — reset state
                    vpnActive = false
                    engineRunning = false
                    connecting = false
                    handler.removeCallbacks(poll)
                }
            }

            val label = when (state) {
                0 -> "DISCONNECTED"
                1 -> "PROVISIONING"
                2 -> "SCANNING"
                3 -> "CONNECTING"
                4 -> {
                    val isTun = spinnerMode.selectedItemPosition == 1
                    if (statusMsg.isNotBlank()) statusMsg.uppercase()
                    else if (isTun) "CONNECTED (TUN)" else "CONNECTED (PROXY)"
                }
                5 -> "ERROR"
                6 -> "RECONNECTING"
                else -> "UNKNOWN"
            }
            // If error state, show the error message directly instead of label + message concatenation
            if (state == 5 && errMsg.isNotEmpty()) {
                statusText.text = "ERROR: $errMsg"
            } else if (state == 4) {
                statusText.text = label
            } else {
                statusText.text = if (statusMsg.isNotEmpty() && state != 0) "$label \u2014 $statusMsg" else label
            }
            statusText.setTextColor(
                when (state) {
                    4 -> COLOR_CONNECTED
                    5 -> COLOR_ERROR
                    0 -> COLOR_DISCONNECTED
                    else -> COLOR_PROGRESS
                },
            )
            if (isPsiphonSelected() || isEgressPsiphon()) {
                // Owned by BROADCAST_STATS from :psiphon — writing native
                // zeros here would step on the live tunnel telemetry.
            } else {
                statsText.text =
                    "\u2193 ${fmt(rx)}/s (${fmt(totalRx)})  |  \u2191 ${fmt(tx)}/s (${fmt(totalTx)})  |  RTT ${if (rtt > 0) "${rtt}ms" else "\u2014"}"
            }

            // Build peer line — include LAN proxy addresses when sharing is on
            val peerLine = StringBuilder()
            peerLine.append("Peer: ${peer.ifEmpty { " \u2014 " }}")
            // Show only listeners belonging to the active backend. Tor-only
            // has its own SOCKS port; Psiphon has ports assigned by its service.
            if (state == 4 && !isPsiphonSelected()) {
                fun endpoints(backend: String, socks: String?, http: String?) {
                    val local = mutableListOf<String>()
                    val shared = mutableListOf<String>()
                    fun add(kind: String, port: String) {
                        local.add("$kind 127.0.0.1:$port")
                        if (switchLan.isChecked && lan.isNotEmpty() && lan != "127.0.0.1") shared.add("$kind $lan:$port")
                    }
                    socks?.let { add("SOCKS5", it) }
                    http?.let { add("HTTP", it) }
                    if (local.isNotEmpty()) peerLine.append("\n$backend local: " + local.joinToString(" | "))
                    if (shared.isNotEmpty()) peerLine.append("\n$backend LAN: " + shared.joinToString(" | "))
                }
                if (!isTorOnly()) endpoints("Aether",
                    if (switchSocks.isChecked || isTunModeSelected() || isEgressPsiphon() || effectiveTorMode() in 1..2)
                        editSocksPort.text.toString().trim().ifEmpty { "1819" } else null,
                    if (switchHttp.isChecked) editHttpPort.text.toString().trim().ifEmpty { "1820" } else null)
                if (isTorOnly() || effectiveTorMode() in 1..2) endpoints("Tor",
                    editTorSocksPort.text.toString().trim().ifEmpty { "1821" },
                    if (switchTorHttp.isChecked) editTorHttpPort.text.toString() else null)
            }
            if (state == 4 && (isPsiphonSelected() || isEgressPsiphon()) && pendingPsiSocks > 0)
                peerLine.append("\n" + psiphonEndpointText())
            // Only append error here if not already shown in statusText (state 5 = ERROR)
            if (errMsg.isNotEmpty() && state != 5) peerLine.append("\nError: $errMsg")
            peerText.text = peerLine.toString()

            renderLogs(logs)
            updateButton()
        } catch (e: Throwable) {
            statusText.text = "UI error: ${e.message}"
        }
    }

    private fun psiphonEndpointText(): String {
        val local = mutableListOf<String>()
        val shared = mutableListOf<String>()
        if (pendingPsiSocks > 0) {
            local.add("SOCKS5 127.0.0.1:$pendingPsiSocks")
            if (pendingPsiLan.isNotEmpty()) shared.add("SOCKS5 $pendingPsiLan:$pendingPsiSocks")
        }
        if (pendingPsiHttp > 0) {
            local.add("HTTP 127.0.0.1:$pendingPsiHttp")
            if (pendingPsiLan.isNotEmpty()) shared.add("HTTP $pendingPsiLan:$pendingPsiHttp")
        }
        return "Psiphon local: " + local.joinToString(" | ") +
            if (shared.isEmpty()) "" else "\nPsiphon LAN: " + shared.joinToString(" | ")
    }

    private fun updateButton() {
        btnConnect.isEnabled = !disconnecting
        if (disconnecting) {
            btnConnect.text = "DISCONNECTING"
            return
        }
        if (vpnActive || engineRunning || connecting) {
            btnConnect.text = "DISCONNECT"
            btnConnect.setBackgroundColor(COLOR_DISCONNECT_BTN)
        } else {
            btnConnect.text = "CONNECT"
            btnConnect.setBackgroundColor(COLOR_CONNECT_BTN)
        }
    }

    /** Map spinner position to the ip_version value the engine expects.
     *  Position 0 = IPv4 (4), 1 = IPv6 (6), 2 = Dual Stack (10). */
    private fun spinnerIpVersionToInt(): Int = when (spinnerIpVersion.selectedItemPosition) {
        0 -> 4    // IPv4 only
        1 -> 6    // IPv6 only
        2 -> 10   // Dual Stack (both)
        else -> 4
    }

    // ── Protocol spinner mapping (H2 folded into the list) ────────────────
    // Spinner: 0 = MASQUE (HTTP/3), 1 = MASQUE (HTTP/2), 2 = WireGuard,
    //          3 = WARP-in-WARP. The core/FFI still takes the same two
    //  fields it always did: protocol (0=masque, 1=wg, 2=gool) + h2Enabled.
    private fun coreProtocolFromSelection(): Int = when (spinnerProtocol.selectedItemPosition) {
        2 -> 1    // WireGuard
        3 -> 2    // WARP-in-WARP
        6, 7 -> 5 // MASQUE-in-MASQUE
        4 -> 4    // Tor (FcaeProtocol::Tor; implies tor.mode = Only)
        5 -> 3    // Psiphon picks its own transport (FcaeProtocol::Auto)
        else -> 0 // MASQUE (either HTTP version)
    }

    /** 0 = Aether, 1 = Psiphon. Only the Psiphon entry switches backend. */
    private fun isTorOnly(): Boolean =
        ::spinnerProtocol.isInitialized && spinnerProtocol.selectedItemPosition == 4

    private fun isPsiphonProtocol(): Boolean =
        ::spinnerProtocol.isInitialized && spinnerProtocol.selectedItemPosition == 5

    /**
     * Egress "Psiphon through the tunnel": valid with any Aether-backed
     * protocol — WARP transports AND Protocol=Tor (the chain then runs
     * Aether(Tor-only) -> Psiphon). Only Protocol=Psiphon excludes it, since
     * there is no engine to chain through then.
     */
    private fun isEgressPsiphon(): Boolean =
        ::spinnerTor.isInitialized && !isPsiphonProtocol() &&
            spinnerTor.selectedItemPosition == 3

    /**
     * Only Protocol=Psiphon runs the Psiphon attach backend. Egress "Psiphon
     * through the tunnel" keeps backend Aether: the engine session stays up
     * and the supervisor requests the AAR exit through the foreground owner.
     * Its _reserved[0] flag now follows the same routing as desktop.
     */
    private fun backendFromSelection(): Int =
        if (isPsiphonProtocol()) 1 else 0

    /** Protocol Psiphon only. Egress Psiphon starts Aether first, then the AAR. */
    private fun isPsiphonSelected(): Boolean = isPsiphonProtocol()

    /** Tor modes 1/2 only. Protocol Tor/Psiphon and egress Psiphon send Off. */
    private fun effectiveTorMode(): Int {
        if (isTorOnly() || isPsiphonProtocol() || isEgressPsiphon()) return 0
        val p = if (::spinnerTor.isInitialized) spinnerTor.selectedItemPosition else 0
        return if (p in 0..2) p else 0
    }

    /**
     * Tor SOCKS port to hand the engine: 0 = "use the engine default"
     * (config.rs DEFAULT_TOR_SOCKS_PORT). The field mirrors that default
     * (1821) for display/editing; an untouched/blank/unparseable field — or
     * one set back to the default — defers to the engine instead of pinning
     * the literal, so a future engine-default bump can't strand configs.
     * Any other explicit value travels as-is.
     */
    private fun deferredTorSocksPort(): Int {
        val t = if (::editTorSocksPort.isInitialized) editTorSocksPort.text.toString().trim() else ""
        val p = t.toIntOrNull() ?: return 0
        return if (p == TOR_SOCKS_ENGINE_DEFAULT) 0 else p
    }

    /** The ISO code currently chosen, or "" for automatic. */
    private fun selectedPsiphonRegion(): String {
        if (applyingRegionList) return savedPsiphonRegion
        if (!::spinnerPsiphonRegion.isInitialized) return savedPsiphonRegion
        val i = spinnerPsiphonRegion.selectedItemPosition
        return psiphonRegionCodes.getOrElse(i) { "" }
    }

    /** Transport spinner position: 0 = Auto, 1 = SSH/OSSH, 2 = QUIC,
     *  3 = unfronted meek, 4 = fronted meek (matches the XML entries and
     *  PsiphonTunnelService.transportProtocols). */
    private fun selectedPsiphonTransportIndex(): Int =
        if (!::spinnerPsiphonTransport.isInitialized)
            prefs.getInt("psiphonTransport", 0)
        else spinnerPsiphonTransport.selectedItemPosition

    /**
     * Rebuild the region list from the core.
     *
     * Psiphon only learns which egress regions exist after a successful
     * handshake, so before the first connect this is just "Auto". Called on
     * load and again once connected, which is when the real list appears.
     */
    private fun refreshPsiphonRegions() {
        if (!::spinnerPsiphonRegion.isInitialized) return
        // Catch Throwable, not Exception: this runs from loadSettings() during
        // onCreate, before the background nativeInit(), so the very first call
        // may be what loads libfcaevpn_native.so. A missing library raises
        // UnsatisfiedLinkError -- an Error, not an Exception -- which would
        // escape a narrower catch and kill the app on launch. The region list
        // is cosmetic until Psiphon connects, so degrade to "Auto".
        val codes = try {
            NativeEngine.nativePsiphonRegions()
                .split(',')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        } catch (t: Throwable) {
            android.util.Log.w("FCAE_VPN", "psiphon regions unavailable: $t")
            emptyList()
        }

        // The core list is authoritative whenever non-empty (engine-side
        // psiphon). On Android it stays empty because psiphon runs in the
        // AAR service, whose broadcasts deliver the regions instead — an
        // empty reply must never shrink the learned + persisted list,
        // otherwise the spinner collapses to "Auto" and the chosen region
        // appears to be forgotten after every connect.
        if (codes.isNotEmpty()) persistRegionCodes(codes)
        applyPsiphonRegionCodes(listOf("") + if (codes.isNotEmpty()) codes else persistedRegionCodes())
    }

    /** Egress regions learned so far, persisted across restarts. Written only
     *  from authoritative sources (service broadcast / non-empty core list). */
    private fun persistedRegionCodes(): List<String> =
        (prefs.getString("psiphonRegionList", "") ?: "")
            .split(',').map { it.trim() }.filter { it.isNotEmpty() }

    private fun persistRegionCodes(codes: List<String>) =
        prefs.edit().putString("psiphonRegionList", codes.joinToString(",")).apply()

    /** Rebuild the region spinner. Always runs so each connect can refresh. */
    private fun applyPsiphonRegionList(csv: String) {
        savedPsiphonRegion = selectedPsiphonRegion()
        val codes = csv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        // Authoritative service list: persist (regions survive restarts) and
        // fall back to what is already stored on the odd empty broadcast.
        if (codes.isNotEmpty()) persistRegionCodes(codes)
        applyPsiphonRegionCodes(listOf("") + if (codes.isNotEmpty()) codes else persistedRegionCodes())
    }

    private fun applyPsiphonRegionCodes(newCodes: List<String>) {
        if (!::spinnerPsiphonRegion.isInitialized) return
        val want = savedPsiphonRegion.trim().uppercase()
        // Canonical order makes repeated/reordered network notices a no-op.
        // Keep an explicit saved choice even if temporarily absent upstream.
        val normalized = listOf("") + (newCodes + listOf(want))
            .map { it.trim().uppercase() }.filter { it.isNotEmpty() }.distinct().sorted()
        if (spinnerPsiphonRegion.adapter != null && normalized == psiphonRegionCodes) return
        if (spinnerPsiphonRegion.adapter != null && !hasWindowFocus()) {
            pendingRegionCodes = normalized
            return // a popup is open; don't rebuild underneath the user's finger
        }
        pendingRegionCodes = null
        applyingRegionList = true
        psiphonRegionCodes = normalized
        spinnerPsiphonRegion.adapter = ArrayAdapter(this,
            android.R.layout.simple_spinner_dropdown_item,
            normalized.map { if (it.isEmpty()) "Auto" else it })
        spinnerPsiphonRegion.setSelection(normalized.indexOf(want).coerceAtLeast(0), false)
        savedPsiphonRegion = want
        spinnerPsiphonRegion.post { applyingRegionList = false }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && ::spinnerPsiphonRegion.isInitialized) pendingRegionCodes?.let {
            // A popup can return window focus before onItemSelected is dispatched.
            // Read its new selection before applying the deferred network list.
            savedPsiphonRegion = selectedPsiphonRegion()
            applyPsiphonRegionCodes(it)
        }
    }

    private fun h2FromSelection(): Boolean = spinnerProtocol.selectedItemPosition in listOf(1, 7)

    /** Old saved prefs keep protocol (0-2) + h2 (bool); map back to the
     *  spinner position so existing configs load unchanged.
     *
     *  The mapping is no longer a simple +1 now that Tor (core 4) and Psiphon
     *  (core 3, via the backend) sit at the end of the list. */
    private fun selectionPositionFromPrefs(protocol: Int, h2: Boolean, backend: Int = 0): Int =
        when {
            backend == 1 -> 5          // Psiphon
            protocol == 5 -> if (h2) 7 else 6
            protocol == 4 -> 4         // Tor only
            protocol == 0 -> if (h2) 1 else 0
            else -> protocol + 1       // 1=wg -> 2, 2=gool -> 3
        }

    // Manual formatting avoids String.format() which creates a Formatter +
    // StringBuilder internally on every call — this runs 4× per poll tick.
    private fun fmt(bps: Long): String {
        return when {
            bps >= 1_073_741_824L -> {
                val v = bps / 1_073_741_824.0
                val whole = v.toLong()
                val frac = ((v - whole) * 10.0).toLong()
                "$whole.$frac GB"
            }
            bps >= 1_048_576L -> {
                val v = bps / 1_048_576.0
                val whole = v.toLong()
                val frac = ((v - whole) * 10.0).toLong()
                "$whole.$frac MB"
            }
            bps >= 1024L -> {
                val v = bps / 1024.0
                "${v.toLong()} KB"
            }
            else -> "$bps B"
        }
    }

    companion object {
        private const val POLL_INTERVAL_MS = 1000L
        // ~70+ log messages on screen. Psiphon's JSON notices average
        // 150-350 chars, so 8000 showed only ~20-30 lines and older lines
        // (handshake, CandidateServers) scrolled away before the connect
        // verdict was visible.
        private const val MAX_LOG_CHARS = 24000

        // Display default for the Tor SOCKS port field — equal to the aether
        // engine's own default (config.rs DEFAULT_TOR_SOCKS_PORT). A field
        // holding this value defers to the engine (see deferredTorSocksPort).
        private const val TOR_SOCKS_ENGINE_DEFAULT = 1821

        // Set to true while the Activity is alive.  The service checks
        // this after fullShutdown() to decide whether to kill the process.
        @JvmField @Volatile var activityAlive = false

        // Pre-computed Color constants — avoids String.parseColor() on every poll tick.
        private val COLOR_CONNECTED = Color.parseColor("#34D399")
        private val COLOR_ERROR = Color.parseColor("#F87171")
        private val COLOR_DISCONNECTED = Color.parseColor("#8A93A6")
        private val COLOR_PROGRESS = Color.parseColor("#60A5FA")
        private val COLOR_DISCONNECT_BTN = Color.parseColor("#B91C1C")
        private val COLOR_CONNECT_BTN = Color.parseColor("#15803D")
        private val COLOR_UPDATE_AVAILABLE = Color.parseColor("#FF8C00")  // orange
        private val COLOR_UPDATE_IDLE = Color.parseColor("#60A5FA")        // blue theme
    }
}
