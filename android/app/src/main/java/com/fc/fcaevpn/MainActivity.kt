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
    private var lastLogHash = 0L
    @Volatile private var vpnActive = false
    private var wasAtBottom = true
    private var updatingLogs = false
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
    private lateinit var editTorBridgeLines: android.widget.EditText
    private lateinit var spinnerEngineLog: Spinner
    private lateinit var editTorSocksPort: android.widget.EditText
    private lateinit var editPsiphonConfig: android.widget.EditText
    private lateinit var spinnerPsiphonRegion: Spinner
    private lateinit var editPsiphonSocksPort: android.widget.EditText
    private lateinit var editPsiphonHttpPort: android.widget.EditText
    /// Regions currently offered, index 0 always "Auto" (empty code).
    private var psiphonRegionCodes: List<String> = listOf("")
    /// Region chosen before the list was known, restored once it arrives.
    private var savedPsiphonRegion: String = ""
    private lateinit var switchEch: SwitchMaterial
    private lateinit var switchQuick: SwitchMaterial
    private lateinit var switchLan: SwitchMaterial
    private lateinit var switchLogging: SwitchMaterial
    private lateinit var switchSocks: SwitchMaterial
    private lateinit var switchHttp: SwitchMaterial
    private lateinit var switchAutoUpdate: SwitchMaterial
    private lateinit var switchPreRelease: SwitchMaterial
    private lateinit var spinnerSysprofile: Spinner
    private lateinit var editSni: android.widget.EditText
    private lateinit var editForcePeer: android.widget.EditText
    private lateinit var editSocksPort: android.widget.EditText
    private lateinit var editHttpPort: android.widget.EditText
    private lateinit var editTeam: android.widget.EditText
    private lateinit var editAccessToken: android.widget.EditText
    private lateinit var editAccessEmail: android.widget.EditText
    private lateinit var editRoutesFile: android.widget.EditText
    private lateinit var editRoutesInline: android.widget.EditText
    private lateinit var outerScroll: ScrollView

    // TUN mode always needs the engine's local SOCKS5 listener (tun2socks dials
    // it), so while TUN is selected the SOCKS5 switch is forced ON and shown
    // grayed out — the same "auto" behaviour the desktop UI has. The user's own
    // Proxy-mode choice is remembered here and restored when they switch back.
    private var socksChoiceForProxyMode = true

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
            startTunServiceWithConfig()
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

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                FCAEVpnService.BROADCAST_VPN_DISCONNECTED,
                FCAEVpnService.BROADCAST_VPN_STATE_CHANGED -> {
                    val isRunning = intent.getBooleanExtra("running", false)
                    val isPaused = intent.getBooleanExtra("paused", false)
                    val gen = intent.getLongExtra("generation", 0)

                    handler.post {
                        // Ignore stale broadcasts from a previous
                        // connect/disconnect cycle.
                        if (gen < lastBroadcastGeneration) return@post

                        if (!isRunning && !isPaused) {

                            lastBroadcastGeneration = gen
                            connecting = false
                            engineRunning = false
                            vpnActive = false
                            updateButton()
                            statusText.text = "DISCONNECTED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
                            statsText.text = ""
                            peerText.text = ""
                            handler.removeCallbacks(poll)
                        } else if (isRunning) {
                            userInitiatedDisconnect = false
                            lastBroadcastGeneration = gen
                            connecting = false
                            engineRunning = true
                            vpnActive = true
                            updateButton()
                            handler.removeCallbacks(poll)
                            handler.post(poll)
                        } else if (isPaused) {
                            userInitiatedDisconnect = false
                            lastBroadcastGeneration = gen
                            connecting = false
                            engineRunning = false
                            vpnActive = false
                            updateButton()
                            statusText.text = "STOPPED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
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
                    val rtt = NativeEngine.nativeGetRttMs()
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
        editTorBridgeLines = findViewById(R.id.editTorBridgeLines)
        spinnerEngineLog = findViewById(R.id.spinnerEngineLog)
        editTorSocksPort = findViewById(R.id.editTorSocksPort)
        editPsiphonConfig = findViewById(R.id.editPsiphonConfig)
        spinnerPsiphonRegion = findViewById(R.id.spinnerPsiphonRegion)
        editPsiphonSocksPort = findViewById(R.id.editPsiphonSocksPort)
        editPsiphonHttpPort = findViewById(R.id.editPsiphonHttpPort)
        switchEch = findViewById(R.id.switchEch)
        switchQuick = findViewById(R.id.switchQuick)
        switchLan = findViewById(R.id.switchLan)
        switchLogging = findViewById(R.id.switchLogging)
        switchSocks = findViewById(R.id.switchSocks)
        switchHttp = findViewById(R.id.switchHttp)
        switchAutoUpdate = findViewById(R.id.switchAutoUpdate)
        switchPreRelease = findViewById(R.id.switchPreRelease)
        spinnerSysprofile = findViewById(R.id.spinnerSysprofile)
        editSni = findViewById(R.id.editSni)
        editForcePeer = findViewById(R.id.editForcePeer)
        editSocksPort = findViewById(R.id.editSocksPort)
        editHttpPort = findViewById(R.id.editHttpPort)
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
        val editTexts = listOf(editSni, editForcePeer, editSocksPort, editHttpPort,
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
                "Tor only (no WARP)", "Psiphon",
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
        spinnerTor.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf(
                "Off",
                "Tor through the tunnel",
                "Tunnel through Tor (MASQUE only)",
                "Tor only (no WARP)",
            ),
        )
        // Positions map 1:1 onto FcaeTorBridges.
        spinnerTorBridges.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("No bridges", "obfs4", "snowflake", "Custom lines"),
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
        loadSettings()
        applyTorLock()

        // Running build, spelled out: version + which channel it is. A build
        // produced by a pre-release workflow run carries the tag as its
        // versionName (e.g. "v1.4.0-beta.2"), so mark it amber instead of
        // leaving the user to infer the channel from a missing BETA badge.
        findViewById<TextView>(R.id.versionText).apply {
            text = if (buildIsPrerelease)
                "${BuildConfig.APP_VERSION}  \u00b7  pre-release (BETA)"
            else
                "${BuildConfig.APP_VERSION}  \u00b7  release"
            setTextColor(Color.parseColor(if (buildIsPrerelease) "#FFF0B429" else "#FF8A93A6"))
        }

        // TUN mode forces SOCKS5 on (tun2socks needs the local SOCKS5 listener),
        // so keep the switch locked/grayed while TUN is selected. Applied after
        // loadSettings() so the saved Proxy-mode preference is captured first.
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

        onBackPressedDispatcher.addCallback(this, backPressedCallback)

        logText.text = ""
        lastLogHash = 0L

        btnConnect.setOnClickListener {
            if (vpnActive || engineRunning || connecting) disconnectAll() else connectClicked()
        }

        findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener {
            NativeEngine.nativeClearLogs()
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

        // Track whether user is at the bottom of the log scroll.
        logScroll.setOnScrollChangeListener { _: android.view.View, _: Int, scrollY: Int, _: Int, _: Int ->
            if (updatingLogs) return@setOnScrollChangeListener
            val child = logScroll.getChildAt(0) ?: return@setOnScrollChangeListener
            val maxScroll = (child.height - logScroll.height).coerceAtLeast(0)
            wasAtBottom = scrollY >= maxScroll - 5
        }

        val filter = IntentFilter().apply {
            addAction(FCAEVpnService.BROADCAST_VPN_DISCONNECTED)
            addAction(FCAEVpnService.BROADCAST_VPN_STATE_CHANGED)
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
                if (state in 1..4) {
                    handler.post {
                        vpnActive = true
                        engineRunning = true
                        connecting = state in 1..3
                        updateButton()
                        handler.post(poll)
                    }
                } else if (state == 0) {
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
                        if (state in 1..4) {
                            vpnActive = true
                            engineRunning = true
                            connecting = state in 1..3
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
                    if (state in 1..4) {
                        handler.post {
                            vpnActive = true
                            engineRunning = true
                            connecting = state in 1..3
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
        if (spinnerMode.selectedItemPosition == 1) {
            // Capture the user's Proxy-mode choice before overriding it. While
            // locked the switch is disabled, so this only happens once.
            if (switchSocks.isEnabled) socksChoiceForProxyMode = switchSocks.isChecked
            switchSocks.isChecked = true
            switchSocks.isEnabled = false
            editSocksPort.isEnabled = false
            switchSocks.alpha = 0.5f
            editSocksPort.alpha = 0.5f
            switchSocks.text = "SOCKS5 proxy (auto — required for TUN)"
        } else {
            switchSocks.isEnabled = true
            editSocksPort.isEnabled = true
            switchSocks.alpha = 1.0f
            editSocksPort.alpha = 1.0f
            switchSocks.isChecked = socksChoiceForProxyMode
            switchSocks.text = "SOCKS5 proxy"
        }
    }

    /**
     * Tor sub-options only mean something when Tor is on, and custom bridge
     * lines only when "Custom lines" is picked. Grey out the rest so the UI
     * cannot express a config the core would reject.
     */
    private fun applyTorLock() {
        if (!::spinnerTor.isInitialized || !::spinnerTorBridges.isInitialized) return
        val torOn = spinnerTor.selectedItemPosition != 0
        spinnerTorBridges.isEnabled = torOn
        spinnerTorBridges.alpha = if (torOn) 1.0f else 0.5f

        val custom = torOn && spinnerTorBridges.selectedItemPosition == 3
        editTorBridgeLines.isEnabled = custom
        editTorBridgeLines.alpha = if (custom) 1.0f else 0.5f
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
            putInt("backend", backendFromSelection())
            putString("torSocksPort", editTorSocksPort.text.toString().trim())
            putString("psiphonConfig", editPsiphonConfig.text.toString().trim())
            putString("psiphonRegion", selectedPsiphonRegion())
            putString("psiphonSocksPort", editPsiphonSocksPort.text.toString().trim())
            putString("psiphonHttpPort", editPsiphonHttpPort.text.toString().trim())
            putBoolean("h2", h2FromSelection())
            putBoolean("ech", switchEch.isChecked)
            putBoolean("quick", switchQuick.isChecked)
            putBoolean("lan", switchLan.isChecked)
            putBoolean("logging", switchLogging.isChecked)
            // In TUN mode the switch is force-locked to ON, so persist the
            // remembered Proxy-mode preference instead of the forced value.
            putBoolean("socks", if (isTunModeSelected()) socksChoiceForProxyMode else switchSocks.isChecked)
            putBoolean("http", switchHttp.isChecked)
            putBoolean("autoUpdate", switchAutoUpdate.isChecked)
            putBoolean("preRelease", switchPreRelease.isChecked)
            putString("sni", editSni.text.toString().trim())
            putString("forcePeer", editForcePeer.text.toString().trim())
            putInt("sysprofile", spinnerSysprofile.selectedItemPosition)
            putString("socksPort", editSocksPort.text.toString())
            putString("httpPort", editHttpPort.text.toString())
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
        spinnerTor.setSelection(prefs.getInt("tor", 0))
        spinnerTorBridges.setSelection(prefs.getInt("torBridges", 0))
        editTorBridgeLines.setText(prefs.getString("torBridgeLines", ""))
        spinnerEngineLog.setSelection(prefs.getInt("engineLog", 3))
        editTorSocksPort.setText(prefs.getString("torSocksPort", "1821"))
        editPsiphonConfig.setText(prefs.getString("psiphonConfig", ""))
        editPsiphonSocksPort.setText(prefs.getString("psiphonSocksPort", "0"))
        editPsiphonHttpPort.setText(prefs.getString("psiphonHttpPort", "0"))
        savedPsiphonRegion = prefs.getString("psiphonRegion", "") ?: ""
        refreshPsiphonRegions()
        switchEch.isChecked = prefs.getBoolean("ech", true)
        switchQuick.isChecked = prefs.getBoolean("quick", false)
        switchLan.isChecked = prefs.getBoolean("lan", false)
        switchLogging.isChecked = prefs.getBoolean("logging", true)
        switchSocks.isChecked = prefs.getBoolean("socks", true)
        switchHttp.isChecked = prefs.getBoolean("http", true)
        switchAutoUpdate.isChecked = prefs.getBoolean("autoUpdate", true)
        switchPreRelease.isChecked = prefs.getBoolean("preRelease", false)
        editSni.setText(prefs.getString("sni", ""))
        editForcePeer.setText(prefs.getString("forcePeer", ""))
        spinnerSysprofile.setSelection(prefs.getInt("sysprofile", 0))
        editSocksPort.setText(prefs.getString("socksPort", "1819"))
        editHttpPort.setText(prefs.getString("httpPort", "1820"))
        editTeam.setText(prefs.getString("team", ""))
        editAccessToken.setText(prefs.getString("accessToken", ""))
        editAccessEmail.setText(prefs.getString("accessEmail", ""))
        editRoutesFile.setText(prefs.getString("routesFile", ""))
        editRoutesInline.setText(prefs.getString("routesInline", ""))
    }

    private fun connectClicked() {
        userInitiatedDisconnect = false
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
        i.putExtra("socksPort", if (switchSocks.isChecked) editSocksPort.text.toString().toIntOrNull() ?: 1819 else 0)
        i.putExtra("httpPort", if (switchHttp.isChecked) editHttpPort.text.toString().toIntOrNull() ?: 1820 else 0)
        i.putExtra("noizeProfile", spinnerNoize.selectedItem.toString())
        i.putExtra("forcePeer", editForcePeer.text.toString().trim())
        i.putExtra("sysProfile", spinnerSysprofile.selectedItemPosition)
        i.putExtra("teamName", editTeam.text.toString().trim())
        i.putExtra("accessToken", editAccessToken.text.toString().trim())
        i.putExtra("accessEmail", editAccessEmail.text.toString().trim())
        i.putExtra("routesFile", editRoutesFile.text.toString().trim())
        i.putExtra("routesInline", editRoutesInline.text.toString().trim())
        i.putExtra("torMode", spinnerTor.selectedItemPosition)
        i.putExtra("torBridges", spinnerTorBridges.selectedItemPosition)
        i.putExtra("torBridgeLines", editTorBridgeLines.text.toString().trim())
        i.putExtra("engineLog", spinnerEngineLog.selectedItemPosition)
        i.putExtra("backend", backendFromSelection())
        i.putExtra("torSocksPort", editTorSocksPort.text.toString().toIntOrNull() ?: 1821)
        i.putExtra("psiphonConfig", editPsiphonConfig.text.toString().trim())
        i.putExtra("psiphonRegion", selectedPsiphonRegion())
        i.putExtra("psiphonSocksPort", editPsiphonSocksPort.text.toString().toIntOrNull() ?: 0)
        i.putExtra("psiphonHttpPort", editPsiphonHttpPort.text.toString().toIntOrNull() ?: 0)
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
        val socksPort = if (switchSocks.isChecked) editSocksPort.text.toString().toIntOrNull() ?: 1819 else 0
        val httpPort = if (switchHttp.isChecked) editHttpPort.text.toString().toIntOrNull() ?: 1820 else 0
        val forcePeer = editForcePeer.text.toString().trim()
        val sysProfile = spinnerSysprofile.selectedItemPosition
        val teamName = editTeam.text.toString().trim()
        val accessToken = editAccessToken.text.toString().trim()
        val accessEmail = editAccessEmail.text.toString().trim()
        val routesFile = editRoutesFile.text.toString().trim()
        val routesInline = editRoutesInline.text.toString().trim()
        val torMode = spinnerTor.selectedItemPosition
        val torBridges = spinnerTorBridges.selectedItemPosition
        val torBridgeLines = editTorBridgeLines.text.toString().trim()
        val engineLog = spinnerEngineLog.selectedItemPosition
        val backend = backendFromSelection()
        val torSocksPort = editTorSocksPort.text.toString().toIntOrNull() ?: 1821
        val psiphonConfig = editPsiphonConfig.text.toString().trim()
        val psiphonRegion = selectedPsiphonRegion()
        val psiphonSocksPort = editPsiphonSocksPort.text.toString().toIntOrNull() ?: 0
        val psiphonHttpPort = editPsiphonHttpPort.text.toString().toIntOrNull() ?: 0

        bgExecutor.execute {
            // Ensure previous engine is fully stopped before starting.
            // nativeStop() -> fcae_stop() is synchronous, so once it returns
            // the previous session has released the TUN fd and its threads
            // are joined. No sleep or retry loop is needed here.
            try { NativeEngine.nativeStop() } catch (_: Throwable) {}

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
                    psiphonConfig = psiphonConfig,
                    psiphonRegion = psiphonRegion,
                    psiphonSocksPort = psiphonSocksPort,
                    psiphonHttpPort = psiphonHttpPort,
                )
            } catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Start failed: ${e.message}", Toast.LENGTH_LONG).show() }
                false
            }
            handler.post {
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
    userInitiatedDisconnect = true

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

    // 2. Trigger disconnect on a background thread
    val currentMode = spinnerMode.selectedItemPosition
    Thread({
        if (currentMode == 1) {
            // TUN mode: fullShutdown() handles nativeStop + nativeFree
            FCAEVpnService.disconnectNow()
        } else {
            // Proxy mode: stopProxy() handles nativeStop + nativeFree
            try {
                val i = Intent(this, ProxyNotification::class.java)
                i.action = ProxyNotification.ACTION_STOP
                startService(i)
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
        NativeEngine.nativeCheckForUpdates(BuildConfig.APP_VERSION, switchPreRelease.isChecked)

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
            if (vpnActive) {
                engineRunning = state in 1..4
                connecting = state in 1..3
                // Psiphon reports its egress regions only after a successful
                // handshake, so this is the first moment the real list can be
                // read. Cheap and idempotent: it no-ops unless the set changed.
                if (state == 4 && isPsiphonSelected()) refreshPsiphonRegions()
                // Detect engine stopped while we thought it was active
                if (state == 0 && !userInitiatedDisconnect) {
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
                    if (isTun) "CONNECTED (TUN)" else "CONNECTED (PROXY)"
                }
                5 -> "ERROR"
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
            statsText.text =
                "\u2193 ${fmt(rx)}/s (${fmt(totalRx)})  |  \u2191 ${fmt(tx)}/s (${fmt(totalTx)})  |  RTT ${if (rtt > 0) "${rtt}ms" else "\u2014"}"

            // Build peer line — include LAN proxy addresses when sharing is on
            val peerLine = StringBuilder()
            peerLine.append("Peer: ${peer.ifEmpty { " \u2014 " }}")
            if (switchLan.isChecked && lan.isNotEmpty() && lan != "127.0.0.1") {
                val socksPort = if (switchSocks.isChecked) "1819" else null
                val httpPort = if (switchHttp.isChecked) "1820" else null
                val ports = listOfNotNull(
                    socksPort?.let { "SOCKS5 $lan:$it" },
                    httpPort?.let { "HTTP $lan:$it" }
                ).joinToString("  |  ")
                if (ports.isNotEmpty()) {
                    peerLine.append("\nLAN: $ports")
                }
            }
            // Only append error here if not already shown in statusText (state 5 = ERROR)
            if (errMsg.isNotEmpty() && state != 5) peerLine.append("\nError: $errMsg")
            peerText.text = peerLine.toString()

            // Fast change detection: length + first/last chars is cheaper
            // than scanning the entire string for hashCode().
            val h = if (logs.isEmpty()) 0L else
                logs.length.toLong() * 31 +
                logs[0].code.toLong() * 31 +
                logs[logs.length - 1].code.toLong()
            if (h != lastLogHash) {
                lastLogHash = h
                val shown = if (logs.length > MAX_LOG_CHARS) logs.takeLast(MAX_LOG_CHARS) else logs

                val scrollWasAtBottom = wasAtBottom

                updatingLogs = true
                logText.text = shown

                if (scrollWasAtBottom) {
                    logScroll.post {
                        val child = logScroll.getChildAt(0)
                        if (child != null) {
                            val target = (child.height - logScroll.height).coerceAtLeast(0)
                            logScroll.scrollTo(0, target)
                        }
                        updatingLogs = false
                    }
                } else {
                    updatingLogs = false
                }
            }
            updateButton()
        } catch (e: Throwable) {
            statusText.text = "UI error: ${e.message}"
        }
    }

    private fun updateButton() {
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
        4 -> 4    // Tor only (FcaeProtocol::Tor; implies tor.mode = Only)
        5 -> 3    // Psiphon picks its own transport (FcaeProtocol::Auto)
        else -> 0 // MASQUE (either HTTP version)
    }

    /** 0 = Aether, 1 = Psiphon. Only the Psiphon entry switches backend. */
    private fun backendFromSelection(): Int =
        if (spinnerProtocol.selectedItemPosition == 5) 1 else 0

    private fun isPsiphonSelected(): Boolean = spinnerProtocol.selectedItemPosition == 5

    /** The ISO code currently chosen, or "" for automatic. */
    private fun selectedPsiphonRegion(): String {
        if (!::spinnerPsiphonRegion.isInitialized) return savedPsiphonRegion
        val i = spinnerPsiphonRegion.selectedItemPosition
        return psiphonRegionCodes.getOrElse(i) { "" }
    }

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

        val newCodes = listOf("") + codes
        if (newCodes == psiphonRegionCodes) return
        psiphonRegionCodes = newCodes

        val labels = newCodes.map { if (it.isEmpty()) "Auto (fastest)" else it }
        spinnerPsiphonRegion.adapter =
            ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)

        // Restore the user's pick if it is still on offer; otherwise fall
        // back to Auto rather than silently selecting someone else's region.
        val want = savedPsiphonRegion
        val at = newCodes.indexOf(want)
        spinnerPsiphonRegion.setSelection(if (at >= 0) at else 0)
    }

    private fun h2FromSelection(): Boolean = spinnerProtocol.selectedItemPosition == 1

    /** Old saved prefs keep protocol (0-2) + h2 (bool); map back to the
     *  spinner position so existing configs load unchanged.
     *
     *  The mapping is no longer a simple +1 now that Tor (core 4) and Psiphon
     *  (core 3, via the backend) sit at the end of the list. */
    private fun selectionPositionFromPrefs(protocol: Int, h2: Boolean, backend: Int = 0): Int =
        when {
            backend == 1 -> 5          // Psiphon
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
        private const val MAX_LOG_CHARS = 8000

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
