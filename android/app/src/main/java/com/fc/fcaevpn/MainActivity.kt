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
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var connecting = false
    @Volatile private var engineRunning = false
    private var pendingAfterVpnPermission = false
    private var lastLogHash = 0
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
    private lateinit var spinnerProtocol: Spinner
    private lateinit var spinnerMode: Spinner
    private lateinit var spinnerScan: Spinner
    private lateinit var spinnerNoize: Spinner
    private lateinit var switchH2: SwitchMaterial
    private lateinit var switchEch: SwitchMaterial
    private lateinit var switchQuick: SwitchMaterial
    private lateinit var switchIronclad: SwitchMaterial
    private lateinit var switchLan: SwitchMaterial
    private lateinit var switchLogging: SwitchMaterial
    private lateinit var switchSocks: SwitchMaterial
    private lateinit var switchHttp: SwitchMaterial
    private lateinit var editSni: android.widget.EditText
    private lateinit var editForcePeer: android.widget.EditText
    private lateinit var editHealthInterval: android.widget.EditText
    private lateinit var editHealthMaxFails: android.widget.EditText
    private lateinit var outerScroll: ScrollView

    private val bgExecutor = Executors.newSingleThreadExecutor()
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

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                FCAEVpnService.BROADCAST_VPN_DISCONNECTED,
                FCAEVpnService.BROADCAST_VPN_STATE_CHANGED -> {
                    val isRunning = intent.getBooleanExtra("running", false)
                    val isPaused = intent.getBooleanExtra("paused", false)

                    handler.post {
                        if (!isRunning && !isPaused) {
                            connecting = false
                            engineRunning = false
                            vpnActive = false
                            updateButton()
                            statusText.text = "DISCONNECTED"
                            statusText.setTextColor(Color.parseColor("#8A93A6"))
                            statsText.text = ""
                            peerText.text = ""

                            // If the user is not in the app (e.g. disconnected
                            // from notification while app was backgrounded), kill
                            // the entire process so nothing lingers.
                            if (!inForeground) {
                                finishAndRemoveTask()
                            }
                        } else if (isRunning) {
                            connecting = false
                            engineRunning = true
                            vpnActive = true
                            updateButton()
                            handler.removeCallbacks(poll)
                            handler.post(poll)
                        } else if (isPaused) {
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
                handler.postDelayed(this, POLL_INTERVAL_MS)
                return
            }
            bgExecutor.execute {
                try {
                    // Triple guard: vpnActive (UI thread), engineRunning (set by
                    // broadcast after nativeStart succeeds), and a second
                    // vpnActive check on the bg thread to close the race window
                    // between disconnectAll() and this task executing.
                    if (!vpnActive || !engineRunning) {
                        handler.post { pollBusy.set(false) }
                        return@execute
                    }
                    val statusJson = NativeEngine.nativeGetStatusJson()
                    val logs = if (switchLogging.isChecked) NativeEngine.nativeGetLogs() else ""
                    handler.post { applyStatus(statusJson, logs) }
                } catch (e: Throwable) {
                    handler.post {
                        statusText.text = "UI error: ${e.message}"
                    }
                } finally {
                    pollBusy.set(false)
                }
            }
            handler.postDelayed(this, POLL_INTERVAL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = getSharedPreferences("aether_vpn", MODE_PRIVATE)

        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)
        peerText = findViewById(R.id.peerText)
        logText = findViewById(R.id.logText)
        logScroll = findViewById(R.id.logScroll)
        btnConnect = findViewById(R.id.btnConnect)
        spinnerProtocol = findViewById(R.id.spinnerProtocol)
        spinnerMode = findViewById(R.id.spinnerMode)
        spinnerScan = findViewById(R.id.spinnerScan)
        spinnerNoize = findViewById(R.id.spinnerNoize)
        switchH2 = findViewById(R.id.switchH2)
        switchEch = findViewById(R.id.switchEch)
        switchQuick = findViewById(R.id.switchQuick)
        switchIronclad = findViewById(R.id.switchIronclad)
        switchLan = findViewById(R.id.switchLan)
        switchLogging = findViewById(R.id.switchLogging)
        switchSocks = findViewById(R.id.switchSocks)
        switchHttp = findViewById(R.id.switchHttp)
        editSni = findViewById(R.id.editSni)
        editForcePeer = findViewById(R.id.editForcePeer)
        editHealthInterval = findViewById(R.id.editHealthInterval)
        editHealthMaxFails = findViewById(R.id.editHealthMaxFails)
        outerScroll = findViewById(R.id.outerScroll)

        spinnerProtocol.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("MASQUE (HTTP/3)", "WireGuard", "WARP-in-WARP"),
        )
        spinnerMode.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Proxy (SOCKS/HTTP)", "TUN (system VPN)"),
        )
        spinnerScan.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("Turbo", "Balanced", "Thorough", "Stealth"),
        )
        spinnerNoize.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            listOf("off", "firewall", "balanced", "gfw", "chrome", "voice", "streaming"),
        )
        loadSettings()

        logText.text = ""
        lastLogHash = 0

        btnConnect.setOnClickListener {
            if (vpnActive || engineRunning || connecting) disconnectAll() else connectClicked()
        }

        findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener {
            NativeEngine.nativeClearLogs()
            logText.text = ""
            lastLogHash = 0
        }

        findViewById<MaterialButton>(R.id.btnCopyLogs).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("FCAE Logs", logText.text)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show()
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
        // running (e.g. service started from notification while app was closed).
        bgExecutor.execute {
            try {
                NativeEngine.nativeInit()
            } catch (e: Throwable) {
                handler.post {
                    Toast.makeText(this, "Native lib failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
                return@execute
            }
            // Query native state — if engine is running, sync UI to it
            try {
                val json = JSONObject(NativeEngine.nativeGetStatusJson())
                val state = json.optInt("state", 0)
                if (state > 0) {
                    handler.post {
                        vpnActive = true
                        engineRunning = state in 1..4
                        connecting = state in 1..3
                        updateButton()
                        handler.post(poll)
                    }
                }
            } catch (_: Throwable) {}
        }
    }

    override fun onPause() {
        super.onPause()
        inForeground = false
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
        // waiting up to 5s for the next tick or for a broadcast.
        if (vpnActive) {
            handler.removeCallbacks(poll)
            handler.post(poll)
        }
    }

    override fun onDestroy() {
        handler.removeCallbacks(poll)
        try { unregisterReceiver(vpnStateReceiver) } catch (_: Throwable) {}
        bgExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun saveSettings() {
        prefs.edit().apply {
            putInt("protocol", spinnerProtocol.selectedItemPosition)
            putInt("mode", spinnerMode.selectedItemPosition)
            putInt("scan", spinnerScan.selectedItemPosition)
            putInt("noize", spinnerNoize.selectedItemPosition)
            putBoolean("h2", switchH2.isChecked)
            putBoolean("ech", switchEch.isChecked)
            putBoolean("quick", switchQuick.isChecked)
            putBoolean("ironclad", switchIronclad.isChecked)
            putBoolean("lan", switchLan.isChecked)
            putBoolean("logging", switchLogging.isChecked)
            putBoolean("socks", switchSocks.isChecked)
            putBoolean("http", switchHttp.isChecked)
            putString("sni", editSni.text.toString().trim())
            putString("forcePeer", editForcePeer.text.toString().trim())
            putString("healthInterval", editHealthInterval.text.toString())
            putString("healthMaxFails", editHealthMaxFails.text.toString())
            apply()
        }
    }

    private fun loadSettings() {
        spinnerProtocol.setSelection(prefs.getInt("protocol", 0))
        spinnerMode.setSelection(prefs.getInt("mode", 1))
        spinnerScan.setSelection(prefs.getInt("scan", 0))
        spinnerNoize.setSelection(prefs.getInt("noize", 2))
        switchH2.isChecked = prefs.getBoolean("h2", true)
        switchEch.isChecked = prefs.getBoolean("ech", true)
        switchQuick.isChecked = prefs.getBoolean("quick", false)
        switchIronclad.isChecked = prefs.getBoolean("ironclad", false)
        switchLan.isChecked = prefs.getBoolean("lan", false)
        switchLogging.isChecked = prefs.getBoolean("logging", true)
        switchSocks.isChecked = prefs.getBoolean("socks", true)
        switchHttp.isChecked = prefs.getBoolean("http", true)
        editSni.setText(prefs.getString("sni", ""))
        editForcePeer.setText(prefs.getString("forcePeer", ""))
        editHealthInterval.setText(prefs.getString("healthInterval", "20"))
        editHealthMaxFails.setText(prefs.getString("healthMaxFails", "2"))
    }

    private fun connectClicked() {
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

    private fun healthInterval(): Int =
        editHealthInterval.text.toString().toIntOrNull()?.coerceIn(2, 120) ?: 20

    private fun healthMaxFails(): Int =
        editHealthMaxFails.text.toString().toIntOrNull()?.coerceIn(1, 10) ?: 2

    private fun liveValidateSecs(): Int =
        // Default 5s — fast enough for quick connect, still gives tunnel time to warm up.
        5

    private fun startTunServiceWithConfig() {
        connecting = true
        vpnActive = true
        updateButton()
        saveSettings()
        val i = Intent(this, FCAEVpnService::class.java)
        i.action = FCAEVpnService.ACTION_START
        i.putExtra("protocol", spinnerProtocol.selectedItemPosition)
        i.putExtra("mode", spinnerMode.selectedItemPosition)
        i.putExtra("scanMode", spinnerScan.selectedItemPosition)
        i.putExtra("ipVersion", 4)
        i.putExtra("quickReconnect", switchQuick.isChecked)
        i.putExtra("h2Enabled", switchH2.isChecked)
        i.putExtra("echEnabled", switchEch.isChecked)
        i.putExtra("lanSharing", switchLan.isChecked)
        i.putExtra("configPath", filesDir.resolve("aether.toml").absolutePath)
        i.putExtra("sni", editSni.text.toString().trim())
        i.putExtra("ironclad", switchIronclad.isChecked)
        i.putExtra("healthInterval", healthInterval())
        i.putExtra("healthMaxFails", healthMaxFails())
        i.putExtra("healthTimeout", 5)
        i.putExtra("liveValidate", liveValidateSecs())
        i.putExtra("socksPort", if (switchSocks.isChecked) 1819 else 0)
        i.putExtra("httpPort", if (switchHttp.isChecked) 1820 else 0)
        i.putExtra("noizeProfile", spinnerNoize.selectedItem.toString())
        i.putExtra("forcePeer", editForcePeer.text.toString().trim())
        startForegroundService(i)
        // Poll is started by the VPN_STATE_CHANGED broadcast from the service
        // AFTER nativeStart() succeeds — NOT here, to avoid calling native
        // methods while the previous engine is still tearing down.
    }

    private fun startEngine() {
        connecting = true
        vpnActive = true
        updateButton()
        saveSettings()

        val protocol = spinnerProtocol.selectedItemPosition
        val mode = spinnerMode.selectedItemPosition
        val scanMode = spinnerScan.selectedItemPosition
        val quick = switchQuick.isChecked
        val h2 = switchH2.isChecked
        val ech = switchEch.isChecked
        val iron = switchIronclad.isChecked
        val lan = switchLan.isChecked
        val sni = editSni.text.toString().trim()
        val hi = healthInterval()
        val hf = healthMaxFails()
        val cfgPath = filesDir.resolve("aether.toml").absolutePath

        bgExecutor.execute {
            // Ensure previous engine is fully stopped before starting.
            // aether_start() now waits for RUNNING=false if SHUTDOWN is set,
            // but we still call nativeStop() first for safety.
            try { NativeEngine.nativeStop() } catch (_: Throwable) {}
            // Brief pause to let the engine thread observe SHUTDOWN
            try { Thread.sleep(300) } catch (_: Throwable) {}

            val ok = try {
                NativeEngine.nativeStart(
                    protocol = protocol,
                    mode = mode,
                    lanSharing = lan,
                    scanMode = scanMode,
                    ipVersion = 4,
                    quickReconnect = quick,
                    noizeProfile = spinnerNoize.selectedItem.toString(),
                    fragmentEnabled = false,
                    fragMinSize = 16,
                    fragMaxSize = 32,
                    fragMinDelay = 2,
                    fragMaxDelay = 10,
                    socksPort = if (switchSocks.isChecked) 1819 else 0,
                    httpPort = if (switchHttp.isChecked) 1820 else 0,
                    forcePeer = editForcePeer.text.toString().trim(),
                    configPath = cfgPath,
                    h2Enabled = h2,
                    echEnabled = ech,
                    sni = sni,
                    ironcladValidate = iron,
                    healthIntervalSecs = hi,
                    healthMaxFails = hf,
                    healthTimeoutSecs = 5,
                    liveValidateSecs = liveValidateSecs(),
                )
            } catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Start failed: ${e.message}", Toast.LENGTH_LONG).show() }
                false
            }
            handler.post {
                if (!ok) {
                    connecting = false
                    vpnActive = false
                    Toast.makeText(this, "Failed to start engine", Toast.LENGTH_SHORT).show()
                }
                updateButton()
                if (ok) handler.post(poll)
            }
        }
    }

    private fun disconnectAll() {
        // Reset UI state immediately so the button flips to CONNECT
        // before the async broadcast arrives.  This prevents double-tap
        // races where the user taps CONNECT while the old broadcast is
        // still in-flight.
        vpnActive = false
        engineRunning = false
        connecting = false
        handler.removeCallbacks(poll)
        updateButton()
        statusText.text = "DISCONNECTING..."
        statusText.setTextColor(Color.parseColor("#8A93A6"))

        // Stop native engine directly — if the service was killed by the
        // system while the app was backgrounded, startService(i) would go
        // nowhere and the UI would stay stuck on DISCONNECTING forever.
        bgExecutor.execute {
            try { NativeEngine.nativeStop() } catch (_: Throwable) {}
        }

        try {
            val i = Intent(this, FCAEVpnService::class.java)
            i.action = FCAEVpnService.ACTION_DISCONNECT
            startForegroundService(i)
        } catch (_: Throwable) {
            // Fallback: stopService works even from background on all APIs
            try { stopService(Intent(this, FCAEVpnService::class.java)) } catch (_: Throwable) {}
        }

        // After a brief delay, force UI to DISCONNECTED even if no
        // broadcast arrives (service might be dead).  If backgrounded,
        // kill the whole process.
        handler.postDelayed({
            if (statusText.text == "DISCONNECTING...") {
                vpnActive = false
                engineRunning = false
                connecting = false
                updateButton()
                statusText.text = "DISCONNECTED"
                statusText.setTextColor(Color.parseColor("#8A93A6"))
                statsText.text = ""
                peerText.text = ""
                if (!inForeground) {
                    finishAndRemoveTask()
                }
            }
        }, 2000)
    }

    private fun applyStatus(statusJson: String, logs: String) {
        try {
            val json = JSONObject(statusJson)
            val state = json.optInt("state", 0)
            val status = json.optString("status", "")
            val err = json.optString("error", "")
            val peer = json.optString("peer", "")
            val rtt = json.optInt("rtt", 0)
            val rx = json.optLong("rx", 0)
            val tx = json.optLong("tx", 0)
            val totalRx = json.optLong("totalRx", 0)
            val totalTx = json.optLong("totalTx", 0)

            if (vpnActive) {
                engineRunning = state in 1..4
                connecting = state in 1..3
            }

            val label = when (state) {
                0 -> "DISCONNECTED"
                1 -> "PROVISIONING"
                2 -> "SCANNING"
                3 -> "CONNECTING"
                4 -> "CONNECTED"
                5 -> "ERROR"
                else -> "UNKNOWN"
            }
            statusText.text = if (status.isNotEmpty()) "$label \u2014 $status" else label
            statusText.setTextColor(
                when (state) {
                    4 -> Color.parseColor("#34D399")
                    5 -> Color.parseColor("#F87171")
                    0 -> Color.parseColor("#8A93A6")
                    else -> Color.parseColor("#60A5FA")
                },
            )
            statsText.text =
                "\u2193 ${fmt(rx)}/s (${fmt(totalRx)})  |  \u2191 ${fmt(tx)}/s (${fmt(totalTx)})  |  RTT ${if (rtt > 0) "${rtt}ms" else "\u2014"}"

            // Build peer line — include LAN proxy addresses when sharing is on
            val lan = json.optString("lan", "")
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
            if (err.isNotEmpty()) peerLine.append("\nError: $err")
            peerText.text = peerLine.toString()

            val h = logs.hashCode()
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
            btnConnect.setBackgroundColor(Color.parseColor("#B91C1C"))
        } else {
            btnConnect.text = "CONNECT"
            btnConnect.setBackgroundColor(Color.parseColor("#15803D"))
        }
    }

    private fun fmt(bps: Long): String {
        return when {
            bps >= 1_073_741_824L -> String.format("%.1f GB", bps / 1_073_741_824.0)
            bps >= 1_048_576L -> String.format("%.1f MB", bps / 1_048_576.0)
            bps >= 1024L -> String.format("%.0f KB", bps / 1024.0)
            else -> "$bps B"
        }
    }

    companion object {
        private const val POLL_INTERVAL_MS = 5000L
        private const val MAX_LOG_CHARS = 8000
    }
}
