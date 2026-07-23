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
    private var engineRunning = false
    private var pendingAfterVpnPermission = false
    private var lastLogHash = 0
    private var vpnActive = false

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

    private var userScrolledUp = false
    private var programmaticScroll = false

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

    private val vpnDisconnectedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == "com.fc.fcaevpn.VPN_DISCONNECTED") {
                handler.post {
                    connecting = false
                    engineRunning = false
                    vpnActive = false
                    updateButton()
                    statusText.text = "DISCONNECTED"
                    statusText.setTextColor(Color.parseColor("#8A93A6"))
                    statsText.text = ""
                    peerText.text = ""
                }
            }
        }
    }

    private val poll = object : Runnable {
        override fun run() {
            if (!vpnActive) return
            if (!pollBusy.compareAndSet(false, true)) {
                handler.postDelayed(this, 1500L)
                return
            }
            bgExecutor.execute {
                try {
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
            handler.postDelayed(this, 1500L)
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

        bgExecutor.execute {
            try { NativeEngine.nativeClearLogs() } catch (_: Throwable) {}
        }
        logText.text = ""
        lastLogHash = 0

        bgExecutor.execute {
            try { NativeEngine.nativeInit() }
            catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Native lib failed: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }

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
        handler.post(poll)

        logScroll.viewTreeObserver.addOnScrollChangedListener {
            if (programmaticScroll) return@addOnScrollChangedListener
            val scrollable = logScroll.getChildAt(0)?.height?.minus(logScroll.height) ?: 0
            userScrolledUp = scrollable > 0 && logScroll.scrollY < scrollable - 10
        }

        outerScroll.post { outerScroll.scrollTo(0, 0) }
        outerScroll.postDelayed({ outerScroll.scrollTo(0, 0) }, 100)

        val filter = IntentFilter("com.fc.fcaevpn.VPN_DISCONNECTED")
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnDisconnectedReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnDisconnectedReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        saveSettings()
    }

    override fun onDestroy() {
        handler.removeCallbacks(poll)
        try { unregisterReceiver(vpnDisconnectedReceiver) } catch (_: Throwable) {}
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
        editHealthInterval.text.toString().toIntOrNull()?.coerceIn(5, 120) ?: 20

    private fun healthMaxFails(): Int =
        editHealthMaxFails.text.toString().toIntOrNull()?.coerceIn(1, 10) ?: 2

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
        i.putExtra("liveValidate", 20)
        i.putExtra("socksPort", if (switchSocks.isChecked) 1819 else 0)
        i.putExtra("httpPort", if (switchHttp.isChecked) 1820 else 0)
        i.putExtra("noizeProfile", spinnerNoize.selectedItem.toString())
        i.putExtra("forcePeer", editForcePeer.text.toString().trim())
        startForegroundService(i)
        handler.post(poll)
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
                    liveValidateSecs = 20,
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

    /**
     * Disconnect: kill the poll, then send ACTION_DISCONNECT to the service.
     * The service handles nativeStop + fd close + stopSelf immediately.
     */
    private fun disconnectAll() {
        handler.removeCallbacks(poll)
        vpnActive = false
        connecting = false
        engineRunning = false
        updateButton()

        try {
            val i = Intent(this, FCAEVpnService::class.java)
            i.action = FCAEVpnService.ACTION_DISCONNECT
            startForegroundService(i)
        } catch (_: Throwable) {}
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

            engineRunning = state in 1..4
            connecting = state in 1..3

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
            peerText.text = "Peer: ${peer.ifEmpty { " \u2014 " }}" +
                if (err.isNotEmpty()) "\nError: $err" else ""

            val h = logs.hashCode()
            if (h != lastLogHash) {
                lastLogHash = h
                val shown = if (logs.length > 24_000) logs.takeLast(24_000) else logs
                val wasAtBottom = !userScrolledUp
                logText.text = shown
                if (wasAtBottom) {
                    programmaticScroll = true
                    logScroll.post {
                        logScroll.fullScroll(ScrollView.FOCUS_DOWN)
                        programmaticScroll = false
                    }
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
}
