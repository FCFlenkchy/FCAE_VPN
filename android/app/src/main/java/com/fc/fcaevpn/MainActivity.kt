package com.fc.fcaevpn

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import org.json.JSONObject

/**
 * Kotlin Material UI — CONNECT is manual (no auto-start VPN).
 */
class MainActivity : AppCompatActivity() {
    private val vpnRequestCode = 100
    private val handler = Handler(Looper.getMainLooper())
    private var connecting = false
    private var engineRunning = false
    private var pendingAfterVpnPermission = false
    private var lastLogHash = 0

    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private lateinit var peerText: TextView
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var btnConnect: MaterialButton
    private lateinit var spinnerProtocol: Spinner
    private lateinit var spinnerMode: Spinner
    private lateinit var spinnerScan: Spinner
    private lateinit var switchH2: SwitchMaterial
    private lateinit var switchQuick: SwitchMaterial

    private val poll = object : Runnable {
        override fun run() {
            Thread {
                try {
                    val statusJson = NativeEngine.nativeGetStatusJson()
                    val logs = NativeEngine.nativeGetLogs()
                    handler.post { applyStatus(statusJson, logs) }
                } catch (e: Throwable) {
                    handler.post {
                        statusText.text = "UI error: ${e.message}"
                    }
                }
            }.start()
            handler.postDelayed(this, 1500L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)
        peerText = findViewById(R.id.peerText)
        logText = findViewById(R.id.logText)
        logScroll = findViewById(R.id.logScroll)
        btnConnect = findViewById(R.id.btnConnect)
        spinnerProtocol = findViewById(R.id.spinnerProtocol)
        spinnerMode = findViewById(R.id.spinnerMode)
        spinnerScan = findViewById(R.id.spinnerScan)
        switchH2 = findViewById(R.id.switchH2)
        switchQuick = findViewById(R.id.switchQuick)

        spinnerProtocol.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf("MASQUE (HTTP/3)", "WireGuard", "WARP-in-WARP"),
        )
        spinnerMode.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf("Proxy (SOCKS/HTTP)", "TUN (system VPN)"),
        )
        spinnerScan.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf("Turbo", "Balanced", "Thorough", "Stealth", "Ironclad"),
        )
        spinnerScan.setSelection(1)

        Thread {
            try {
                NativeEngine.nativeInit()
            } catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Native lib failed: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()

        btnConnect.setOnClickListener {
            if (engineRunning || connecting) disconnectAll() else connectClicked()
        }

        findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener {
            NativeEngine.nativeClearLogs()
            logText.text = ""
            lastLogHash = 0
        }

        updateButton()
        handler.post(poll)
    }

    override fun onDestroy() {
        handler.removeCallbacks(poll)
        super.onDestroy()
    }

    private fun connectClicked() {
        val mode = spinnerMode.selectedItemPosition
        if (mode == 1) {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                pendingAfterVpnPermission = true
                @Suppress("DEPRECATION")
                startActivityForResult(prep, vpnRequestCode)
                return
            }
            startTunServiceWithConfig()
        } else {
            startEngine()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequestCode) {
            if (resultCode == Activity.RESULT_OK && pendingAfterVpnPermission) {
                pendingAfterVpnPermission = false
                startTunServiceWithConfig()
            } else {
                pendingAfterVpnPermission = false
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun startTunServiceWithConfig() {
        connecting = true
        updateButton()
        val i = Intent(this, FCAEVpnService::class.java)
        i.action = FCAEVpnService.ACTION_START
        i.putExtra("protocol", spinnerProtocol.selectedItemPosition)
        i.putExtra("mode", spinnerMode.selectedItemPosition)
        i.putExtra("scanMode", spinnerScan.selectedItemPosition)
        i.putExtra("ipVersion", 4)
        i.putExtra("quickReconnect", switchQuick.isChecked)
        i.putExtra("h2Enabled", switchH2.isChecked)
        i.putExtra("configPath", filesDir.resolve("aether.toml").absolutePath)
        startForegroundService(i)
    }

    private fun startEngine() {
        connecting = true
        updateButton()

        Thread {
            val ok = try {
                NativeEngine.nativeStart(
                    protocol = spinnerProtocol.selectedItemPosition,
                    mode = spinnerMode.selectedItemPosition,
                    lanSharing = false,
                    scanMode = spinnerScan.selectedItemPosition,
                    ipVersion = 4,
                    quickReconnect = switchQuick.isChecked,
                    noizeProfile = "balanced",
                    fragmentEnabled = false,
                    fragMinSize = 16,
                    fragMaxSize = 32,
                    fragMinDelay = 2,
                    fragMaxDelay = 10,
                    socksPort = 1819,
                    httpPort = 1820,
                    forcePeer = "",
                    configPath = filesDir.resolve("aether.toml").absolutePath,
                    h2Enabled = switchH2.isChecked,
                    echEnabled = false,
                )
            } catch (e: Throwable) {
                handler.post { Toast.makeText(this, "Start failed: ${e.message}", Toast.LENGTH_LONG).show() }
                false
            }
            handler.post {
                if (!ok) {
                    connecting = false
                    Toast.makeText(this, "Failed to start engine", Toast.LENGTH_SHORT).show()
                }
                updateButton()
                refreshStatus()
            }
        }.start()
    }

    private fun disconnectAll() {
        Thread {
            try {
                NativeEngine.nativeStop()
            } catch (_: Throwable) {
            }
            handler.post {
                try {
                    val i = Intent(this, FCAEVpnService::class.java)
                    i.action = FCAEVpnService.ACTION_DISCONNECT
                    startService(i)
                } catch (_: Throwable) {
                }
                connecting = false
                engineRunning = false
                updateButton()
                refreshStatus()
            }
        }.start()
    }

    private fun refreshStatus() {
        Thread {
            try {
                val statusJson = NativeEngine.nativeGetStatusJson()
                val logs = NativeEngine.nativeGetLogs()
                handler.post { applyStatus(statusJson, logs) }
            } catch (e: Throwable) {
                handler.post { statusText.text = "UI error: ${e.message}" }
            }
        }.start()
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
            statusText.text = if (status.isNotEmpty()) "$label — $status" else label
            statusText.setTextColor(
                when (state) {
                    4 -> Color.parseColor("#34D399")
                    5 -> Color.parseColor("#F87171")
                    0 -> Color.parseColor("#8A93A6")
                    else -> Color.parseColor("#60A5FA")
                },
            )
            statsText.text =
                "↓ ${fmt(rx)}/s (${fmt(totalRx)})  |  ↑ ${fmt(tx)}/s (${fmt(totalTx)})  |  RTT ${if (rtt > 0) "${rtt}ms" else "—"}"
            peerText.text = "Peer: ${peer.ifEmpty { "—" }}" +
                if (err.isNotEmpty()) "\nError: $err" else ""

            val h = logs.hashCode()
            if (h != lastLogHash) {
                lastLogHash = h
                val shown = if (logs.length > 24_000) logs.takeLast(24_000) else logs
                logText.text = shown
                logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
            }
            updateButton()
        } catch (e: Throwable) {
            statusText.text = "UI error: ${e.message}"
        }
    }

    private fun updateButton() {
        if (engineRunning || connecting) {
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
