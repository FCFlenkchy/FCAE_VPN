package com.fc.fcaevpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.view.View
import android.widget.RemoteViews
import org.json.JSONObject

class VpnWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        for (appWidgetId in appWidgetIds) {
            updateWidget(context, appWidgetManager, appWidgetId)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        val action = intent.action ?: return

        when (action) {
            ACTION_WIDGET_TOGGLE -> {
                handleToggle(context)
            }
            ACTION_WIDGET_PAUSE_RESUME -> {
                handlePauseResume(context)
            }
            FCAEVpnService.BROADCAST_VPN_STATE_CHANGED -> {
                lastRunning = intent.getBooleanExtra("running", false)
                lastPaused = intent.getBooleanExtra("paused", false)
                lastConnecting = intent.getBooleanExtra("connecting", false)
                if (lastRunning || lastPaused) {
                    val rx = intent.getLongExtra("rx", 0L)
                    val tx = intent.getLongExtra("tx", 0L)
                    val totalRx = intent.getLongExtra("totalRx", 0L)
                    val totalTx = intent.getLongExtra("totalTx", 0L)
                    val rtt = intent.getIntExtra("rtt", 0)
                    lastSpeedLine = "↓ ${fmtBytes(rx)}/s (${fmtBytes(totalRx)})  |  ↑ ${fmtBytes(tx)}/s (${fmtBytes(totalTx)})"
                    lastRttLine = if (rtt > 0) "RTT: ${rtt}ms" else "RTT: —"
                }
                updateAllWidgets(context)
            }
            FCAEVpnService.BROADCAST_VPN_DISCONNECTED,
            PsiphonTunnelService.BROADCAST_STOPPED -> {
                lastRunning = false
                lastPaused = false
                lastConnecting = false
                lastSpeedLine = "↓ 0 B/s (0 B)  |  ↑ 0 B/s (0 B)"
                lastRttLine = "RTT: —"
                updateAllWidgets(context)
            }
            PsiphonTunnelService.BROADCAST_READY -> {
                lastRunning = true
                lastPaused = false
                lastConnecting = false
                updateAllWidgets(context)
            }
            PsiphonTunnelService.BROADCAST_FAILED -> {
                lastRunning = false
                lastPaused = false
                lastConnecting = false
                lastSpeedLine = "↓ 0 B/s (0 B)  |  ↑ 0 B/s (0 B)"
                lastRttLine = "RTT: —"
                updateAllWidgets(context)
            }
            PsiphonTunnelService.BROADCAST_STATS -> {
                val rxBps = intent.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L)
                val txBps = intent.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0L)
                val totalRx = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L)
                val totalTx = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L)
                val rtt = intent.getIntExtra(PsiphonTunnelService.EXTRA_RTT, 0)
                lastSpeedLine = "↓ ${fmtBytes(rxBps)}/s (${fmtBytes(totalRx)})  |  ↑ ${fmtBytes(txBps)}/s (${fmtBytes(totalTx)})"
                lastRttLine = if (rtt > 0) "RTT: ${rtt}ms" else "RTT: —"
                updateAllWidgets(context)
            }
        }
    }

    private fun handleToggle(context: Context) {
        val prefs = context.getSharedPreferences("aether_vpn", Context.MODE_PRIVATE)
        val mode = prefs.getInt("mode", 1)
        val isTun = mode == 1
        val proto = prefs.getInt("protocol", 0)
        val isPsiphon = proto == 5

        if (lastRunning || lastPaused || lastConnecting) {
            if (isTun) {
                FCAEVpnService.disconnectNow()
            } else {
                val i = Intent(context, ProxyNotification::class.java).setAction(ProxyNotification.ACTION_DISCONNECT)
                try {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                        context.startForegroundService(i)
                    } else {
                        context.startService(i)
                    }
                } catch (_: Throwable) {}
                try { NativeEngine.nativeStop() } catch (_: Throwable) {}
            }
            try { PsiphonTunnelService.stopBound(context) } catch (_: Throwable) {}
            lastRunning = false
            lastPaused = false
            lastConnecting = false
            lastSpeedLine = "↓ 0 B/s (0 B)  |  ↑ 0 B/s (0 B)"
            lastRttLine = "RTT: —"
            updateAllWidgets(context)
        } else {
            if (isTun) {
                val prep = VpnService.prepare(context)
                if (prep != null) {
                    val mainIntent = Intent(context, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    }
                    context.startActivity(mainIntent)
                    return
                }

                val startIntent = buildStartIntentFromPrefs(context)
                try {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                        context.startForegroundService(startIntent)
                    } else {
                        context.startService(startIntent)
                    }
                    lastConnecting = true
                    updateAllWidgets(context)
                } catch (_: Throwable) {}
            } else {
                if (isPsiphon) {
                    val psiIntent = Intent(context, ProxyNotification::class.java).apply {
                        action = ProxyNotification.ACTION_PSIPHON
                        putExtras(buildStartIntentFromPrefs(context))
                    }
                    try {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                            context.startForegroundService(psiIntent)
                        } else {
                            context.startService(psiIntent)
                        }
                        lastConnecting = true
                        updateAllWidgets(context)
                    } catch (_: Throwable) {}
                } else {
                    val proxyIntent = Intent(context, ProxyNotification::class.java).apply {
                        action = ProxyNotification.ACTION_START
                    }
                    try {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                            context.startForegroundService(proxyIntent)
                        } else {
                            context.startService(proxyIntent)
                        }
                    } catch (_: Throwable) {}
                    startEngineNative(context, prefs)
                    lastConnecting = true
                    updateAllWidgets(context)
                }
            }
        }
    }

    private fun startEngineNative(context: Context, prefs: android.content.SharedPreferences) {
        val proto = prefs.getInt("protocol", 0)
        val scanMode = prefs.getInt("scan", 0)
        val ipPos = prefs.getInt("ipVersion", 0)
        val ipVer = when (ipPos) { 0 -> 4; 1 -> 6; 2 -> 10; else -> 4 }
        val quick = prefs.getBoolean("quick", false)
        val h2 = prefs.getBoolean("h2", true)
        val ech = prefs.getBoolean("ech", true)
        val lan = prefs.getBoolean("lan", false)
        val sni = prefs.getString("sni", "")?.trim() ?: ""
        val cfgPath = context.filesDir.resolve("aether.toml").absolutePath
        val noizeArray = arrayOf("off", "light", "balanced", "aggressive", "firewall", "gfw")
        val noizePos = prefs.getInt("noize", 2).coerceIn(0, noizeArray.size - 1)
        val noizeProfile = noizeArray[noizePos]
        val socksPort = if (prefs.getBoolean("socks", false) || proto in 4..5) prefs.getString("socksPort", "1819")?.toIntOrNull() ?: 1819 else 0
        val httpPort = if (prefs.getBoolean("http", false)) prefs.getString("httpPort", "1820")?.toIntOrNull() ?: 1820 else 0
        val forcePeer = prefs.getString("forcePeer", "")?.trim() ?: ""
        val sysProfile = prefs.getInt("sysprofile", 0)
        val teamName = prefs.getString("team", "")?.trim() ?: ""
        val accessToken = prefs.getString("accessToken", "")?.trim() ?: ""
        val accessEmail = prefs.getString("accessEmail", "")?.trim() ?: ""
        val routesFile = prefs.getString("routesFile", "")?.trim() ?: ""
        val routesInline = prefs.getString("routesInline", "")?.trim() ?: ""
        val torPos = prefs.getInt("tor", 0)
        val torMode = if (proto in 4..5) 0 else if (torPos in 0..2) torPos else 0
        val torBridges = prefs.getInt("torBridges", 0)
        val torBridgeLines = prefs.getString("torBridgeLines", "")?.trim() ?: ""
        val engineLog = prefs.getInt("engineLog", 3)
        val backend = prefs.getInt("backend", 0)
        val torSocksDef = prefs.getString("torSocksPort", "1821")?.toIntOrNull() ?: 0
        val torSocksPort = if (torSocksDef == 1821) 0 else torSocksDef
        val torHttpPort = if (prefs.getBoolean("torHttp", false)) prefs.getString("torHttpPort", "1822")?.toIntOrNull() ?: 1822 else 0
        val throughPsiphon = proto == 5
        val psiTransport = prefs.getInt("psiphonTransport", 0)
        val psiphonConfig = JSONObject().put("FCAETransport", psiTransport).toString()
        val psiphonRegion = prefs.getString("psiphonRegion", "ANY") ?: "ANY"
        val psiphonSocksPort = prefs.getString("psiphonSocksPort", "0")?.toIntOrNull() ?: 0
        val psiphonHttpPort = prefs.getString("psiphonHttpPort", "0")?.toIntOrNull() ?: 0
        val sndbuf = (prefs.getString("tunTcpSndbuf", "256")?.toIntOrNull() ?: 256) * 1000
        val rcvbuf = (prefs.getString("tunTcpRcvbuf", "256")?.toIntOrNull() ?: 256) * 1000
        val tunTcpAutoTuning = prefs.getBoolean("tunTcpAutoTuning", false)
        val tunDnsServers = listOf(prefs.getString("tunDnsV4", "")?.trim() ?: "", prefs.getString("tunDnsV6", "")?.trim() ?: "")
            .filter { it.isNotEmpty() }
            .joinToString(",")

        NativeEngine.lifecycleExecutor.execute {
            try { NativeEngine.nativeInit() } catch (_: Throwable) {}
            try { NativeEngine.nativeStop() } catch (_: Throwable) {}
            try {
                NativeEngine.nativeStart(
                    protocol = proto,
                    mode = 0,
                    lanSharing = lan,
                    scanMode = scanMode,
                    ipVersion = ipVer,
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
                    tunTcpSndbuf = sndbuf,
                    tunTcpRcvbuf = rcvbuf,
                    tunTcpAutoTuning = tunTcpAutoTuning,
                    tunDnsServers = tunDnsServers,
                )
            } catch (_: Throwable) {}
        }
    }

    private fun handlePauseResume(context: Context) {
        val prefs = context.getSharedPreferences("aether_vpn", Context.MODE_PRIVATE)
        if (prefs.getInt("mode", 1) != 1) return

        val targetAction = if (lastPaused) FCAEVpnService.ACTION_START else FCAEVpnService.ACTION_STOP
        val intent = Intent(context, FCAEVpnService::class.java).apply {
            this.action = targetAction
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        } catch (_: Throwable) {}
    }

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.fc.fcaevpn.WIDGET_TOGGLE"
        const val ACTION_WIDGET_PAUSE_RESUME = "com.fc.fcaevpn.WIDGET_PAUSE_RESUME"

        private val COLOR_CONNECTED = Color.parseColor("#34D399")
        private val COLOR_DISCONNECTED = Color.parseColor("#8A93A6")
        private val COLOR_PROGRESS = Color.parseColor("#60A5FA")
        private val COLOR_PAUSED = Color.parseColor("#F59E0B")

        private var lastRunning = false
        private var lastPaused = false
        private var lastConnecting = false
        private var lastSpeedLine = "↓ 0 B/s (0 B)  |  ↑ 0 B/s (0 B)"
        private var lastRttLine = "RTT: —"

        fun updateStats(context: Context, rx: Long, tx: Long, totalRx: Long, totalTx: Long, rtt: Int) {
            if (!lastRunning && !lastPaused) return
            lastSpeedLine = "↓ ${fmtBytes(rx)}/s (${fmtBytes(totalRx)})  |  ↑ ${fmtBytes(tx)}/s (${fmtBytes(totalTx)})"
            lastRttLine = if (rtt > 0) "RTT: ${rtt}ms" else "RTT: —"
            updateAllWidgets(context)
        }

        fun updateAllWidgets(context: Context) {
            val appWidgetManager = AppWidgetManager.getInstance(context) ?: return
            val ids = appWidgetManager.getAppWidgetIds(ComponentName(context, VpnWidgetProvider::class.java))
            for (id in ids) {
                updateWidget(context, appWidgetManager, id)
            }
        }

        fun buildStartIntentFromPrefs(context: Context): Intent {
            val prefs = context.getSharedPreferences("aether_vpn", Context.MODE_PRIVATE)
            val i = Intent(context, FCAEVpnService::class.java)
            i.action = FCAEVpnService.ACTION_START
            val proto = prefs.getInt("protocol", 0)
            i.putExtra("protocol", proto)
            val mode = prefs.getInt("mode", 1)
            i.putExtra("mode", mode)
            i.putExtra("tunEngine", prefs.getInt("tunEngine", 0))
            val mtu = prefs.getString("tunMtu", "1500")?.toIntOrNull()?.coerceIn(1280, 9000) ?: 1500
            i.putExtra("tunMtu", mtu)
            val sndbuf = (prefs.getString("tunTcpSndbuf", "256")?.toIntOrNull() ?: 256) * 1000
            val rcvbuf = (prefs.getString("tunTcpRcvbuf", "256")?.toIntOrNull() ?: 256) * 1000
            i.putExtra("tunTcpSndbuf", sndbuf)
            i.putExtra("tunTcpRcvbuf", rcvbuf)
            i.putExtra("tunTcpAutoTuning", prefs.getBoolean("tunTcpAutoTuning", false))
            i.putExtra("scanMode", prefs.getInt("scan", 0))
            val ipPos = prefs.getInt("ipVersion", 0)
            val ipVer = when (ipPos) { 0 -> 4; 1 -> 6; 2 -> 10; else -> 4 }
            i.putExtra("ipVersion", ipVer)
            i.putExtra("quickReconnect", prefs.getBoolean("quick", false))
            i.putExtra("h2Enabled", prefs.getBoolean("h2", true))
            i.putExtra("echEnabled", prefs.getBoolean("ech", true))
            i.putExtra("lanSharing", prefs.getBoolean("lan", false))
            i.putExtra("configPath", context.filesDir.resolve("aether.toml").absolutePath)
            i.putExtra("sni", prefs.getString("sni", "")?.trim() ?: "")
            val socksChecked = prefs.getBoolean("socks", false)
            val socksPortVal = prefs.getString("socksPort", "1819")?.toIntOrNull() ?: 1819
            i.putExtra("socksPort", if (socksChecked || proto in 4..5) socksPortVal else 0)
            val httpChecked = prefs.getBoolean("http", false)
            val httpPortVal = prefs.getString("httpPort", "1820")?.toIntOrNull() ?: 1820
            i.putExtra("httpPort", if (httpChecked) httpPortVal else 0)
            val noizeArray = arrayOf("off", "light", "balanced", "aggressive", "firewall", "gfw")
            val noizePos = prefs.getInt("noize", 2).coerceIn(0, noizeArray.size - 1)
            i.putExtra("noizeProfile", noizeArray[noizePos])
            i.putExtra("forcePeer", prefs.getString("forcePeer", "")?.trim() ?: "")
            i.putExtra("sysProfile", prefs.getInt("sysprofile", 0))
            i.putExtra("teamName", prefs.getString("team", "")?.trim() ?: "")
            i.putExtra("accessToken", prefs.getString("accessToken", "")?.trim() ?: "")
            i.putExtra("accessEmail", prefs.getString("accessEmail", "")?.trim() ?: "")
            i.putExtra("routesFile", prefs.getString("routesFile", "")?.trim() ?: "")
            i.putExtra("routesInline", prefs.getString("routesInline", "")?.trim() ?: "")
            val torPos = prefs.getInt("tor", 0)
            val effectiveTor = if (proto in 4..5) 0 else if (torPos in 0..2) torPos else 0
            i.putExtra("torMode", effectiveTor)
            i.putExtra("torBridges", prefs.getInt("torBridges", 0))
            i.putExtra("torBridgeLines", prefs.getString("torBridgeLines", "")?.trim() ?: "")
            i.putExtra("engineLog", prefs.getInt("engineLog", 3))
            i.putExtra("t2sLog", prefs.getInt("t2sLog", 0))
            i.putExtra("backend", prefs.getInt("backend", 0))
            val torSocksDef = prefs.getString("torSocksPort", "1821")?.toIntOrNull() ?: 0
            i.putExtra("torSocksPort", if (torSocksDef == 1821) 0 else torSocksDef)
            val torHttpChecked = prefs.getBoolean("torHttp", false)
            val torHttpVal = prefs.getString("torHttpPort", "1822")?.toIntOrNull() ?: 1822
            i.putExtra("torHttpPort", if (torHttpChecked) torHttpVal else 0)
            i.putExtra("psiphonThroughTunnel", proto == 5)
            val psiTransport = prefs.getInt("psiphonTransport", 0)
            val psiJson = JSONObject().put("FCAETransport", psiTransport).toString()
            i.putExtra("psiphonConfig", psiJson)
            i.putExtra("psiphonRegion", prefs.getString("psiphonRegion", "ANY") ?: "ANY")
            val psiSocks = prefs.getString("psiphonSocksPort", "0")?.toIntOrNull() ?: 0
            val psiHttp = prefs.getString("psiphonHttpPort", "0")?.toIntOrNull() ?: 0
            i.putExtra("psiphonSocksPort", psiSocks)
            i.putExtra("psiphonHttpPort", psiHttp)
            return i
        }

        private fun fmtBytes(bytes: Long): String {
            return when {
                bytes >= 1_073_741_824L -> String.format("%.1f GB", bytes / 1_073_741_824.0)
                bytes >= 1_048_576L -> String.format("%.1f MB", bytes / 1_048_576.0)
                bytes >= 1024L -> String.format("%.0f KB", bytes / 1024.0)
                else -> "$bytes B"
            }
        }

        private fun updateWidget(
            context: Context,
            appWidgetManager: AppWidgetManager,
            appWidgetId: Int
        ) {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn)
            val prefs = context.getSharedPreferences("aether_vpn", Context.MODE_PRIVATE)
            val isTun = prefs.getInt("mode", 1) == 1
            val modeLabel = if (isTun) "TUN" else "PROXY"

            val statusText: String
            val statusColor: Int
            val btnText: String

            when {
                lastConnecting -> {
                    statusText = "CONNECTING"
                    statusColor = COLOR_PROGRESS
                    btnText = "DISCONNECT"
                }
                lastPaused -> {
                    statusText = "PAUSED"
                    statusColor = COLOR_PAUSED
                    btnText = "DISCONNECT"
                }
                lastRunning -> {
                    statusText = "CONNECTED - $modeLabel"
                    statusColor = COLOR_CONNECTED
                    btnText = "DISCONNECT"
                }
                else -> {
                    statusText = "DISCONNECTED"
                    statusColor = COLOR_DISCONNECTED
                    btnText = "CONNECT"
                }
            }

            views.setTextViewText(R.id.widget_status, statusText)
            views.setTextColor(R.id.widget_status, statusColor)
            views.setTextViewText(R.id.widget_btn_action, btnText)

            val actionBgRes = if (btnText == "CONNECT") R.drawable.widget_btn_connect else R.drawable.widget_btn_disconnect
            views.setInt(R.id.widget_btn_action, "setBackgroundResource", actionBgRes)

            if (isTun && (lastRunning || lastPaused)) {
                views.setViewVisibility(R.id.widget_btn_pause_resume, View.VISIBLE)
                if (lastPaused) {
                    views.setTextViewText(R.id.widget_btn_pause_resume, "START")
                    views.setInt(R.id.widget_btn_pause_resume, "setBackgroundResource", R.drawable.widget_btn_tun_start)
                } else {
                    views.setTextViewText(R.id.widget_btn_pause_resume, "STOP")
                    views.setInt(R.id.widget_btn_pause_resume, "setBackgroundResource", R.drawable.widget_btn_tun_stop)
                }

                val prIntent = Intent(context, VpnWidgetProvider::class.java).apply {
                    action = ACTION_WIDGET_PAUSE_RESUME
                }
                val prPi = PendingIntent.getBroadcast(
                    context, 102, prIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                views.setOnClickPendingIntent(R.id.widget_btn_pause_resume, prPi)
            } else {
                views.setViewVisibility(R.id.widget_btn_pause_resume, View.GONE)
            }

            views.setTextViewText(R.id.widget_stats, lastSpeedLine)
            views.setTextViewText(R.id.widget_rtt, lastRttLine)

            val toggleIntent = Intent(context, VpnWidgetProvider::class.java).apply {
                action = ACTION_WIDGET_TOGGLE
            }
            val togglePi = PendingIntent.getBroadcast(
                context, 101, toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_btn_action, togglePi)

            val settingsIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val settingsPi = PendingIntent.getActivity(
                context, 100, settingsIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_btn_settings, settingsPi)
            views.setOnClickPendingIntent(R.id.widget_header, settingsPi)

            appWidgetManager.updateAppWidget(appWidgetId, views)
        }
    }
}
