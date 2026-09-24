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
            // Check VPN permission for TUN mode
            if (isTun) {
                val prep = VpnService.prepare(context)
                if (prep != null) {
                    val mainIntent = Intent(context, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        putExtra(MainActivity.EXTRA_TRIGGER_CONNECT, true)
                    }
                    context.startActivity(mainIntent)
                    return
                }
            }

            // Launch MainActivity with trigger to start tunnel cleanly using all its shared logic
            val mainIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra(MainActivity.EXTRA_TRIGGER_CONNECT, true)
            }
            context.startActivity(mainIntent)
            lastConnecting = true
            updateAllWidgets(context)
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
