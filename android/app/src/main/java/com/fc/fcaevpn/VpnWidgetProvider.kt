package com.fc.fcaevpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.view.View
import android.widget.RemoteViews
import java.util.Locale

/**
 * Home screen control surface.
 *
 * It renders [SessionState] and sends the commands the app's own notification
 * sends, to the same owner service: CONNECT is the notification's Start, so a
 * tap connects the last session in the background, with no second copy of the
 * connect logic here to drift away from the app's. A tap on the app's own
 * widget is a documented exemption from Android 12's background service-start
 * restriction, which is what makes that headless start legal.
 *
 * Two cases still open the app, both forced by the platform: no session to
 * replay yet (only the UI can compose one) and the one-time VPN consent, whose
 * dialog is an Activity started for result.
 */
class VpnWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) =
        render(context, manager, ids, force = true)

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        when (intent.action) {
            ACTION_WIDGET_TOGGLE -> {
                toggle(context, intent)
                renderAll(context)
            }

            ACTION_WIDGET_PAUSE_RESUME -> {
                val session = SessionState.snapshot(context)
                val action = if (session.paused) FCAEVpnService.ACTION_START
                else FCAEVpnService.ACTION_STOP
                dispatch(context, Intent(context, FCAEVpnService::class.java).setAction(action))
                renderAll(context)
            }

            // A live Psiphon exit is the AAR's session, not the engine's.
            PsiphonTunnelService.BROADCAST_READY,
            PsiphonTunnelService.BROADCAST_STATS -> {
                if (intent.getBooleanExtra("regionsOnly", false)) return
                if (!PsiphonTunnelService.isCurrentBroadcast(intent)) return
                SessionState.absorb(context, intent)
                renderAll(context)
            }

            PsiphonTunnelService.BROADCAST_STOPPED,
            PsiphonTunnelService.BROADCAST_FAILED -> {
                // Stamped: a failure of a previous session must not blank a
                // live one.
                if (!PsiphonTunnelService.isCurrentBroadcast(intent)) return
                SessionState.markIdle(context)
                renderAll(context)
            }

            FCAEVpnService.BROADCAST_VPN_STATE_CHANGED,
            FCAEVpnService.BROADCAST_VPN_DISCONNECTED -> {
                SessionState.absorb(context, intent)
                renderAll(context)
            }
        }
    }

    private fun toggle(context: Context, intent: Intent) {
        // The flag is what the button read when it was rendered: without it a
        // stale widget could stop the session it just started, or raise a
        // second one on top of a live one.
        val renderedActive = intent.getBooleanExtra(EXTRA_TAP_ACTIVE, false)
        val live = SessionState.isLive()
        when {
            renderedActive && live -> disconnect(context)
            renderedActive -> SessionState.markIdle(context)
            !live && !connect(context) -> openApp(context)
            // Button and reality disagree: reality wins, the render fixes it.
        }
    }

    /** Replay the last session in the background. False means the app must. */
    private fun connect(context: Context): Boolean {
        val session = FCAEVpnService.recalledSession(context) ?: return false
        val command = if (session.getIntExtra("mode", 1) == 1) {
            // Consent is an Activity-for-result flow: it can never be granted
            // from here, and a tunnel must not start blind.
            if (VpnService.prepare(context) != null) return false
            Intent(context, FCAEVpnService::class.java).setAction(FCAEVpnService.ACTION_START)
        } else {
            Intent(context, ProxyNotification::class.java)
                .setAction(ProxyNotification.ACTION_START)
                .putExtras(session)
        }
        if (!dispatch(context, command)) return false
        SessionState.markConnecting(context, FCAEVpnService.stateGeneration())
        return true
    }

    /** End the session, whichever owner holds it. */
    private fun disconnect(context: Context) {
        val tun = FCAEVpnService.ownsSession()
        val proxy = ProxyNotification.isAlive()
        if (tun) {
            dispatch(context, Intent(context, FCAEVpnService::class.java)
                .setAction(FCAEVpnService.ACTION_DISCONNECT))
        }
        if (proxy) {
            dispatch(context, Intent(context, ProxyNotification::class.java)
                .setAction(ProxyNotification.ACTION_DISCONNECT_KILL))
        }
        if (!tun && !proxy) {
            // No owner left to ask (process recycled under the button): end the
            // engine directly so no data plane outlives the tap.
            try {
                PsiphonTunnelService.stopBound(context)
            } catch (_: Throwable) {
            }
            NativeEngine.lifecycleExecutor.execute {
                try {
                    NativeEngine.nativeStopBegin()
                } catch (_: Throwable) {
                }
                try {
                    NativeEngine.nativeStop()
                } catch (_: Throwable) {
                }
            }
        }
        SessionState.markIdle(context)
    }

    private fun openApp(context: Context) {
        try {
            context.startActivity(
                Intent(context, MainActivity::class.java)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra(MainActivity.EXTRA_TRIGGER_CONNECT, true)
            )
        } catch (_: Throwable) {
        }
    }

    private fun dispatch(context: Context, intent: Intent): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
        true
    } catch (_: Throwable) {
        false
    }

    private fun renderAll(context: Context) {
        val manager = AppWidgetManager.getInstance(context) ?: return
        val ids = manager.getAppWidgetIds(ComponentName(context, VpnWidgetProvider::class.java))
        if (ids.isNotEmpty()) render(context, manager, ids)
    }

    private fun render(
        context: Context,
        manager: AppWidgetManager,
        ids: IntArray,
        force: Boolean = false
    ) {
        val session = SessionState.snapshot(context)
        val tun = context.getSharedPreferences(PREFS_MAIN, Context.MODE_PRIVATE)
            .getInt("mode", 1) == 1

        val status: String
        val statusColor: Int
        val action: String
        when {
            session.connecting -> {
                status = "CONNECTING"; statusColor = COLOR_PROGRESS; action = "DISCONNECT"
            }
            session.paused -> {
                status = "PAUSED"; statusColor = COLOR_PAUSED; action = "DISCONNECT"
            }
            session.running -> {
                status = "CONNECTED - ${if (tun) "TUN" else "PROXY"}"
                statusColor = COLOR_CONNECTED
                action = "DISCONNECT"
            }
            else -> {
                status = "DISCONNECTED"; statusColor = COLOR_DISCONNECTED; action = "CONNECT"
            }
        }

        val pausable = tun && (session.running || session.paused)
        val pauseLabel = if (session.paused) "START" else "STOP"
        val values = listOf(
            status,
            if (session.rtt > 0) "RTT: ${session.rtt} ms" else "RTT: —",
            "↓ " + fmtRate(session.rx),
            "↑ " + fmtRate(session.tx),
            "↓ " + fmtBytes(session.totalRx),
            "↑ " + fmtBytes(session.totalTx),
            action,
            pauseLabel,
            pausable.toString()
        )
        // Every repaint is a round trip to the launcher: identical content is
        // not worth one.
        val key = values.joinToString("|")
        if (!force && key == lastRendered) return
        lastRendered = key

        val views = RemoteViews(context.packageName, R.layout.widget_vpn)
        views.setTextViewText(R.id.widget_status, status)
        views.setTextColor(R.id.widget_status, statusColor)
        views.setTextViewText(R.id.widget_rtt, values[1])
        views.setTextViewText(R.id.widget_rx_rate, values[2])
        views.setTextViewText(R.id.widget_tx_rate, values[3])
        views.setTextViewText(R.id.widget_rx_total, values[4])
        views.setTextViewText(R.id.widget_tx_total, values[5])
        views.setTextViewText(R.id.widget_btn_action, action)
        views.setInt(
            R.id.widget_btn_action, "setBackgroundResource",
            if (action == "CONNECT") R.drawable.widget_btn_connect else R.drawable.widget_btn_disconnect
        )
        views.setOnClickPendingIntent(
            R.id.widget_btn_action,
            pending(context, ACTION_WIDGET_TOGGLE, 101, session.active)
        )
        views.setViewVisibility(
            R.id.widget_btn_pause_resume, if (pausable) View.VISIBLE else View.GONE
        )
        if (pausable) {
            views.setTextViewText(R.id.widget_btn_pause_resume, pauseLabel)
            views.setInt(
                R.id.widget_btn_pause_resume, "setBackgroundResource",
                if (session.paused) R.drawable.widget_btn_tun_start else R.drawable.widget_btn_tun_stop
            )
            views.setOnClickPendingIntent(
                R.id.widget_btn_pause_resume, pending(context, ACTION_WIDGET_PAUSE_RESUME, 102, false)
            )
        }

        val open = PendingIntent.getActivity(
            context, 100,
            Intent(context, MainActivity::class.java)
                .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PENDING_FLAGS
        )
        views.setOnClickPendingIntent(R.id.widget_btn_settings, open)
        views.setOnClickPendingIntent(R.id.widget_header, open)

        for (id in ids) manager.updateAppWidget(id, views)
    }

    /** A command broadcast, tagged with what the button read when drawn. */
    private fun pending(context: Context, action: String, code: Int, active: Boolean) =
        PendingIntent.getBroadcast(
            context, code,
            Intent(context, VpnWidgetProvider::class.java)
                .setAction(action)
                .putExtra(EXTRA_TAP_ACTIVE, active),
            PENDING_FLAGS
        )

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.fc.fcaevpn.WIDGET_TOGGLE"
        const val ACTION_WIDGET_PAUSE_RESUME = "com.fc.fcaevpn.WIDGET_PAUSE_RESUME"

        private const val EXTRA_TAP_ACTIVE = "tapActive"
        private const val PREFS_MAIN = "aether_vpn"
        private const val PENDING_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        private const val KIB = 1024L
        private const val MIB = KIB * 1024
        private const val GIB = MIB * 1024

        private val COLOR_CONNECTED = Color.parseColor("#34D399")
        private val COLOR_DISCONNECTED = Color.parseColor("#8A93A6")
        private val COLOR_PROGRESS = Color.parseColor("#60A5FA")
        private val COLOR_PAUSED = Color.parseColor("#F59E0B")

        /** Last rendered content; identical content is not worth a repaint. */
        private var lastRendered: String? = null

        private fun fmtBytes(bytes: Long): String = when {
            bytes >= GIB -> String.format(Locale.US, "%.1f GB", bytes / GIB.toDouble())
            bytes >= MIB -> String.format(Locale.US, "%.1f MB", bytes / MIB.toDouble())
            bytes >= KIB -> String.format(Locale.US, "%.1f KB", bytes / KIB.toDouble())
            else -> "$bytes B"
        }

        private fun fmtRate(bytesPerSecond: Long): String =
            fmtBytes(if (bytesPerSecond < 0L) 0L else bytesPerSecond) + "/s"
    }
}
