package com.fc.fcaevpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.RemoteViews
import java.util.concurrent.Executors

/**
 * Home screen control surface, fixed 3x2 (widget_vpn_info.xml): name, state
 * with the session's RTT, rates, totals, controls.
 *
 * Renders [SessionState] and sends the same commands as the app's
 * notification, to the same owner, so the connect logic has one copy. A tap
 * on the widget is a documented Android 12 exemption from the background
 * service-start restriction, which is what makes the headless connect legal;
 * only "nothing to replay yet" and the one-time VPN consent open the app.
 */
class VpnWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) =
        render(context, ids, force = true)

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action == ACTION_WIDGET_TOGGLE || action == ACTION_WIDGET_PAUSE_RESUME) {
            val pending = goAsync()
            val app = context.applicationContext
            val tapActive = intent.getBooleanExtra(EXTRA_TAP_ACTIVE, false)
            clicks.execute {
                try {
                    when (action) {
                        ACTION_WIDGET_TOGGLE -> {
                            toggle(app, tapActive)
                            if (SessionState.snapshot(app).connecting) scheduleRecheck(app)
                        }
                        ACTION_WIDGET_PAUSE_RESUME -> pauseOrResume(app, tapActive)
                    }
                } finally {
                    pending.finish()
                }
            }
            return
        }
        super.onReceive(context, intent)
        // Nothing else is handled here on purpose: this receiver is in
        // the manifest, and a manifest receiver is delivered by starting
        // its process — so any app-state action added to the filter
        // would resurrect the process on every state broadcast. The
        // feed repaints the widget in-process instead.
    }

    private fun toggle(context: Context, renderedActive: Boolean) {
        VpnCommands.toggle(context, renderedActive)
    }

    private fun pauseOrResume(context: Context, wasPaused: Boolean) {
        SessionState.command(
            if (wasPaused) SessionState.Command.RESUME else SessionState.Command.PAUSE
        )
        if (!dispatch(
                context,
                Intent(context, FCAEVpnService::class.java).setAction(
                    if (wasPaused) FCAEVpnService.ACTION_START else FCAEVpnService.ACTION_STOP
                )
            )
        ) {
            SessionState.command(SessionState.Command.NONE)
            return
        }
        SessionState.markPause(context, !wasPaused)
    }

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.fc.fcaevpn.WIDGET_TOGGLE"
        const val ACTION_WIDGET_PAUSE_RESUME = "com.fc.fcaevpn.WIDGET_PAUSE_RESUME"

        private const val EXTRA_TAP_ACTIVE = "tapActive"
        private const val PENDING_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        private const val RECHECK_DELAY_MS = 2500L

        private val COLOR_CONNECTED = Color.parseColor("#34D399")
        private val COLOR_DISCONNECTED = Color.parseColor("#8A93A6")
        private val COLOR_PROGRESS = Color.parseColor("#60A5FA")

        private val mainHandler = Handler(Looper.getMainLooper())
        private val clicks = Executors.newSingleThreadExecutor { r ->
            Thread(r, "FCAE-Widget").apply { isDaemon = true }
        }

        /** Last rendered content; identical content is not worth a repaint. */
        @Volatile
        private var lastRendered: String? = null


                /**
                 * Repaint now, from wherever a session ends. The teardown paths kill
                 * this process and an in-flight broadcast dies with it, so the owners
                 * call this synchronously before the kill: the last frame the launcher
                 * keeps is the truth.
                 */
        @JvmStatic
        fun refresh(context: Context) {
            val ids = ids(context).takeIf { it.isNotEmpty() } ?: return
            render(context, ids, force = true)
        }

        private fun ids(context: Context): IntArray {
            val manager = AppWidgetManager.getInstance(context) ?: return IntArray(0)
            return manager.getAppWidgetIds(ComponentName(context, VpnWidgetProvider::class.java))
        }

        /**
         * A start can still be refused after the command was accepted (nothing
         * to replay, no engine). Re-ask the owners once it had time to come up,
         * and fall back to DISCONNECTED rather than leaving a button that lies.
         */
        private fun scheduleRecheck(context: Context) {
            val app = context.applicationContext
            mainHandler.postDelayed({
                if (SessionState.isLive()) return@postDelayed
                if (SessionState.snapshot(app).active) {
                    SessionState.command(SessionState.Command.NONE)
                    SessionState.markIdle(app)
                    refresh(app)
                }
            }, RECHECK_DELAY_MS)
        }

        private fun dispatch(context: Context, intent: Intent): Boolean =
            VpnCommands.dispatch(context, intent)

        private fun render(context: Context, ids: IntArray, force: Boolean = false) {
            val manager = AppWidgetManager.getInstance(context) ?: return
            // reconciled(), not snapshot(): a stored frame can outlive its
            // session, and the widget must never offer DISCONNECT for a tunnel
            // that no longer exists.
            val session = SessionState.reconciled(context)
            val tun = session.mode == 1

            // Same meter the notification and the app paint, including while
            // Stop has the TUN paused. Disconnect is the only frame with no
            // reading.
            val shown = if (session.active) session else SessionState.Snapshot.IDLE

            val status = when (session.phase) {
                SessionState.Phase.DISCONNECTED -> "DISCONNECTED"
                SessionState.Phase.CONNECTING -> "CONNECTING"
                SessionState.Phase.RECONNECTING -> "RECONNECTING"
                SessionState.Phase.CONNECTED,
                SessionState.Phase.PAUSED -> "CONNECTED - ${if (tun) "TUN" else "PROXY"}"
            }
            val statusColor = when (session.phase) {
                SessionState.Phase.DISCONNECTED -> COLOR_DISCONNECTED
                SessionState.Phase.CONNECTING -> COLOR_PROGRESS
                SessionState.Phase.RECONNECTING -> COLOR_PROGRESS
                else -> COLOR_CONNECTED
            }
            val action =
                if (session.phase == SessionState.Phase.DISCONNECTED) "CONNECT" else "DISCONNECT"

            // Same rule as the app's own controls (MainActivity.updateButton):
            // the pair is there for a TUN session from the first moment a
            // connect is asked for — dialing included — and gone once the
            // session is over. Stop cancels a dial and pauses a live tunnel, so
            // the label only flips on the paused phase.
            val pausable = tun && session.active
            val pauseLabel = if (session.paused) "START" else "STOP"
            // Down and up are separate readings, each with its own arrow: rates
            // and totals each get a row, split into the two directions.
            // The notification's formatter, not a copy of it: KB/MB/GB text in
            // the widget has to read exactly like the notification and the app.
            val ratesDown = "↓ " + VpnNotification.fmtRate(shown.rx)
            val ratesUp = "↑ " + VpnNotification.fmtRate(shown.tx)
            val totalDown = "↓ " + VpnNotification.fmtBytes(shown.totalRx)
            val totalUp = "↑ " + VpnNotification.fmtBytes(shown.totalTx)
            // The reading, bare, with its unit — the shape the app's own line
            // and the desktop's use. No label: this slot is the RTT's.
            val rtt = "${shown.rtt}ms"

            // Every repaint is a round trip to the launcher: identical content
            // is not worth one.
            val key = listOf(
                status, rtt, ratesDown, ratesUp, totalDown, totalUp,
                action, pauseLabel, pausable.toString()
            ).joinToString("|")
            if (!force && key == lastRendered) return
            lastRendered = key

            val views = RemoteViews(context.packageName, R.layout.widget_vpn)
            views.setTextViewText(R.id.widget_status, status)
            views.setTextColor(R.id.widget_status, statusColor)
            views.setTextViewText(R.id.widget_rtt, rtt)
            views.setTextViewText(R.id.widget_rx_rate, ratesDown)
            views.setTextViewText(R.id.widget_tx_rate, ratesUp)
            views.setTextViewText(R.id.widget_rx_total, totalDown)
            views.setTextViewText(R.id.widget_tx_total, totalUp)
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
                    R.id.widget_btn_pause_resume,
                    pending(context, ACTION_WIDGET_PAUSE_RESUME, 102, session.paused)
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

        /**
         * A command broadcast, tagged with what the button read when drawn: the
         * toggle carries "the session looked active", the pause button "the
         * session looked paused". One extra, one meaning: never act on a
         * snapshot that may have moved since the user saw that button.
         */
        private fun pending(context: Context, action: String, code: Int, active: Boolean) =
            PendingIntent.getBroadcast(
                context, code,
                Intent(context, VpnWidgetProvider::class.java)
                    .setAction(action)
                    .putExtra(EXTRA_TAP_ACTIVE, active),
                PENDING_FLAGS
            )
    }
}
