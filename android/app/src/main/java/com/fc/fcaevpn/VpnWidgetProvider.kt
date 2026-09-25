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
import android.os.SystemClock
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
 *
 * Launchers rate-limit RemoteViews. Telemetry used to rebuild the whole
 * widget (buttons, backgrounds, click intents) at 1 Hz, so CONNECT/DISCONNECT
 * paints were queued or dropped. Controls and meters are separate paints;
 * button chrome is dedicated views, not setBackgroundResource.
 */
class VpnWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) =
        render(context, ids, force = true, full = true)

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action == ACTION_WIDGET_TOGGLE || action == ACTION_WIDGET_PAUSE_RESUME) {
            val app = context.applicationContext
            val tapActive = intent.getBooleanExtra(EXTRA_TAP_ACTIVE, false)
            inReceive.set(true)
            try {
                // Optimistic frame after the launcher finishes delivering this
                // click. Updating AppWidgetManager inside onReceive is what
                // hosts hold until the binder call ends — the half-second
                // (or dropped) button paint.
                when (action) {
                    ACTION_WIDGET_TOGGLE -> {
                        if (!tapActive) {
                            try { VpnCommands.paintConnecting(app) } catch (_: Throwable) {}
                        } else {
                            try { VpnCommands.paintIdle(app) } catch (_: Throwable) {}
                        }
                    }
                    ACTION_WIDGET_PAUSE_RESUME -> {
                        try {
                            SessionState.command(
                                if (tapActive) SessionState.Command.RESUME
                                else SessionState.Command.PAUSE
                            )
                            SessionState.markPause(app, !tapActive)
                        } catch (_: Throwable) {}
                    }
                }
            } finally {
                inReceive.set(false)
            }
            val pending = goAsync()
            clicks.execute {
                try {
                    when (action) {
                        ACTION_WIDGET_TOGGLE -> {
                            toggle(app, tapActive)
                            if (SessionState.snapshot(app).connecting) scheduleRecheck(app)
                        }
                        ACTION_WIDGET_PAUSE_RESUME -> pauseOrResume(app, tapActive)
                    }
                } catch (_: Throwable) {
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
        if (!dispatch(
                context,
                Intent(context, FCAEVpnService::class.java).setAction(
                    if (wasPaused) FCAEVpnService.ACTION_START else FCAEVpnService.ACTION_STOP
                )
            )
        ) {
            SessionState.command(SessionState.Command.NONE)
            SessionState.markPause(context, wasPaused)
        }
    }

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.fc.fcaevpn.WIDGET_TOGGLE"
        const val ACTION_WIDGET_PAUSE_RESUME = "com.fc.fcaevpn.WIDGET_PAUSE_RESUME"

        private const val EXTRA_TAP_ACTIVE = "tapActive"
        private const val PENDING_FLAGS =
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        private const val RECHECK_DELAY_MS = 2500L
        /** Meter-only paints. Control changes never wait on this. */
        private const val METER_MIN_MS = 2000L

        private const val REQ_OPEN = 100
        private const val REQ_CONNECT = 101
        private const val REQ_STOP = 102
        private const val REQ_DISCONNECT = 103
        private const val REQ_START = 104

        private val COLOR_CONNECTED = Color.parseColor("#34D399")
        private val COLOR_DISCONNECTED = Color.parseColor("#8A93A6")
        private val COLOR_PROGRESS = Color.parseColor("#60A5FA")

        private val mainHandler = Handler(Looper.getMainLooper())
        private val clicks = Executors.newSingleThreadExecutor { r ->
            Thread(r, "FCAE-Widget").apply { isDaemon = true }
        }
        private val inReceive = ThreadLocal.withInitial { false }

        @Volatile private var lastControlKey: String? = null
        @Volatile private var lastMeterKey: String? = null
        @Volatile private var lastMeterAt = 0L
        @Volatile private var paintContext: Context? = null
        /** First paint of this process must reinflate: layout IDs may have
         *  changed since the host last inflated, and a partial merge cannot
         *  create views. */
        @Volatile private var inflated = false

        private val postedPaint = Runnable {
            val ctx = paintContext ?: return@Runnable
            paintNow(ctx)
        }

        /**
         * Repaint now, from wherever a session ends. The teardown paths kill
         * this process and an in-flight broadcast dies with it, so the owners
         * call this synchronously before the kill: the last frame the launcher
         * keeps is the truth.
         */
        @JvmStatic
        fun refresh(context: Context) {
            val app = context.applicationContext
            val ids = ids(app)
            if (ids.isEmpty()) return
            paintContext = app
            val onMain = Looper.myLooper() == Looper.getMainLooper()
            // Inside the widget click delivery the host is still applying the
            // tap; a binder update there is deferred or dropped. Everywhere
            // else — teardown especially — paint on this thread so a process
            // kill cannot eat the queued frame.
            if (onMain && inReceive.get() != true) {
                mainHandler.removeCallbacks(postedPaint)
                paintNow(app)
            } else {
                mainHandler.removeCallbacks(postedPaint)
                mainHandler.post(postedPaint)
            }
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

        private fun paintNow(context: Context) {
            val ids = ids(context)
            if (ids.isEmpty()) return
            render(context, ids, force = false, full = false)
        }

        private fun render(context: Context, ids: IntArray, force: Boolean = false, full: Boolean = false) {
            val manager = AppWidgetManager.getInstance(context) ?: return
            // reconciled(), not snapshot(): a stored frame can outlive its
            // session, and the widget must never offer DISCONNECT for a tunnel
            // that no longer exists.
            val session = SessionState.reconciled(context)
            val tun = session.mode == 1

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
            val connect = session.phase == SessionState.Phase.DISCONNECTED
            val pausable = tun && session.active
            val paused = session.paused
            val ratesDown = "↓ " + VpnNotification.fmtRate(shown.rx)
            val ratesUp = "↑ " + VpnNotification.fmtRate(shown.tx)
            val totalDown = "↓ " + VpnNotification.fmtBytes(shown.totalRx)
            val totalUp = "↑ " + VpnNotification.fmtBytes(shown.totalTx)
            val rtt = "${shown.rtt}ms"

            val controlKey = "$status|$statusColor|$connect|$pausable|$paused"
            val meterKey = "$rtt|$ratesDown|$ratesUp|$totalDown|$totalUp"
            val controlsChanged = force || controlKey != lastControlKey
            val metersChanged = force || meterKey != lastMeterKey
            if (!controlsChanged && !metersChanged) return

            if (!controlsChanged && !full) {
                val wait = METER_MIN_MS - (SystemClock.elapsedRealtime() - lastMeterAt)
                if (wait > 0L) {
                    paintContext = context.applicationContext
                    mainHandler.removeCallbacks(postedPaint)
                    mainHandler.postDelayed(postedPaint, wait)
                    return
                }
                val views = RemoteViews(context.packageName, R.layout.widget_vpn)
                bindMeters(views, rtt, ratesDown, ratesUp, totalDown, totalUp)
                push(manager, ids, views, full = false)
                lastMeterKey = meterKey
                lastMeterAt = SystemClock.elapsedRealtime()
                return
            }

            val views = RemoteViews(context.packageName, R.layout.widget_vpn)
            views.setTextViewText(R.id.widget_status, status)
            views.setTextColor(R.id.widget_status, statusColor)
            bindMeters(views, rtt, ratesDown, ratesUp, totalDown, totalUp)

            // Dedicated views, XML backgrounds. setBackgroundResource on a
            // partial update is what left CONNECT green after the label
            // flipped, and what some hosts ignore until a full reinflate.
            views.setViewVisibility(R.id.widget_btn_connect, if (connect) View.VISIBLE else View.GONE)
            views.setViewVisibility(R.id.widget_btn_disconnect, if (connect) View.GONE else View.VISIBLE)
            views.setViewVisibility(R.id.widget_btn_stop, if (pausable && !paused) View.VISIBLE else View.GONE)
            views.setViewVisibility(R.id.widget_btn_start, if (pausable && paused) View.VISIBLE else View.GONE)

            views.setOnClickPendingIntent(
                R.id.widget_btn_connect,
                pending(context, ACTION_WIDGET_TOGGLE, REQ_CONNECT, false)
            )
            views.setOnClickPendingIntent(
                R.id.widget_btn_disconnect,
                pending(context, ACTION_WIDGET_TOGGLE, REQ_DISCONNECT, true)
            )
            views.setOnClickPendingIntent(
                R.id.widget_btn_stop,
                pending(context, ACTION_WIDGET_PAUSE_RESUME, REQ_STOP, false)
            )
            views.setOnClickPendingIntent(
                R.id.widget_btn_start,
                pending(context, ACTION_WIDGET_PAUSE_RESUME, REQ_START, true)
            )

            val open = PendingIntent.getActivity(
                context, REQ_OPEN,
                Intent(context, MainActivity::class.java)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PENDING_FLAGS
            )
            views.setOnClickPendingIntent(R.id.widget_btn_settings, open)
            views.setOnClickPendingIntent(R.id.widget_header, open)

            // A full update after a tap is what launchers defer (~half a
            // second) and what reinflates the layout, flashing the status
            // down to its placeholder. Merge into the view already on screen
            // once this process has inflated once.
            val reinflate = full || !inflated
            push(manager, ids, views, reinflate)
            inflated = true
            lastControlKey = controlKey
            lastMeterKey = meterKey
            lastMeterAt = SystemClock.elapsedRealtime()
        }

        private fun bindMeters(
            views: RemoteViews,
            rtt: String,
            ratesDown: String,
            ratesUp: String,
            totalDown: String,
            totalUp: String
        ) {
            views.setTextViewText(R.id.widget_rtt, rtt)
            views.setTextViewText(R.id.widget_rx_rate, ratesDown)
            views.setTextViewText(R.id.widget_tx_rate, ratesUp)
            views.setTextViewText(R.id.widget_rx_total, totalDown)
            views.setTextViewText(R.id.widget_tx_total, totalUp)
        }

        private fun push(
            manager: AppWidgetManager,
            ids: IntArray,
            views: RemoteViews,
            full: Boolean
        ) {
            if (full) {
                for (id in ids) manager.updateAppWidget(id, views)
            } else {
                for (id in ids) manager.partiallyUpdateAppWidget(id, views)
            }
        }

        /**
         * A command broadcast, tagged with what the button read when drawn: the
         * toggle carries "the session looked active", the pause button "the
         * session looked paused". One extra, one meaning: never act on a
         * snapshot that may have moved since the user saw that button.
         *
         * Each button has its own request code so FLAG_IMMUTABLE extras are
         * never rewritten on the sibling control.
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
