package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper

/** Connect and disconnect for the widget and the Quick Settings tile.
 *  One copy: a tile must not grow a second session starter. */
object VpnCommands {
    private const val RECHECK_DELAY_MS = 2500L
    private val main = Handler(Looper.getMainLooper())

    fun dispatch(context: Context, intent: Intent): Boolean =
        start(context, intent, foreground = true)

    fun start(context: Context, intent: Intent, foreground: Boolean): Boolean = try {
        if (foreground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
        true
    } catch (_: Throwable) {
        false
    }

    fun toggle(context: Context, renderedActive: Boolean, start: (Context, Intent) -> Boolean = ::dispatch) {
        val live = SessionState.isLive()
        if (live) disconnect(context, start)
        else connect(context, start)
    }

    /** Optimistic frame shown before the foreground owner resolves the saved
     *  session. The owner publishes the authoritative mode and phase. */
    fun paintConnecting(context: Context): Boolean {
        VpnTileService.clearPendingExit(context)
        SessionState.command(SessionState.Command.CONNECT)
        SessionState.markConnecting(context, 1)
        return true
    }

    /** Disconnect frame before teardown runs. The latch hides still-live
     *  owner ticks, so the button can flip now instead of waiting on the
     *  service. */
    fun paintIdle(context: Context) {
        SessionState.command(SessionState.Command.DISCONNECT)
        SessionState.markIdle(context)
    }

    /** Send a replay command without reading configuration on the control
     *  surface. The foreground owner loads and validates the saved session. */
    fun connect(context: Context, start: (Context, Intent) -> Boolean = ::dispatch): Boolean {
        VpnTileService.clearPendingExit(context)
        val command = Intent(context, FCAEVpnService::class.java)
            .setAction(FCAEVpnService.ACTION_REPLAY)
        SessionState.command(SessionState.Command.CONNECT)
        SessionState.markConnecting(context, 1)
        if (!start(context, command)) {
            SessionState.command(SessionState.Command.NONE)
            SessionState.markIdle(context)
            return false
        }
        ProcessExit.cancel()
        return true
    }

    /** Tear the owners down in this process. startForegroundService(DISCONNECT)
     *  from the widget/tile is not the notification's PendingIntent path: it
     *  can report success without onStartCommand ever running, and then
     *  disconnectNow was skipped — the session (and process) stayed up. */
    fun disconnect(context: Context, start: (Context, Intent) -> Boolean = ::dispatch) {
        paintIdle(context)
        val tun = FCAEVpnService.disconnectNow()
        val proxy = ProxyNotification.disconnectNow()
        if (!tun && !proxy) {
            endIdle(context)
            return
        }
        // Widget teardown is a direct in-process call, unlike the notification
        // PendingIntent path. Always arm the remote-disconnect exit watchdog so
        // an owner that is already stopping cannot leave this process alive.
        ProcessExit.request(context, true)
    }

    /** Disconnect when no owner is up. The tap still has to end this process
     *  and the :psiphon one; clearing the widget frame is not enough. */
    fun endIdle(context: Context) {
        val app = context.applicationContext
        SessionState.command(SessionState.Command.NONE)
        SessionState.markIdle(app)
        FCAEVpnService.disconnectNow()
        ProxyNotification.disconnectNow()
        try {
            app.stopService(Intent(app, FCAEVpnService::class.java))
        } catch (_: Throwable) {
        }
        try {
            app.stopService(Intent(app, ProxyNotification::class.java))
        } catch (_: Throwable) {
        }
        try {
            PsiphonTunnelService.killProcessOnExit(app)
        } catch (_: Throwable) {
        }
        ProcessExit.request(app, true)
    }

    fun openApp(context: Context) {
        try {
            context.startActivity(
                Intent(context, MainActivity::class.java)
                    .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra(MainActivity.EXTRA_TRIGGER_CONNECT, true)
            )
        } catch (_: Throwable) {
        }
    }

    fun recheck(context: Context) {
        val app = context.applicationContext
        main.postDelayed({
            if (SessionState.isLive()) return@postDelayed
            if (SessionState.snapshot(app).active) {
                SessionState.command(SessionState.Command.NONE)
                SessionState.markIdle(app)
            }
        }, RECHECK_DELAY_MS)
    }
}
