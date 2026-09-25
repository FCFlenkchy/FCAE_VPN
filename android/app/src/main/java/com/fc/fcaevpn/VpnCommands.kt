package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
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
        when {
            renderedActive && live -> disconnect(context, start)
            renderedActive -> SessionState.markIdle(context)
            !live && !connect(context, start) -> openApp(context)
        }
    }

    /** Replay the last session. False means the app must show the consent screen. */
    fun connect(context: Context, start: (Context, Intent) -> Boolean = ::dispatch): Boolean {
        val session = FCAEVpnService.recalledSession(context) ?: return false
        val mode = session.getIntExtra("mode", 1)
        val command = if (mode == 1) {
            if (VpnService.prepare(context) != null) return false
            Intent(context, FCAEVpnService::class.java).setAction(FCAEVpnService.ACTION_START)
        } else {
            Intent(context, ProxyNotification::class.java)
                .setAction(ProxyNotification.ACTION_START)
                .putExtras(session)
        }
        SessionState.command(SessionState.Command.CONNECT)
        SessionState.markConnecting(context, mode)
        if (!start(context, command)) {
            SessionState.command(SessionState.Command.NONE)
            SessionState.markIdle(context)
            return false
        }
        return true
    }

    fun disconnect(context: Context, start: (Context, Intent) -> Boolean = ::dispatch) {
        SessionState.command(SessionState.Command.DISCONNECT)
        val tun = FCAEVpnService.ownsSession()
        val proxy = ProxyNotification.isAlive()
        if (tun) {
            start(context, Intent(context, FCAEVpnService::class.java)
                .setAction(FCAEVpnService.ACTION_DISCONNECT))
        }
        if (proxy) {
            start(context, Intent(context, ProxyNotification::class.java)
                .setAction(ProxyNotification.ACTION_DISCONNECT_KILL))
        }
        if (!tun && !proxy) {
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
        if (!tun && !proxy && !FCAEApplication.uiOnScreen()) {
            try {
                PsiphonTunnelService.killProcessOnExit(context)
            } catch (_: Throwable) {
            }
            FCAEVpnService.killProcessQuietly()
        }
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
