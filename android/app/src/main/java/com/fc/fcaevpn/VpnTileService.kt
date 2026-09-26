package com.fc.fcaevpn

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** One Quick Settings button: connect the saved session, or disconnect it.
 *  Pause stays on the widget and the notification. */
class VpnTileService : TileService() {

    override fun onStartListening() {
        enableRefreshTicket.incrementAndGet()
        updateRequested = false
        requestedActive = null
        listening = this
        if (ProcessExit.deferForTileBinding()) exitPending = true
        SessionState.reconciled(this)
        refresh()
    }

    override fun onStopListening() {
        if (listening === this) listening = null
        // Retry once the shade closes, but only for an explicit disconnect.
        if (exitPending && !FCAEVpnService.sessionActive()
            && !ProxyNotification.sessionActive()) {
            exitPending = false
            ProcessExit.request(this, true)
        }
    }

    override fun onClick() {
        val active = qsTile?.state == Tile.STATE_ACTIVE
        val run = Runnable { perform(active) }
        if (isLocked) unlockAndRun(run) else run.run()
    }

    private fun perform(renderedActive: Boolean) {
        val live = SessionState.isLive()
        if (live) {
            exitPending = true
            paint(false)
            // Same process as the owners: startForegroundService from a tile
            // is rejected on Android 14, and startService can report success
            // without the Disconnect command landing. disconnectNow talks to
            // the running instance directly, like the notification path.
            VpnCommands.disconnect(this)
            return
        }
        clearPendingExit(this)
        // Android 14 refuses a foreground start from the tile itself. A blank
        // activity is in the foreground, so the same start the widget uses is
        // legal there. 12 and 15 do not need the hop.
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            collapse(Intent(this, VpnTileActivity::class.java))
            return
        }
        if (!VpnCommands.connect(this)) {
            collapse(Intent(this, MainActivity::class.java)
                .putExtra(MainActivity.EXTRA_TRIGGER_CONNECT, true))
            return
        }
        paint(true)
        VpnCommands.recheck(this)
    }

    private fun collapse(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 7, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun paint(active: Boolean) {
        publishedActive = active
        requestedActive = null
        val tile = qsTile ?: return
        tile.icon = Icon.createWithResource(this, R.drawable.ic_fcae_vpn)
        tile.label = getString(R.string.app_name)
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }

    fun refresh() {
        val tile = qsTile ?: return
        val active = SessionState.snapshot(this).active
        val state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (tile.state == state && tile.icon != null) {
            publishedActive = active
            requestedActive = null
            return
        }
        paint(active)
    }

    companion object {
        @Volatile private var exitPending = false
        @Volatile private var updateRequested = false
        @Volatile private var requestedActive: Boolean? = null
        @Volatile private var publishedActive: Boolean? = null

        @JvmStatic
        fun deferTerminalExit(): Boolean {
            if (listening == null && !updateRequested) return false
            exitPending = true
            return true
        }

        fun clearPendingExit(context: Context) {
            exitPending = false
        }

        private const val ENABLE_REFRESH_ATTEMPTS = 20
        private const val ENABLE_REFRESH_INTERVAL_MS = 250L
        private val enableRefreshTicket = java.util.concurrent.atomic.AtomicInteger()

        fun refreshAfterEnable(context: Context) {
            val ticket = enableRefreshTicket.incrementAndGet()
            requestEnabledState(context.applicationContext, ticket, 0)
        }

        fun cancelEnableRefresh() {
            enableRefreshTicket.incrementAndGet()
        }

        private fun requestEnabledState(context: Context, ticket: Int, attempt: Int) {
            if (ticket != enableRefreshTicket.get()) return
            publishedActive = null
            requestedActive = null
            updateRequested = false
            publish(context)
            if (attempt + 1 >= ENABLE_REFRESH_ATTEMPTS) return
            main.postDelayed({
                if (ticket == enableRefreshTicket.get() && listening == null) {
                    requestEnabledState(context, ticket, attempt + 1)
                }
            }, ENABLE_REFRESH_INTERVAL_MS)
        }

        @Volatile
        private var listening: VpnTileService? = null

        private val main = Handler(Looper.getMainLooper())

        fun publish(context: Context) {
            val tile = listening
            val active = SessionState.snapshot(context).active
            if (tile == null && (publishedActive == active ||
                    updateRequested && requestedActive == active)) return
            if (tile != null) {
                if (Looper.myLooper() == Looper.getMainLooper()) tile.refresh()
                else main.post { if (listening === tile) tile.refresh() }
                return
            }
            updateRequested = true
            requestedActive = active
            try {
                TileService.requestListeningState(
                    context.applicationContext,
                    ComponentName(context, VpnTileService::class.java)
                )
            } catch (_: RuntimeException) {
                updateRequested = false
                requestedActive = null
            }
        }
    }
}
