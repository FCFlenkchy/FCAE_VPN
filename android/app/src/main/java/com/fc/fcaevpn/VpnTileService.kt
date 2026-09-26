package com.fc.fcaevpn

import android.app.PendingIntent
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
        listening = this
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
        if (tile.state == state && tile.icon != null) return
        paint(active)
    }

    companion object {
        @Volatile private var exitPending = false

        fun clearPendingExit(context: Context) {
            exitPending = false
        }

        @Volatile
        private var listening: VpnTileService? = null

        private val main = Handler(Looper.getMainLooper())

        fun publish() {
            val tile = listening ?: return
            if (Looper.myLooper() == Looper.getMainLooper()) tile.refresh()
            else main.post { if (listening === tile) tile.refresh() }
        }
    }
}
