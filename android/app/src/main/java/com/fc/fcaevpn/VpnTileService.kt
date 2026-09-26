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
        updateRequested = false
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
        val run = Runnable { perform() }
        if (isLocked) unlockAndRun(run) else run.run()
    }

    private fun perform() {
        val live = SessionState.isLive()
        val command = Intent(this, VpnTileActivity::class.java)
        if (live) {
            exitPending = true
            paint(false)
            command.putExtra(VpnTileActivity.EXTRA_DISCONNECT, true)
        } else {
            clearPendingExit(this)
            paint(true)
        }
        collapse(command)
    }

    private fun collapse(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val requestCode = if (intent.getBooleanExtra(VpnTileActivity.EXTRA_DISCONNECT, false)) 8 else 7
            startActivityAndCollapse(
                PendingIntent.getActivity(this, requestCode, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun paint(active: Boolean) {
        publishedActive = active
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
        @Volatile private var updateRequested = false
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

        @Volatile
        private var listening: VpnTileService? = null

        private val main = Handler(Looper.getMainLooper())

        fun publish(context: Context) {
            val tile = listening
            val active = SessionState.snapshot(context).active
            if (tile == null && publishedActive == active) return
            if (tile != null) {
                publishedActive = active
                if (Looper.myLooper() == Looper.getMainLooper()) tile.refresh()
                else main.post { if (listening === tile) tile.refresh() }
                return
            }
            updateRequested = true
            try {
                TileService.requestListeningState(
                    context.applicationContext,
                    ComponentName(context, VpnTileService::class.java)
                )
                publishedActive = active
            } catch (_: RuntimeException) {
                updateRequested = false
            }
        }
    }
}
