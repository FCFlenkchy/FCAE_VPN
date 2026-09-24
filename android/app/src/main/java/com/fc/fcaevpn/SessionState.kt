package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.os.SystemClock

/**
 * The one status feed for surfaces without an Activity.
 *
 * [FCAEVpnService] (TUN) and [ProxyNotification] (proxy) publish here on every
 * tick of the loops they already run; the home screen widget renders
 * [snapshot]. The broadcast is the app's own state channel (same action, same
 * extras, same generation), so the Activity and the widget read one story.
 *
 * Only state transitions reach disk — rates live in memory, and a write per
 * second is not worth the flash. That is enough for the widget to draw the
 * truth on a cold start (a tunnel that outlived the launcher, a session that
 * ended off screen) and it takes the numbers from the next tick.
 */
object SessionState {

    private const val PREFS = "fcae_session_state"
    private const val K_RUNNING = "running"
    private const val K_PAUSED = "paused"
    private const val K_CONNECTING = "connecting"
    private const val K_RX = "rx"
    private const val K_TX = "tx"
    private const val K_TOTAL_RX = "totalRx"
    private const val K_TOTAL_TX = "totalTx"
    private const val K_RTT = "rtt"
    /** Write time, elapsedRealtime: a lower clock means the device rebooted. */
    private const val K_STAMP = "stamp"

    data class Snapshot(
        val running: Boolean,
        val paused: Boolean,
        val connecting: Boolean,
        val rx: Long,
        val tx: Long,
        val totalRx: Long,
        val totalTx: Long,
        val rtt: Int
    ) {
        /** Up, dialing, or held open. */
        val active: Boolean get() = running || paused || connecting

        companion object {
            @JvmField val IDLE = Snapshot(false, false, false, 0L, 0L, 0L, 0L, 0)
        }
    }

    /** Flags of the last persisted write; statistics alone never trigger one. */
    private var persistedFlags = -1

    /**
     * Last snapshot reported in this process. Publishers and the widget share
     * the app process, so this is the live value: rates move every second while
     * the disk copy deliberately stands still.
     */
    @Volatile
    private var latest: Snapshot? = null

    private var rttHeld = 0

    /**
     * The RTT of the session, fixed by its first successful probe.
     *
     * One value, one session, one place: every surface reads this, so the app,
     * the notification and the widget cannot show two different latencies for
     * the same tunnel. Latency does not change while a tunnel is up, so
     * re-probing it would only make the number under the user's eyes jump; a
     * new session starts the measurement over.
     */
    @JvmStatic
    @Synchronized
    fun holdRtt(sampleMs: Int): Int {
        if (sampleMs > 0 && rttHeld == 0) rttHeld = sampleMs
        return rttHeld
    }

    /** Forget the held RTT: the next session measures its own. */
    @JvmStatic
    @Synchronized
    fun clearRtt() {
        rttHeld = 0
    }

    /** Report a measured state: persist it and broadcast it. */
    @JvmStatic
    fun publish(
        context: Context,
        running: Boolean,
        paused: Boolean,
        connecting: Boolean,
        rx: Long,
        tx: Long,
        totalRx: Long,
        totalTx: Long,
        rttSample: Int
    ) {
        val rtt = holdRtt(rttSample)
        write(context, Snapshot(running, paused, connecting, rx, tx, totalRx, totalTx, rtt))
        val intent = Intent(FCAEVpnService.BROADCAST_VPN_STATE_CHANGED)
            .setPackage(context.packageName)
            .putExtra("generation", FCAEVpnService.stateGeneration())
            .putExtra("running", running)
            .putExtra("paused", paused)
            .putExtra("connecting", connecting)
            .putExtra("rx", rx)
            .putExtra("tx", tx)
            .putExtra("totalRx", totalRx)
            .putExtra("totalTx", totalTx)
            .putExtra("rtt", rtt)
        try {
            context.sendBroadcast(intent)
        } catch (_: Throwable) {
        }
    }

    /**
     * Ingest a telemetry intent: a state broadcast of the app's own channel, or
     * one of the AAR's — a live Psiphon exit measures in its own process, and
     * its broadcasts are the only numbers that exist on that path.
     */
    @JvmStatic
    fun absorb(context: Context, intent: Intent) {
        val snapshot = when (intent.action) {
            PsiphonTunnelService.BROADCAST_STATS -> Snapshot(
                running = true, paused = false, connecting = false,
                rx = intent.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L),
                tx = intent.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0L),
                totalRx = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L),
                totalTx = intent.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L),
                rtt = holdRtt(intent.getIntExtra(PsiphonTunnelService.EXTRA_RTT, 0))
            )
            PsiphonTunnelService.BROADCAST_READY -> Snapshot(
                running = true, paused = false, connecting = false,
                rx = 0L, tx = 0L, totalRx = 0L, totalTx = 0L, rtt = holdRtt(0)
            )
            else -> Snapshot(
                running = intent.getBooleanExtra("running", false),
                paused = intent.getBooleanExtra("paused", false),
                connecting = intent.getBooleanExtra("connecting", false),
                rx = intent.getLongExtra("rx", 0L),
                tx = intent.getLongExtra("tx", 0L),
                totalRx = intent.getLongExtra("totalRx", 0L),
                totalTx = intent.getLongExtra("totalTx", 0L),
                rtt = holdRtt(intent.getIntExtra("rtt", 0))
            )
        }
        write(context, snapshot)
    }

    /**
     * Command sent, owner not up yet: keeps the button from looking dead for
     * the second it takes the service to publish its first state.
     */
    @JvmStatic
    fun markConnecting(context: Context) {
        write(context, Snapshot(false, false, true, 0L, 0L, 0L, 0L, holdRtt(0)))
    }

    /** The session is over: disconnected, stopped, or refused. */
    @JvmStatic
    fun markIdle(context: Context) {
        clearRtt()
        write(context, Snapshot.IDLE)
    }

    /**
     * Byte telemetry of the session: the AAR's when one owns the exit, the
     * engine's otherwise. `[rx, tx, totalRx, totalTx, rtt]`.
     */
    @JvmStatic
    fun stats(psiStats: Intent?): LongArray {
        if (psiStats != null && PsiphonTunnelService.isCurrentBroadcast(psiStats)) {
            return longArrayOf(
                psiStats.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L),
                psiStats.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0L),
                psiStats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L),
                psiStats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L),
                psiStats.getIntExtra(PsiphonTunnelService.EXTRA_RTT, 0).toLong()
            )
        }
        var rx = 0L; var tx = 0L; var totalRx = 0L; var totalTx = 0L; var rtt = 0L
        try {
            val s = FCAEVpnService.nativeGetTrafficStats()
            if (s != null && s.size >= 4) {
                rx = s[0]; tx = s[1]; totalRx = s[2]; totalTx = s[3]
            }
            rtt = NativeEngine.nativeGetRttMs().toLong()
        } catch (_: Throwable) {
        }
        return longArrayOf(rx, tx, totalRx, totalTx, rtt)
    }

    @JvmStatic
    fun snapshot(context: Context): Snapshot {
        latest?.let { return it }
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stamp = prefs.getLong(K_STAMP, 0L)
        // Never written, or written by a boot that has ended since: a tunnel
        // does not survive a reboot, so the record must not claim one did.
        if (stamp == 0L || stamp > SystemClock.elapsedRealtime()) return Snapshot.IDLE
        return Snapshot(
            prefs.getBoolean(K_RUNNING, false),
            prefs.getBoolean(K_PAUSED, false),
            prefs.getBoolean(K_CONNECTING, false),
            prefs.getLong(K_RX, 0L),
            prefs.getLong(K_TX, 0L),
            prefs.getLong(K_TOTAL_RX, 0L),
            prefs.getLong(K_TOTAL_TX, 0L),
            prefs.getInt(K_RTT, 0)
        )
    }

    /**
     * Whether a session is live, asked of the owners themselves rather than of
     * the last state anyone published. Only meaningful in the app process: in a
     * fresh one every owner is null, which is the honest answer there.
     */
    @JvmStatic
    fun isLive(): Boolean {
        if (FCAEVpnService.sessionActive()) return true
        if (ProxyNotification.sessionActive()) return true
        if (PsiphonTunnelService.hasActiveBinding()) return true
        // Reconnecting counts: the engine is recovering on its own, and a second
        // session on top of it must stay off the table.
        return try {
            NativeEngine.nativeGetState() in 1..6
        } catch (_: Throwable) {
            false
        }
    }

    private var stableKey = Long.MIN_VALUE
    private var stable: Snapshot? = null
    private var regressions = 0

    /**
     * Session key, and the snapshot published for it.
     *
     * One session can be measured by two very different counters — the engine's
     * and the AAR's — and either can go quiet for a tick (a rebind, a stale
     * sample, a source switch). Publishing that tick as-is makes the widget drag
     * the totals backwards and then up again, which is the flicker.
     */
    @Synchronized
    private fun stabilize(key: Long, next: Snapshot): Snapshot? {
        if (key != stableKey) {
            stableKey = key
            stable = next
            regressions = 0
            return next
        }
        val prev = stable ?: return next
        val regressed = prev.active && next.active &&
            (next.totalRx < prev.totalRx || next.totalTx < prev.totalTx)
        if (!regressed) {
            regressions = 0
            return next
        }
        // A lone bad tick is held back; a real counter restart (the AAR came
        // back with fresh counters) confirms itself on the next sample and is
        // shown then, honestly, instead of being pinned to the old peak.
        if (++regressions < 2) return null
        return next
    }

    /**
     * Persist `snapshot`. Ending a session is written synchronously: every
     * disconnect path can take this process down milliseconds later, and a
     * queued apply() would go with it, leaving a widget that claims a session
     * for a tunnel that does not exist. Starts stay asynchronous.
     */
    private fun write(context: Context, snapshot: Snapshot) {
        val accepted = stabilize(FCAEVpnService.stateGeneration(), snapshot) ?: return
        latest = accepted
        val flags =
            (if (accepted.running) 1 else 0) or
                (if (accepted.paused) 2 else 0) or
                (if (accepted.connecting) 4 else 0)
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (flags == persistedFlags && prefs.contains(K_STAMP)) return
        persistedFlags = flags
        val editor = prefs.edit()
            .putBoolean(K_RUNNING, accepted.running)
            .putBoolean(K_PAUSED, accepted.paused)
            .putBoolean(K_CONNECTING, accepted.connecting)
            .putLong(K_RX, accepted.rx)
            .putLong(K_TX, accepted.tx)
            .putLong(K_TOTAL_RX, accepted.totalRx)
            .putLong(K_TOTAL_TX, accepted.totalTx)
            .putInt(K_RTT, accepted.rtt)
            .putLong(K_STAMP, SystemClock.elapsedRealtime())
        if (accepted.active) editor.apply() else editor.commit()
    }
}
