package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The one status feed for surfaces without an Activity.
 *
 * [FCAEVpnService] (TUN) and [ProxyNotification] (proxy) publish the session's
 * phase and telemetry on every tick of the loops they already run; the widget
 * renders [reconciled]. State is process-local by design, so a reboot or cold
 * process starts idle and only a live owner can restore an active frame. The
 * phase is the owner's to decide — it is the only
 * party that knows the state machine — and is never re-derived by a consumer.
 */
object SessionState {

    /** How long an unconfirmed frame is trusted while a command is carried out. */
    private const val GRACE_MS = 2500L
    private const val COMMAND_TIMEOUT_MS = 4000L
    private val reconcileHandler = Handler(Looper.getMainLooper())
    private val reconcileScheduled = AtomicBoolean(false)

    /** The engine measures the session itself. */
    const val SOURCE_ENGINE = 0

        /**
         * The exit owns the session's counters: a chained session has two meters
         * (engine and AAR) reporting different numbers for one traffic, so which
         * one is the session's is decided once and held, never swapped per tick.
         */
    const val SOURCE_AAR = 1

    /**
     * What the user sees. One vocabulary for the whole app: the widget renders
     * these words, and the values the Activity's receiver needs (running /
     * paused / connecting) are derived from them — never the other way round.
     */
    enum class Phase { DISCONNECTED, CONNECTING, RECONNECTING, CONNECTED, PAUSED }

    /** A command in flight, from the app, the notification or the widget. */
    enum class Command { NONE, CONNECT, DISCONNECT, PAUSE, RESUME }

    data class Snapshot(
        val phase: Phase,
        /** 1 = system VPN (TUN), 0 = local proxy. */
        val mode: Int,
        val rx: Long,
        val tx: Long,
        val totalRx: Long,
        val totalTx: Long,
        val rtt: Int
    ) {
        /** A session is up, dialing, recovering, or held open by a Stop. */
        val active: Boolean
            get() = phase == Phase.CONNECTING || phase == Phase.RECONNECTING ||
                phase == Phase.CONNECTED || phase == Phase.PAUSED

        /** The tunnel is up (a Stop holds it open; only the data plane goes). */
        val up: Boolean get() = phase == Phase.CONNECTED || phase == Phase.PAUSED

        val paused: Boolean get() = phase == Phase.PAUSED

        /** MainActivity's own vocabulary, for the shared broadcast. */
        val running: Boolean get() = up || phase == Phase.RECONNECTING
        val connecting: Boolean get() = phase == Phase.CONNECTING

        companion object {
            @JvmField val IDLE = Snapshot(Phase.DISCONNECTED, 1, 0L, 0L, 0L, 0L, 0)
        }
    }

    /**
     * Last snapshot reported in this process, and when. Publishers and the
     * widget share the app process, so this is the live value: rates move every
     * second while the disk copy deliberately stands still.
     */
    @Volatile
    private var latest: Snapshot? = null
    private var latestAt = 0L

    private var rttHeld = 0
    /** Session the held RTT and the frame on screen belong to. */
    private var sessionGeneration = Long.MIN_VALUE
    /** Which meter this session's counters come from; AAR outranks the engine. */
    private var statsSource = SOURCE_ENGINE
    /** Last telemetry of the session's own source: rx, tx, totalRx, totalTx. */
    private var heldStats = longArrayOf(0L, 0L, 0L, 0L)
    private var pending = Command.NONE
    private var pendingAt = 0L

    private var stablePhase = -1
    private var stable: Snapshot? = null
    private var regressions = 0

        /**
         * The RTT of the session, fixed by its first successful probe — one value,
         * one session, one place, so no two surfaces can show different latencies
         * for one tunnel. A new session starts the measurement over.
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

        /**
         * A command was just sent: until the state it asks for arrives, frames
         * that contradict it are held back, so a disconnect cannot be undone on
         * screen by the owner's ticks during teardown. Ends at the first
         * confirming frame, or at the timeout.
         */
    @JvmStatic
    @Synchronized
    fun command(command: Command) {
        pending = command
        pendingAt = SystemClock.elapsedRealtime()
    }

    /**
     * Report a measured phase: persist it and broadcast it. Owners call this on
     * every tick they already run.
     */
    @JvmStatic
    fun publish(
        context: Context,
        phase: Phase,
        mode: Int,
        rx: Long,
        tx: Long,
        totalRx: Long,
        totalTx: Long,
        rttSample: Int,
        source: Int
    ) {
        // A new session owns its own readings: the epoch the owners bump when a
        // session starts or ends is what tells them apart, so a stale RTT (or a
        // stale total, if a backend keeps cumulative counters) can never be
        // presented as this session's. A Stop is not a new session — it pauses
        // one — so it does not start the measurements over.
        val generation = FCAEVpnService.sessionEpoch()
        if (generation != sessionGeneration) {
            sessionGeneration = generation
            statsSource = SOURCE_ENGINE
            heldStats = longArrayOf(0L, 0L, 0L, 0L)
            clearRtt()
        }
        // The session's meter, not the frame's: the AAR claims a session's
        // counters the first time it reports, and keeps them from then on — a
        // frame from the other meter still carries the phase, but its numbers
        // are not this session's and are held back. Replacing a
        // closer-to-the-exit measurement with a wider one is a change of
        // measurement, not of session, and it is also where a held RTT from the
        // lesser meter has to go.
        val upgraded = source == SOURCE_AAR && statsSource != SOURCE_AAR
        if (upgraded) {
            statsSource = SOURCE_AAR
            clearRtt()
        }
        val mine = source == statsSource
        if (mine) heldStats = longArrayOf(rx, tx, totalRx, totalTx)
        val snapshot = Snapshot(
            phase, mode, heldStats[0], heldStats[1], heldStats[2], heldStats[3],
            holdRtt(if (mine) rttSample else 0)
        )
        write(context, snapshot, measured = true)
        val intent = Intent(FCAEVpnService.BROADCAST_VPN_STATE_CHANGED)
            .setPackage(context.packageName)
            .putExtra("generation", FCAEVpnService.stateGeneration())
            .putExtra("epoch", FCAEVpnService.sessionEpoch())
            .putExtra("phase", snapshot.phase.ordinal)
            .putExtra("mode", snapshot.mode)
            .putExtra("running", snapshot.running)
            .putExtra("paused", snapshot.paused)
            .putExtra("connecting", snapshot.connecting)
            .putExtra("rx", snapshot.rx)
            .putExtra("tx", snapshot.tx)
            .putExtra("totalRx", snapshot.totalRx)
            .putExtra("totalTx", snapshot.totalTx)
            .putExtra("rtt", snapshot.rtt)
        try {
            context.sendBroadcast(intent)
        } catch (_: Throwable) {
        }
    }

    /**
     * Command sent, owner not up yet: keeps the button from looking dead for the
     * second it takes the service to publish its first phase.
     */
    @JvmStatic
    fun markConnecting(context: Context, mode: Int) {
        write(context, Snapshot(Phase.CONNECTING, mode, 0L, 0L, 0L, 0L, holdRtt(0)))
    }

        /**
         * Pause tapped: flip the phase now, hold the reading exactly as it was.
         * Stop only halts the TUN data plane, so status, rates and totals must not
         * move, and the button must not look dead for a beat.
         */
    @JvmStatic
    fun markPause(context: Context, paused: Boolean) {
        val current = latest?.takeIf { it.active } ?: return
        write(
            context,
            current.copy(phase = if (paused) Phase.PAUSED else Phase.CONNECTED)
        )
    }

    /** The session is over: disconnected, stopped, or refused. */
    @JvmStatic
    fun markIdle(context: Context) {
        clearRtt()
        write(context, Snapshot.IDLE)
    }

        /**
         * Telemetry of the session: the AAR's when it owns the exit, the engine's
         * otherwise. `[rx, tx, totalRx, totalTx, rtt]`. `ownAar` is the owner's
         * session-long answer, never a freshness test — a sample that stopped
         * being the newest one is still this session's reading.
         */
    @JvmStatic
    fun stats(psiStats: Intent?, ownAar: Boolean): LongArray {
        if (ownAar) {
            // The exit's numbers, or none at all: borrowing the engine's until
            // the first exit sample lands puts the carrier's rates, totals and
            // RTT on screen and then swaps them — the flinch this rule exists
            // to prevent. No reading yet means no reading, not another meter's.
            if (psiStats == null) return LongArray(5)
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
    fun snapshot(context: Context): Snapshot = latest ?: Snapshot.IDLE

        /**
         * [snapshot] minus any session that no longer exists: a stored frame can
         * outlive its session (killed process, force-stop, an OEM task manager),
         * and the widget must not keep offering DISCONNECT for a tunnel that is
         * gone. The owners are the authority, so ask them.
         */
    @JvmStatic
    fun reconciled(context: Context): Snapshot {
        val current = snapshot(context)
        if (!current.active) return current
        if (isLive()) return current
        val last = latest
        if (last != null && SystemClock.elapsedRealtime() - latestAt < GRACE_MS) {
            scheduleReconciliation(context)
            return current
        }
        command(Command.NONE)
        markIdle(context)
        return Snapshot.IDLE
    }

    private fun scheduleReconciliation(context: Context) {
        if (!reconcileScheduled.compareAndSet(false, true)) return
        val app = context.applicationContext
        val delay = (GRACE_MS - (SystemClock.elapsedRealtime() - latestAt)).coerceAtLeast(1L)
        reconcileHandler.postDelayed({
            reconcileScheduled.set(false)
            reconciled(app)
        }, delay)
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
        // The AAR binding is deliberately not asked here: a binding is an
        // attachment, and the region refresh holds one — a session always has
        // one of the two owners above, and those are the parties that know.
        // The engine's own state, read through the same test the service uses:
        // ERROR (5) is a session that ended and left its last state behind, and
        // counting it kept a dead session — and the process behind it — alive.
        // An engine lives in this process, so a process that never loaded it
        // has no session: asking would load the Go and Rust libraries and run
        // fcae_init on the caller's thread — the widget's main thread, on a
        // cold tap, before its button could even repaint.
        if (!NativeEngine.Loaded.value) return false
        return try {
            FCAEVpnService.engineSessionLive(NativeEngine.nativeGetState())
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Whether a command the user just gave is still being carried out.
     *
     * Timed out on the same rule as the frame latch: a command nothing answers
     * must stop holding anything back, or a refused connect would keep the
     * process alive for as long as it likes.
     */
    @JvmStatic
    @Synchronized
    fun commandInFlight(): Boolean {
        if (pending == Command.NONE) return false
        if (SystemClock.elapsedRealtime() - pendingAt > COMMAND_TIMEOUT_MS) {
            pending = Command.NONE
            return false
        }
        return true
    }

    /** Whether `snapshot` may be shown while a command is in flight. */
    @Synchronized
    private fun accepts(snapshot: Snapshot): Boolean {
        if (pending == Command.NONE) return true
        if (SystemClock.elapsedRealtime() - pendingAt > COMMAND_TIMEOUT_MS) {
            pending = Command.NONE
            return true
        }
        return when (pending) {
            Command.DISCONNECT -> !snapshot.active
            Command.CONNECT -> snapshot.active
            Command.PAUSE -> snapshot.up
            // A resume is not a connect: the owner publishes CONNECTING while it
            // re-raises the interface, and that frame would blank the controls
            // mid-flip.
            Command.RESUME -> snapshot.phase != Phase.CONNECTING
            else -> true
        }
    }

    /** Release the latch once a frame matches what was asked for. */
    @Synchronized
    private fun confirmed(snapshot: Snapshot) {
        val done = when (pending) {
            Command.DISCONNECT -> !snapshot.active
            Command.CONNECT -> snapshot.active
            Command.PAUSE -> snapshot.paused
            Command.RESUME -> snapshot.up && !snapshot.paused
            else -> false
        }
        if (done) pending = Command.NONE
    }

    /**
     * Session key, and the snapshot published for it.
     *
     * One session can be measured by two very different counters — the engine's
     * and the AAR's — and either can go quiet for a tick (a rebind, a stale
     * sample, a source switch). Publishing that tick as-is makes the widget drag
     * the totals backwards and then up again, which is the flicker.
     */
    @Synchronized
    private fun stabilize(phase: Phase, next: Snapshot): Snapshot? {
        if (phase != stable?.phase) {
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
     * Publish an in-process snapshot. Control surfaces are projections of the
     * running owners, never durable state: after process death or reboot they
     * start idle until a foreground owner reports again.
     */
    private fun write(context: Context, snapshot: Snapshot, measured: Boolean = false) {
        if (!accepts(snapshot)) return
        // Only an owner's own frame can confirm a command: the optimistic
        // writes made here (a command the user just gave) would otherwise
        // release the latch that is hiding the old state, and the owner's
        // still-dying frames would flip the surfaces back.
        if (measured) confirmed(snapshot)
        val accepted = stabilize(snapshot.phase, snapshot) ?: return
        latest = accepted
        latestAt = SystemClock.elapsedRealtime()
        // The frame lands on the widget here, in the process the widget's
        // provider runs in. It is deliberately not a broadcast: a broadcast
        // reaches a manifest-registered receiver in a process that is not
        // running by STARTING that process, so the app's own state messages
        // were resurrecting the very process a teardown had just ended.
        try {
            VpnWidgetProvider.refresh(context)
        } catch (_: Throwable) {
        }
        try {
            VpnTileService.publish(context)
        } catch (_: Throwable) {
        }
    }
}
