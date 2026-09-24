package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.os.SystemClock

/**
 * The one status feed for surfaces without an Activity.
 *
 * [FCAEVpnService] (TUN) and [ProxyNotification] (proxy) publish the session's
 * *phase* here on every tick of the loops they already run, plus the byte
 * telemetry that goes with it; the home screen widget renders [reconciled].
 * The broadcast is the app's own state channel (same action, same extras), so
 * the Activity and the widget read one story.
 *
 * The phase is decided by the owner — which is the only party that knows the
 * state machine — and never re-derived by a consumer from a handful of
 * booleans. That is deliberate: re-deriving is how the widget ended up showing
 * CONNECTED for a dead tunnel, with no RECONNECTING and no CONNECTING at all.
 */
object SessionState {

    private const val PREFS = "fcae_session_state"
    private const val K_PHASE = "phase"
    private const val K_MODE = "mode"
    private const val K_RX = "rx"
    private const val K_TX = "tx"
    private const val K_TOTAL_RX = "totalRx"
    private const val K_TOTAL_TX = "totalTx"
    private const val K_RTT = "rtt"
    /** Write time, elapsedRealtime: a lower clock means the device rebooted. */
    private const val K_STAMP = "stamp"

    /** How long an unconfirmed frame is trusted while a command is carried out. */
    private const val GRACE_MS = 2500L
    private const val COMMAND_TIMEOUT_MS = 4000L

    /** The engine measures the session itself. */
    const val SOURCE_ENGINE = 0

    /**
     * The Psiphon AAR owns the session's exit, and therefore its counters.
     *
     * A chained session has two meters — the engine's tunnel and the AAR's
     * tunnel — and they are different numbers for the same traffic. Which one
     * is the session's is a property of the session, so it is decided once and
     * then held: switching between them per tick is what made the totals and
     * the RTT flip between two readings while a Psiphon session ran.
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

    /** Flags of the last persisted write; statistics alone never trigger one. */
    private var persistedPhase = -1

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
     * The RTT of the session, fixed by its first successful probe.
     *
     * One value, one session, one place: every surface reads this, so the app,
     * the notification and the widget cannot show two different latencies for
     * one tunnel. Latency does not change while a tunnel is up, so re-probing
     * it would only make the number under the user's eyes jump; a new session
     * starts the measurement over.
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
     * A command was just sent to an owner: from here until the state it asks
     * for arrives, frames that contradict it are held back.
     *
     * Without this the surfaces flinch: a Disconnect takes a moment to tear the
     * session down and the owner's ticks keep publishing the live phase in that
     * window, so the widget flipped back to CONNECTED right after the user had
     * disconnected. The latch ends at the first confirming frame, or after a
     * timeout, so a command that is never carried out cannot wedge the display.
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
     * The pause button was tapped: flip the phase now, keep everything else.
     *
     * Stop only halts the TUN data plane, so the reading is held exactly as it
     * was — the status, the rates and the totals do not move. Waiting for the
     * owner to confirm instead made the button look dead for a beat, and
     * rendering the owner's zeroed rates made Stop look like a start-stop
     * flinch.
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
     * Byte telemetry of the session: the AAR's when it owns the exit, the
     * engine's otherwise. `[rx, tx, totalRx, totalTx, rtt]`.
     *
     * `ownAar` is the owner's session-long answer, never a freshness test: a
     * sample that has stopped being the newest one (a rebind between
     * broadcasts, a paused session) is still this session's reading, and
     * falling back to the other meter for those ticks is what made the numbers
     * flip.
     */
    @JvmStatic
    fun stats(psiStats: Intent?, ownAar: Boolean): LongArray {
        if (ownAar) {
            // The exit's numbers, or none at all. Borrowing the engine's in the
            // window before the AAR's first sample is what put the carrier's
            // rates, totals and RTT on screen first and then swapped them for
            // the exit's — the very flinch the single-source rule exists to
            // prevent. No reading yet means no reading, not another meter's.
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
    fun snapshot(context: Context): Snapshot {
        latest?.let { return it }
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stamp = prefs.getLong(K_STAMP, 0L)
        // Never written, or written by a boot that has ended since: a tunnel
        // does not survive a reboot, so the record must not claim one did.
        if (stamp == 0L || stamp > SystemClock.elapsedRealtime()) return Snapshot.IDLE
        val phase = Phase.entries.getOrElse(prefs.getInt(K_PHASE, 0)) { Phase.DISCONNECTED }
        return Snapshot(
            phase,
            prefs.getInt(K_MODE, 1),
            prefs.getLong(K_RX, 0L),
            prefs.getLong(K_TX, 0L),
            prefs.getLong(K_TOTAL_RX, 0L),
            prefs.getLong(K_TOTAL_TX, 0L),
            prefs.getInt(K_RTT, 0)
        )
    }

    /**
     * The snapshot a consumer may act on: [snapshot] minus any session that no
     * longer exists.
     *
     * A stored frame can outlive the session it describes — the process is
     * killed, the app is force-stopped, an OEM task manager takes the tunnel —
     * and then nothing will ever publish again, so the widget would keep
     * offering DISCONNECT for a tunnel that is gone. The owners are the only
     * authority on whether a session exists, so ask them: if none is live and
     * no fresh frame is arriving, the session is over and the record says so.
     */
    @JvmStatic
    fun reconciled(context: Context): Snapshot {
        val current = snapshot(context)
        if (!current.active) return current
        if (isLive()) return current
        val last = latest
        if (last != null && SystemClock.elapsedRealtime() - latestAt < GRACE_MS) return current
        command(Command.NONE)
        markIdle(context)
        return Snapshot.IDLE
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
     * Persist `snapshot`. Ending a session is written synchronously: every
     * disconnect path can take this process down milliseconds later, and a
     * queued apply() would go with it, leaving a widget that claims a session
     * for a tunnel that does not exist. Starts stay asynchronous.
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
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (accepted.phase.ordinal == persistedPhase && prefs.contains(K_STAMP)) return
        persistedPhase = accepted.phase.ordinal
        val editor = prefs.edit()
            .putInt(K_PHASE, accepted.phase.ordinal)
            .putInt(K_MODE, accepted.mode)
            .putLong(K_RX, accepted.rx)
            .putLong(K_TX, accepted.tx)
            .putLong(K_TOTAL_RX, accepted.totalRx)
            .putLong(K_TOTAL_TX, accepted.totalTx)
            .putInt(K_RTT, accepted.rtt)
            .putLong(K_STAMP, SystemClock.elapsedRealtime())
        if (accepted.active) editor.apply() else editor.commit()
    }
}
