package com.fc.fcaevpn;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Intent;
import android.app.Service;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

public class ProxyNotification extends Service {
    private static final String TAG = "FCAE_PROXY";
    private static final String CHANNEL_ID = "fcaevpn_proxy_hi";
    public static final int NOTIFICATION_ID = 2;
    /**
     * Long enough for the disconnect broadcast to reach the UI, short enough
     * that the process is gone before the user can tell it lingered. The kill
     * does not wait for the engine teardown on purpose: the process ending IS
     * the teardown, and the kernel closes what is left.
     */
    private static final long PROCESS_KILL_DELAY_MS = 250L;

    public static final String ACTION_START = "com.fc.fcaevpn.PROXY_START";
    public static final String ACTION_DISCONNECT = "com.fc.fcaevpn.PROXY_DISCONNECT";
    /**
     * Same teardown as {@link #ACTION_DISCONNECT}, but the process goes too.
     * Only the notification uses it: MainActivity sends plain
     * ACTION_DISCONNECT from its own Disconnect button, where the user is
     * still in the app and expects to reconnect.
     */
    public static final String ACTION_DISCONNECT_KILL = "com.fc.fcaevpn.PROXY_DISCONNECT_KILL";

    private static final int BUTTONS_CONNECTING = 0;
    private static final int BUTTONS_RUNNING = 1;

    private Handler handler;
    private PendingIntent piMain;
    private Notification.Action disconnectAction;
    private volatile boolean nativeFreed = false;
    public static final String ACTION_PSIPHON = "com.fc.fcaevpn.PROXY_PSIPHON";
    public static final String ACTION_PSIPHON_REGIONS = "com.fc.fcaevpn.PROXY_PSIPHON_REGIONS";
    private static ProxyNotification instance;
    // Main-process snapshot kept by the foreground notification owner. The
    // Activity's dynamic receiver is not sticky and may miss broadcasts while
    // it is being recreated, so resume can rehydrate from this copy without
    // asking the native engine for Psiphon state.
    private static volatile Intent latestPsiphonStats;
    private static final String PSI_SNAPSHOT_PREFS = "psiphon_ui_snapshot";
    private boolean externalPsiphon;

    /**
     * A session was asked of this owner. The service is also started for
     * one-shot commands — the Psiphon region refresh — and an instance that was
     * never asked for a session must not answer "a session is up" to the
     * widget, to the app's own exit check or to any other consumer. That false
     * yes is what kept answering for a process with nothing behind it.
     */
    private volatile boolean sessionRequested;

    /**
     * The AAR measures this session's traffic. Its counters and its tunnel RTT
     * are then the session's only real numbers — a chained proxy session is
     * measured by the AAR outside and by the engine inside, and they are two
     * different readings of the same traffic.
     */
    private boolean psiTelemetry;

        /**
         * The AAR reported a live tunnel for this session. Set by its own signals
         * (READY, a stats sample), cleared by them (STOPPED, FAILED) — never by
         * one missing tick, which is what a rebind looks like and is exactly what
         * made the status flip CONNECTED -> CONNECTING -> CONNECTED.
         */
    private volatile boolean psiLive;
    private boolean handingOff;
    private long ownerGeneration;
    private Intent lastPsiphonStats;

    public static void cachePsiphonStats(Intent stats) {
        latestPsiphonStats = stats == null ? null : new Intent(stats);
    }

    /**
     * Keep the latest service snapshot outside the Activity as well as in
     * memory. The foreground owner continues receiving PSI_STATS while the
     * Activity is gone; SharedPreferences covers a notification-owner or
     * Activity recreation before the next non-sticky broadcast arrives.
     */
    public static void cachePsiphonStats(android.content.Context context, Intent stats) {
        cachePsiphonStats(stats);
        android.content.SharedPreferences.Editor e = context.getApplicationContext()
                .getSharedPreferences(PSI_SNAPSHOT_PREFS, android.content.Context.MODE_PRIVATE).edit();
        if (stats == null) {
            e.clear().apply();
            return;
        }
        e.putLong("psiSession", stats.getLongExtra("psiSession", -1L));
        e.putLong("requestId", stats.getLongExtra("requestId", 0L));
        e.putString(PsiphonTunnelService.EXTRA_LAN,
                stats.getStringExtra(PsiphonTunnelService.EXTRA_LAN));
        e.putInt(PsiphonTunnelService.EXTRA_SOCKS,
                stats.getIntExtra(PsiphonTunnelService.EXTRA_SOCKS, 0));
        e.putInt(PsiphonTunnelService.EXTRA_HTTP,
                stats.getIntExtra(PsiphonTunnelService.EXTRA_HTTP, 0));
        e.putInt(PsiphonTunnelService.EXTRA_RTT,
                stats.getIntExtra(PsiphonTunnelService.EXTRA_RTT, 0));
        e.putLong(PsiphonTunnelService.EXTRA_UP_BPS,
                stats.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0L));
        e.putLong(PsiphonTunnelService.EXTRA_DOWN_BPS,
                stats.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L));
        e.putLong(PsiphonTunnelService.EXTRA_TOTAL_UP,
                stats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L));
        e.putLong(PsiphonTunnelService.EXTRA_TOTAL_DOWN,
                stats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L));
        e.apply();
    }

    public static Intent latestPsiphonStats() {
        Intent stats = latestPsiphonStats;
        return stats == null ? null : new Intent(stats);
    }

    /** Return the in-memory snapshot, or the last owner snapshot after a
     * process/Activity recreation. */
    public static Intent latestPsiphonStats(android.content.Context context) {
        Intent stats = latestPsiphonStats();
        if (stats != null) return stats;
        android.content.SharedPreferences p = context.getApplicationContext()
                .getSharedPreferences(PSI_SNAPSHOT_PREFS, android.content.Context.MODE_PRIVATE);
        if (!p.contains("psiSession")) return null;
        Intent restored = new Intent(PsiphonTunnelService.BROADCAST_STATS);
        restored.setPackage(context.getPackageName());
        restored.putExtra("psiSession", p.getLong("psiSession", -1L));
        restored.putExtra("requestId", p.getLong("requestId", 0L));
        restored.putExtra(PsiphonTunnelService.EXTRA_LAN,
                p.getString(PsiphonTunnelService.EXTRA_LAN, ""));
        restored.putExtra(PsiphonTunnelService.EXTRA_SOCKS,
                p.getInt(PsiphonTunnelService.EXTRA_SOCKS, 0));
        restored.putExtra(PsiphonTunnelService.EXTRA_HTTP,
                p.getInt(PsiphonTunnelService.EXTRA_HTTP, 0));
        restored.putExtra(PsiphonTunnelService.EXTRA_RTT,
                p.getInt(PsiphonTunnelService.EXTRA_RTT, 0));
        restored.putExtra(PsiphonTunnelService.EXTRA_UP_BPS,
                p.getLong(PsiphonTunnelService.EXTRA_UP_BPS, 0L));
        restored.putExtra(PsiphonTunnelService.EXTRA_DOWN_BPS,
                p.getLong(PsiphonTunnelService.EXTRA_DOWN_BPS, 0L));
        restored.putExtra(PsiphonTunnelService.EXTRA_TOTAL_UP,
                p.getLong(PsiphonTunnelService.EXTRA_TOTAL_UP, 0L));
        restored.putExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN,
                p.getLong(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0L));
        latestPsiphonStats = new Intent(restored);
        return restored;
    }

    /** Remove only the obsolete notification owned by older Psiphon builds. */
    public static void clearLegacyPsiphonNotification(android.content.Context context) {
        android.app.NotificationManager manager = context.getSystemService(android.app.NotificationManager.class);
        if (manager == null) return;
        manager.cancel(3); // Old PsiphonTunnelService.NOTIF_ID; app owners use 1/2.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            manager.deleteNotificationChannel("fcaevpn_psiphon");
        }
    }

    public static void handoffToVpn() {
        ProxyNotification current = instance;
        if (current == null || !current.externalPsiphon) return;
        current.handingOff = true;
        current.handler.removeCallbacks(current.statsRunnable);
        current.stopForeground(STOP_FOREGROUND_REMOVE);
        current.stopSelf();
    }
    public static String psiphonTrafficText(Intent stats) {
        return String.format("↓ %s  %s  |  ↑ %s  %s",
                VpnNotification.fmtBytes(stats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_DOWN, 0)),
                VpnNotification.fmtRate(stats.getLongExtra(PsiphonTunnelService.EXTRA_DOWN_BPS, 0)),
                VpnNotification.fmtBytes(stats.getLongExtra(PsiphonTunnelService.EXTRA_TOTAL_UP, 0)),
                VpnNotification.fmtRate(stats.getLongExtra(PsiphonTunnelService.EXTRA_UP_BPS, 0)));
    }

    private final android.content.BroadcastReceiver psiphonReceiver = new android.content.BroadcastReceiver() {
        @Override public void onReceive(android.content.Context context, Intent intent) {
            if (stopping || handingOff || !PsiphonTunnelService.isCurrentBroadcast(intent)) return;
            if (PsiphonTunnelService.BROADCAST_STATS.equals(intent.getAction())) {
                lastPsiphonStats = new Intent(intent);
                cachePsiphonStats(context, lastPsiphonStats);
                psiLive = true;
                updateNotification();
                return;
            }
            if (!psiTelemetry) return;
            // The AAR's own word on its tunnel: up, or down. These are signals
            // about the session, not samples of it, so they are the only thing
            // allowed to move the phase.
            final boolean ready = PsiphonTunnelService.BROADCAST_READY.equals(intent.getAction());
            final boolean stopped = PsiphonTunnelService.BROADCAST_STOPPED.equals(intent.getAction())
                    || PsiphonTunnelService.BROADCAST_FAILED.equals(intent.getAction());
            if (!ready && !stopped) return;
            psiLive = ready;
            if (!externalPsiphon) return;
            if (stopped) {
                stopProxy();
            } else if (!intent.getBooleanExtra("regionsOnly", false)) {
                showNotification(VpnNotification.zeroTrafficText(), BUTTONS_RUNNING);
            }
        }
    };
    /** Set once teardown starts, so the watchdog cannot re-enter stopProxy(). */
    private volatile boolean stopping = false;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
                        // Engine-death watchdog: the engine can die after nativeStart()
                        // returned, and then nothing is listening on the SOCKS port while
                        // this notification still claims "connected". Terminal states are
                        // 0 and 5; 1..4 and 6 are transient. Pure Psiphon proxy mode is
                        // owned by the AAR, so an idle native state there means nothing.
            if (!stopping && !externalPsiphon) {
                int engineState = 5; // pessimistic if the JNI call throws
                try {
                    engineState = NativeEngine.nativeGetState();
                } catch (Exception ignored) {}
                if (engineState == 0 || engineState == 5) {
                    Log.w(TAG, "Engine reached terminal state " + engineState
                            + " \u2014 stopping proxy service");
                    stopProxy();
                    return;
                }
            }
            if (!stopping && !externalPsiphon) PsiphonTunnelService.pollChainedRequest(ProxyNotification.this);
            updateNotification();
            publishState();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        clearLegacyPsiphonNotification(this);
        Log.i(TAG, "ProxyNotification created");
        instance = this;
        ownerGeneration = FCAEVpnService.sGeneration.get();
        android.content.IntentFilter filter = new android.content.IntentFilter();
        filter.addAction(PsiphonTunnelService.BROADCAST_READY);
        filter.addAction(PsiphonTunnelService.BROADCAST_STATS);
        filter.addAction(PsiphonTunnelService.BROADCAST_FAILED);
        filter.addAction(PsiphonTunnelService.BROADCAST_STOPPED);
        androidx.core.content.ContextCompat.registerReceiver(this, psiphonReceiver, filter,
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED);
        handler = new Handler(Looper.getMainLooper());

        ensureChannel(this);

        Intent mainIntent = new Intent(this, MainActivity.class);
        piMain = PendingIntent.getActivity(this, 20, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        disconnectAction = buildAction(this, "Disconnect", ACTION_DISCONNECT_KILL, 21);
    }

    /**
     * Idempotent channel creation, callable from any process of the package:
     * the :psiphon foreground service must be able to raise the channel
     * before posting this class's notification from its own process.
     */
    public static void ensureChannel(android.content.Context context) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            android.app.NotificationChannel ch = new android.app.NotificationChannel(
                CHANNEL_ID, "FCAE Proxy",
                android.app.NotificationManager.IMPORTANCE_HIGH);
            ch.setSound(null, null);
            ch.enableVibration(false);
            ch.setDescription("FCAE VPN proxy mode status");
            ch.setShowBadge(false);
            android.app.NotificationManager mgr = context.getSystemService(android.app.NotificationManager.class);
            if (mgr != null) {
                mgr.createNotificationChannel(ch);
                try { mgr.deleteNotificationChannel("fcaevpn_proxy"); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * The exact connecting-state notification of an external Psiphon session,
     * buildable from any process of the package: the :psiphon foreground
     * service posts it under this same id while the tunnel dials, so the
     * shared entry never differs from what this owner shows. Mirrors
     * showNotification(VpnNotification.zeroTrafficText(), BUTTONS_CONNECTING).
     */
    @SuppressWarnings("deprecation")
    public static Notification buildConnecting(android.content.Context context) {
        PendingIntent piMain = PendingIntent.getActivity(context, 20,
            new Intent(context, MainActivity.class),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder nb = (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O
            ? new Notification.Builder(context, CHANNEL_ID)
            : new Notification.Builder(context))
            .setContentTitle("FCAE VPN (Proxy)")
            .setContentText(VpnNotification.zeroTrafficText())
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(piMain)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setStyle(new Notification.BigTextStyle().bigText(VpnNotification.zeroTrafficText()));
        nb.addAction(buildAction(context, "Disconnect", ACTION_DISCONNECT_KILL, 21));
        return nb.build();
    }

    private static Notification.Action buildAction(android.content.Context context,
            String label, String action, int requestCode) {
        Intent intent = new Intent(context, ProxyNotification.class);
        intent.setAction(action);
        PendingIntent pi;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            pi = PendingIntent.getForegroundService(context, requestCode,
                intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        } else {
            pi = PendingIntent.getService(context, requestCode,
                intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        }
        return new Notification.Action.Builder(null, label, pi).build();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_PSIPHON_REGIONS.equals(intent.getAction())) {
            PsiphonTunnelService.startBound(this,
                    new Intent(this, PsiphonTunnelService.class)
                            .setAction(PsiphonTunnelService.ACTION_REGIONS));
            // A region refresh is a one-shot command, and the binding above
            // outlives it (the AAR answers later). It is not a session, so this
            // instance must not hold the foreground state — or the zeroed
            // notification that goes with it — and the post below is only what
            // startForegroundService obliges this start to answer.
            if (!sessionRequested) {
                showNotification(VpnNotification.zeroTrafficText(), BUTTONS_CONNECTING);
                stopForeground(STOP_FOREGROUND_REMOVE);
            }
            return START_STICKY;
        }
        if (intent != null && ACTION_PSIPHON.equals(intent.getAction())) {
            ownerGeneration = FCAEVpnService.sGeneration.incrementAndGet();
            sessionRequested = true;
            externalPsiphon = true;
            psiTelemetry = true;
            psiLive = false;
            showNotification(VpnNotification.zeroTrafficText(), BUTTONS_CONNECTING);
            Intent psi = new Intent(this, PsiphonTunnelService.class).setAction(PsiphonTunnelService.ACTION_START);
            if (intent.getExtras() != null) psi.putExtras(intent.getExtras());
            psi.putExtra(PsiphonTunnelService.EXTRA_OWNER, PsiphonTunnelService.OWNER_PROXY);
            PsiphonTunnelService.startBound(this, psi);
            return START_STICKY;
        }
        if (intent != null && ACTION_DISCONNECT_KILL.equals(intent.getAction())) {
            // Notification Disconnect has no UI left to reconnect from, so the
            // process goes with the session — same contract as TUN mode.
            SessionState.command(SessionState.Command.DISCONNECT);
            terminalTeardown("Notification Disconnect");
            return START_NOT_STICKY;
        }
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            SessionState.command(SessionState.Command.DISCONNECT);
            showNotification(VpnNotification.zeroTrafficText(), BUTTONS_CONNECTING);
            stopProxy();
            return START_NOT_STICKY;
        }
        if (intent == null) {
            // A task removal or service recreation is not a user disconnect.
            // Do not call stopProxy(): that detaches Psiphon and causes the
            // next Activity launch to start a second tunnel.
            return START_STICKY;
        }

        // Anything but ACTION_START reaching this point is the task-removal
        // redelivery (the launcher base intent replayed to every started
        // service on swipe) or another stray delivery — not a session
        // request. Starting a "fresh" session for it would bump the
        // generation and reset a live session's notification to connecting.
        if (!ACTION_START.equals(intent.getAction())) {
            return START_STICKY;
        }

        // A fresh proxy session: bump the shared generation counter so this
        // session's later disconnect broadcast is never mistaken for a stale
        // one from a previous connect/disconnect cycle.
        ownerGeneration = FCAEVpnService.sGeneration.incrementAndGet();
        sessionRequested = true;
        stopping = false;
        nativeFreed = false;
        // Which hop measures this session, told by whoever asked for it: the
        // Activity passes it for an egress session (the engine carries it, the
        // exit measures it), and a headless start carries it in its own
        // description. An exit-measured session has no engine numbers to show.
        psiTelemetry = intent.getBooleanExtra("psiphonThroughTunnel", false);

        // A description on the intent means a surface without an Activity is
        // asking for this session (the widget). MainActivity's own ACTION_START
        // carries none: it starts the engine itself, from its live views.
        final boolean described = intent.hasExtra("protocol");
        if (described && engineAlive()) {
            // Already up (second tap, stale widget, redelivery). The TUN owner
            // ignores a start on a live tunnel for the same reason: rebuilding
            // the session under it would drop everything in flight.
            Log.i(TAG, "Start ignored: session already up");
            showNotification(VpnNotification.zeroTrafficText(), BUTTONS_RUNNING);
            return START_STICKY;
        }

        showNotification(VpnNotification.zeroTrafficText(), BUTTONS_CONNECTING);
        handler.removeCallbacks(statsRunnable);
        handler.postDelayed(statsRunnable, 2000L);

        if (described && intent.getIntExtra("backend", 0) == 1) {
            // Protocol=Psiphon in proxy mode IS the AAR tunnel: no engine
            // session exists, and this owner carries its notification.
            externalPsiphon = true;
            psiTelemetry = true;
            psiLive = false;
            Intent psi = new Intent(this, PsiphonTunnelService.class)
                    .setAction(PsiphonTunnelService.ACTION_START)
                    .putExtras(intent)
                    .putExtra(PsiphonTunnelService.EXTRA_OWNER, PsiphonTunnelService.OWNER_PROXY);
            PsiphonTunnelService.startBound(this, psi);
            return START_STICKY;
        }
        externalPsiphon = false;
        psiTelemetry = psiTelemetry ||
                (described && intent.getBooleanExtra("psiphonThroughTunnel", false));
        psiLive = false;
        if (described) startEngineFromSession(intent);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // startForeground(int, Notification) is deprecated on API 34; the
    // manifest's specialUse covers it.
    @SuppressWarnings("deprecation")
    private void showNotification(String text, int buttons) {
        Notification.Builder nb = (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O
            ? new Notification.Builder(this, CHANNEL_ID)
            : new Notification.Builder(this))
            .setContentTitle("FCAE VPN (Proxy)")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(piMain)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setStyle(new Notification.BigTextStyle().bigText(text));

        // Disconnect only, in every state: Stop/Start are TUN-mode
        // controls (the data plane can be halted and resumed there); a
        // proxy session has nothing to pause, so the button must never
        // appear here.
        switch (buttons) {
            case BUTTONS_CONNECTING:
            case BUTTONS_RUNNING:
            default:
                nb.addAction(disconnectAction);
                break;
        }

        try {
            startForeground(NOTIFICATION_ID, nb.build());
        } catch (Exception e) {
            Log.e(TAG, "startForeground failed: " + e.getMessage());
        }
    }

    /**
     * Start the engine for a session described by an intent, from this owner
     * rather than from an Activity (the widget's connect). Runs on the same
     * lifecycle executor as the UI's connect worker, and is generation-checked
     * around the stop/start pair so a disconnect that lands mid-way wins.
     */
    private void startEngineFromSession(Intent session) {
        final Intent described = new Intent(session);
        final long generation = ownerGeneration;
        NativeEngine.lifecycleExecutor.execute(() -> {
            if (generation != FCAEVpnService.sGeneration.get() || stopping) return;
            try { NativeEngine.nativeStop(); } catch (Throwable ignored) {}
            if (generation != FCAEVpnService.sGeneration.get() || stopping) return;
            boolean started = false;
            try {
                started = NativeEngine.startSession(this, described);
            } catch (Throwable t) {
                Log.e(TAG, "headless start failed: " + t);
            }
            if (!started) {
                Log.w(TAG, "headless start refused — ending the session");
                handler.post(ProxyNotification.this::stopProxy);
            }
        });
    }

    /** True while a session of this process is up or still dialing. */
    private boolean engineAlive() {
        try {
            int state = NativeEngine.nativeGetState();
            return state != 0 && state != 5;
        } catch (Throwable t) {
            return false;
        }
    }

        /**
         * Publish this owner's state for Activity-less consumers. The engine state
         * decides, not "the owner is alive": a session still dialing must not
         * render as connected.
         */
    private void publishState() {
        if (stopping) return;
        // A pure Psiphon exit lives entirely in the AAR, so this owner is the
        // only publisher its session has; a chained one is measured by the AAR
        // as well, and its numbers are one session's worth of telemetry. Both
        // are decided per session, not per tick.
        final long[] stats = SessionState.stats(psiTelemetry ? lastPsiphonStats : null, psiTelemetry);
        SessionState.publish(this, phase(), 0,
                stats[0], stats[1], stats[2], stats[3], (int) stats[4],
                psiTelemetry ? SessionState.SOURCE_AAR : SessionState.SOURCE_ENGINE);
    }

    /**
     * The phase of this session, decided here: an exit-measured session is the
     * exit's to describe (the engine is idle on that path, or is only the
     * carrier), and this owner is the party that hears from it.
     */
    private SessionState.Phase phase() {
        if (psiTelemetry) {
            // An exit-measured session is described by the exit: it is the only
            // party that knows whether the final hop is up. The carrier's state
            // says nothing about it — it reads CONNECTED as soon as the first
            // hop is, while the exit may still be dialing.
            if (psiLive) return SessionState.Phase.CONNECTED;
            int carrier = 0;
            try { carrier = NativeEngine.nativeGetState(); } catch (Exception ignored) {}
            return carrier == 6 ? SessionState.Phase.RECONNECTING : SessionState.Phase.CONNECTING;
        }
        int state = 5;
        try { state = NativeEngine.nativeGetState(); } catch (Exception ignored) {}
        if (state == 6) return SessionState.Phase.RECONNECTING;
        // 0 = not reported yet: the session exists (this owner is running) and is
        // not passing traffic — dialing, not disconnected.
        if (state <= 3) return SessionState.Phase.CONNECTING;
        if (state == 5) return SessionState.Phase.DISCONNECTED;
        return SessionState.Phase.CONNECTED;
    }

    // Byte-flow text only — no state words — so Psiphon exits and plain
    // Aether protocols look identical. Re-posts every call on purpose: the
    // :psiphon foreground service shares this notification id while its
    // tunnel (re)dials, and the next tick must always restore the owner's
    // content.
    private void updateNotification() {
        // This session's numbers: while the exit owns the session its last
        // sample is the reading, rebind or not, and before the first one there
        // is nothing to show but zeros (see SessionState.stats).
        if (psiTelemetry) {
            showNotification(lastPsiphonStats != null
                    ? psiphonTrafficText(lastPsiphonStats)
                    : VpnNotification.zeroTrafficText(), BUTTONS_RUNNING);
            return;
        }
        long rx = 0, tx = 0, totalRx = 0, totalTx = 0;
        try {
            long[] stats = FCAEVpnService.nativeGetTrafficStats();
            if (stats != null && stats.length >= 4) {
                rx = stats[0];
                tx = stats[1];
                totalRx = stats[2];
                totalTx = stats[3];
            }
        } catch (Exception ignored) {}

        showNotification(VpnNotification.trafficText(rx, tx, totalRx, totalTx), BUTTONS_RUNNING);
    }


    /**
     * @return true when this call performed the teardown, false when it was
     *         already stopping or another owner holds the session. Callers
     *         that must not leave the process behind use it to decide whether
     *         to end the process themselves.
     */
    private synchronized boolean stopProxy() {
        if (stopping || ownerGeneration != FCAEVpnService.sGeneration.get()) return false;
        lastPsiphonStats = null;
        stopping = true;
        sessionRequested = false;
        psiTelemetry = false;
        psiLive = false;
        handler.removeCallbacks(statsRunnable);
        PsiphonTunnelService.stopBound(this);
        // Proxy mode has no VpnService, so nothing else broadcasts state. The
        // UI listens for these actions to clear its CONNECTED indicator; omit
        // this and the app keeps showing a live session after the engine died.
        broadcastStopped();
        // Committed synchronously, and pushed to the widget with it: this owner
        // can end this process moments later (notification Disconnect), and a
        // frame still in flight would die with it.
        SessionState.markIdle(this);
        // Abort the engine immediately, then reap on the cleanup thread.
        if (!externalPsiphon) {
            try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
        }
        try {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } catch (Exception e) {
            Log.w(TAG, "stopForeground failed: " + e.getMessage());
        }
        stopSelf();
        Log.i(TAG, "ProxyNotification stopped");

        freeNativeOnce();

        // Same rule as the TUN owner (see FCAEVpnService.fullShutdown). Queued,
        // not fired here: the stop broadcast above is already on the main looper
        // and has to land before the process goes.
        if (!FCAEApplication.uiOnScreen() && handler != null) {
            handler.postDelayed(this::killOwnProcess, PROCESS_KILL_DELAY_MS);
        }

        return true;
    }

        /**
         * A disconnect from outside the UI (notification button, widget): end
         * the session, and this process only if the app is not on screen. The
         * {@code :psiphon} process holds the exit, has no UI, and always goes.
         */
    private void terminalTeardown(String reason) {
        Log.i(TAG, reason + " — ending the session");
        boolean tornDown = false;
        try {
            tornDown = stopProxy();
        } catch (Throwable t) {
            Log.w(TAG, "teardown failed: " + t);
        }
        if (!tornDown) {
            // Already stopping (another teardown got here first), so stopProxy
            // made no decision of its own about the process — this command still
            // owes the session one.
            try {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } catch (Throwable ignored) {
            }
            stopSelf();
            if (!FCAEApplication.uiOnScreen()) {
                if (handler != null) {
                    handler.postDelayed(this::killOwnProcess, PROCESS_KILL_DELAY_MS);
                } else {
                    killOwnProcess();
                }
            }
        }
        try {
            PsiphonTunnelService.killProcessOnExit(this);
        } catch (Throwable ignored) {
        }
    }

    private void killOwnProcess() {
        FCAEVpnService.killProcessQuietly();
    }

    public static boolean isAlive() {
        return instance != null;
    }

    /** Whether this owner has a session up, dialing or held open. */
    public static boolean sessionActive() {
        ProxyNotification current = instance;
        return current != null && !current.stopping && current.sessionRequested;
    }

    /** Mirrors FCAEVpnService's disconnect broadcast so MainActivity resets. */
    private void broadcastStopped() {
        try {
            Intent i = new Intent(FCAEVpnService.BROADCAST_VPN_DISCONNECTED);
            i.putExtra("running", false);
            i.putExtra("paused", false);
            i.putExtra("generation", FCAEVpnService.sGeneration.get());
            i.setPackage(getPackageName());
            sendBroadcast(i);
        } catch (Exception e) {
            Log.w(TAG, "state broadcast failed: " + e.getMessage());
        }
    }

    public static void notifyCleanupComplete(android.content.Context context) {
        Intent done = new Intent(FCAEVpnService.BROADCAST_VPN_DISCONNECTED).setPackage(context.getPackageName());
        done.putExtra("cleanupComplete", true);
        done.putExtra("generation", FCAEVpnService.sGeneration.get());
        context.sendBroadcast(done);
    }

    private synchronized void freeNativeOnce() {
        if (nativeFreed) return;
        nativeFreed = true;
        final long generation = ownerGeneration;
        if (generation != FCAEVpnService.sGeneration.get()) return;
        if (externalPsiphon) { notifyCleanupComplete(this); return; }
        NativeEngine.lifecycleExecutor.execute(() -> {
            if (generation != FCAEVpnService.sGeneration.get()) return;
            try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            // Keep the process-global FFI and Android hooks alive for reconnect.
            if (generation == FCAEVpnService.sGeneration.get()) notifyCleanupComplete(this);
        });
    }

    @Override
    public void onDestroy() {
        handler.removeCallbacks(statsRunnable);
        unregisterReceiver(psiphonReceiver);
        if (instance == this) instance = null;
        if (handingOff || ownerGeneration != FCAEVpnService.sGeneration.get()) { super.onDestroy(); return; }
        Log.i(TAG, "ProxyNotification onDestroy");
        // Android may recreate the notification owner while Psiphon is live.
        // Only an explicit stop may detach the Psiphon service or reset stats.
        if (stopping) {
            PsiphonTunnelService.stopBound(this);
            broadcastStopped();
            freeNativeOnce();
        }


        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        // Removing the task is not a disconnect request. Keep proxy mode alive;
        // the notification and explicit Disconnect own teardown.
        Log.i(TAG, "App removed from recent tasks — keeping proxy session alive");
        super.onTaskRemoved(rootIntent);
    }
}
