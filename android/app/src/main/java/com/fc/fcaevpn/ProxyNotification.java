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

    public static final String ACTION_START = "com.fc.fcaevpn.PROXY_START";
    public static final String ACTION_STOP  = "com.fc.fcaevpn.PROXY_STOP";

    private Handler handler;
    private PendingIntent piMain;
    private Notification.Action disconnectAction;
    private String lastNotifText = null;
    private volatile boolean nativeFreed = false;
    public static final String ACTION_PSIPHON = "com.fc.fcaevpn.PROXY_PSIPHON";
    private static ProxyNotification instance;
    private boolean externalPsiphon;
    private boolean handingOff;
    private long ownerGeneration;
    private Intent lastPsiphonStats;
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
                updateNotification();
                return;
            }
            if (!externalPsiphon) return;
            if (PsiphonTunnelService.BROADCAST_READY.equals(intent.getAction())) {
                if (!intent.getBooleanExtra("regionsOnly", false))
                    showNotification("FCAE VPN — Proxy connected", true);
            } else { stopProxy(); }
        }
    };
    /** Set once teardown starts, so the watchdog cannot re-enter stopProxy(). */
    private volatile boolean stopping = false;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            // ── Engine-death watchdog ─────────────────────────
            // nativeStart() returns as soon as the engine thread is launched;
            // the engine can still die LATER on its own (no endpoint found,
            // tunnel failed permanently, connectivity lost). Without this
            // check the proxy notification kept claiming "connected" forever,
            // complete with a Disconnect button, while nothing was listening
            // on the SOCKS port -- and the UI never learned either, because
            // only FCAEVpnService broadcasts state.
            //
            // Terminal states: 0 = DISCONNECTED, 5 = ERROR. Transient states
            // (1 provisioning, 2 scanning/reconnecting, 3 connecting,
            // 4 connected) must NOT tear down.
            if (!stopping) {
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

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            android.app.NotificationChannel ch = new android.app.NotificationChannel(
                CHANNEL_ID, "FCAE Proxy",
                android.app.NotificationManager.IMPORTANCE_HIGH);
            ch.setSound(null, null);
            ch.enableVibration(false);
            ch.setDescription("FCAE VPN proxy mode status");
            ch.setShowBadge(false);
            android.app.NotificationManager mgr = getSystemService(android.app.NotificationManager.class);
            if (mgr != null) {
                mgr.createNotificationChannel(ch);
                try { mgr.deleteNotificationChannel("fcaevpn_proxy"); } catch (Exception ignored) {}
            }
        }

        Intent mainIntent = new Intent(this, MainActivity.class);
        piMain = PendingIntent.getActivity(this, 20, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent disconnectIntent = new Intent(this, ProxyNotification.class);
        disconnectIntent.setAction(ACTION_STOP);
        PendingIntent piDisconnect = PendingIntent.getService(this, 21,
            disconnectIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        disconnectAction = new Notification.Action.Builder(null, "Disconnect", piDisconnect).build();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_PSIPHON.equals(intent.getAction())) {
            ownerGeneration = FCAEVpnService.sGeneration.incrementAndGet();
            externalPsiphon = true;
            showNotification("FCAE VPN — Connecting…", true);
            Intent psi = new Intent(this, PsiphonTunnelService.class).setAction(PsiphonTunnelService.ACTION_START);
            if (intent.getExtras() != null) psi.putExtras(intent.getExtras());
            PsiphonTunnelService.startBound(this, psi);
            return START_NOT_STICKY;
        }
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            // Satisfy a startForegroundService STOP delivery as well.
            showNotification("FCAE VPN — Disconnecting…", false);
            stopProxy();
            return START_NOT_STICKY;
        }

        if (intent == null) {
            // Sticky re-delivery (system restarts the service, typically
            // after a process death). The engine runs IN-PROCESS, so nothing
            // survives a process death: tearing down here instead of
            // re-announcing "Proxy connecting..." for an engine that is
            // gone (and re-bumping the shared generation counter for it).
            stopProxy();
            return START_NOT_STICKY;
        }

        // A fresh proxy session: bump the shared generation counter so this
        // session's later disconnect broadcast is never mistaken for a stale
        // one from a previous connect/disconnect cycle.
        ownerGeneration = FCAEVpnService.sGeneration.incrementAndGet();
        stopping = false;
        nativeFreed = false;
        showNotification("FCAE VPN — Proxy connecting...", false);
        handler.removeCallbacks(statsRunnable);
        handler.postDelayed(statsRunnable, 2000L);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // startForeground(int, Notification) is deprecated on API 34; this service
    // never declares a foregroundServiceType, so the two-arg form is the
    // deliberate choice on every API level (same as FCAEVpnService).
    @SuppressWarnings("deprecation")
    private void showNotification(String text, boolean connected) {
        Notification.Builder nb = new Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("FCAE VPN (Proxy)")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(piMain)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setStyle(new Notification.BigTextStyle().bigText(text));

        if (connected) {
            nb.addAction(disconnectAction);
        }

        try {
            startForeground(NOTIFICATION_ID, nb.build());
        } catch (Exception e) {
            Log.e(TAG, "startForeground failed: " + e.getMessage());
        }
    }

    private void updateNotification() {
        if (PsiphonTunnelService.hasActiveBinding() && lastPsiphonStats != null
                && PsiphonTunnelService.isCurrentBroadcast(lastPsiphonStats)) {
            String text = psiphonTrafficText(lastPsiphonStats);
            if (!text.equals(lastNotifText)) {
                lastNotifText = text;
                showNotification(text, true);
            }
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

        String text = String.format(
            "↓ %s  %s  |  ↑ %s  %s",
            VpnNotification.fmtBytes(totalRx), VpnNotification.fmtRate(rx),
            VpnNotification.fmtBytes(totalTx), VpnNotification.fmtRate(tx));

        if (!text.equals(lastNotifText)) {
            lastNotifText = text;
            showNotification(text, true);
        }
    }

    private synchronized void stopProxy() {
        if (stopping || ownerGeneration != FCAEVpnService.sGeneration.get()) return;
        stopping = true;
        handler.removeCallbacks(statsRunnable);
        PsiphonTunnelService.stopBound(this);
        // Proxy mode has no VpnService, so nothing else broadcasts state. The
        // UI listens for these actions to clear its CONNECTED indicator; omit
        // this and the app keeps showing a live session after the engine died.
        broadcastStopped();
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
        PsiphonTunnelService.stopBound(this);
        Log.i(TAG, "ProxyNotification onDestroy");

        // The service can also be destroyed without stopProxy() -- e.g. the
        // system reclaims it. Tell the UI in that case too, otherwise it keeps
        // showing CONNECTED for an engine that is being torn down right here.
        if (!stopping) {
            stopping = true;
            broadcastStopped();
        }

        // Only cleanup native here if stopProxy() didn't already do it.
        freeNativeOnce();


        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        Log.i(TAG, "App removed from recent tasks — proxy continues in background");
    }
}
