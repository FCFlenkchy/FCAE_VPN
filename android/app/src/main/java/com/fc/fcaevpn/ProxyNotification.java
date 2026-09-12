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
    private static final String CHANNEL_ID = "fcaevpn_proxy";
    public static final int NOTIFICATION_ID = 2;

    public static final String ACTION_START = "com.fc.fcaevpn.PROXY_START";
    public static final String ACTION_STOP  = "com.fc.fcaevpn.PROXY_STOP";

    private Handler handler;
    private PendingIntent piMain;
    private Notification.Action disconnectAction;
    private String lastNotifText = null;
    private volatile boolean nativeFreed = false;
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
            updateNotification();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "ProxyNotification created");
        handler = new Handler(Looper.getMainLooper());

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            android.app.NotificationChannel ch = new android.app.NotificationChannel(
                CHANNEL_ID, "FCAE Proxy",
                android.app.NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("FCAE VPN proxy mode status");
            ch.setShowBadge(false);
            android.app.NotificationManager mgr = getSystemService(android.app.NotificationManager.class);
            if (mgr != null) mgr.createNotificationChannel(ch);
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
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProxy();
            return START_NOT_STICKY;
        }

        // A fresh proxy session: bump the shared generation counter so this
        // session's later disconnect broadcast is never mistaken for a stale
        // one from a previous connect/disconnect cycle.
        FCAEVpnService.sGeneration.incrementAndGet();
        stopping = false;
        nativeFreed = false;
        showNotification("FCAE VPN — Proxy connecting...", false);
        handler.removeCallbacks(statsRunnable);
        handler.post(statsRunnable);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

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

    private void stopProxy() {
        stopping = true;
        handler.removeCallbacks(statsRunnable);
        // Proxy mode has no VpnService, so nothing else broadcasts state. The
        // UI listens for these actions to clear its CONNECTED indicator; omit
        // this and the app keeps showing a live session after the engine died.
        broadcastStopped();
        try {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } catch (Exception e) {
            Log.w(TAG, "stopForeground failed: " + e.getMessage());
        }
        stopSelf();
        Log.i(TAG, "ProxyNotification stopped");

        freeNativeOnce();

        if (!MainActivity.activityAlive) {
            android.os.Process.killProcess(android.os.Process.myPid());
        }
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

    private void freeNativeOnce() {
        if (nativeFreed) return;
        nativeFreed = true;
        new Thread(() -> {
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            try { Thread.sleep(300); } catch (InterruptedException ignored) {}
            try { NativeEngine.nativeFree(); } catch (Exception ignored) {}
        }, "FCAE-ProxyStop").start();
    }

    @Override
    public void onDestroy() {
        handler.removeCallbacks(statsRunnable);
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

        if (!MainActivity.activityAlive) {
            android.os.Process.killProcess(android.os.Process.myPid());
        }

        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        Log.i(TAG, "App removed from recent tasks — proxy continues in background");
    }
}
