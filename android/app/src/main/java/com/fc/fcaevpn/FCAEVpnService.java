package com.fc.fcaevpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class FCAEVpnService extends VpnService {
    private static final String TAG = "FCAE_VPN";

    public static final String ACTION_STOP      = "com.fc.fcaevpn.STOP";
    public static final String ACTION_DISCONNECT = "com.fc.fcaevpn.DISCONNECT";
    public static final String ACTION_START     = "com.fc.fcaevpn.START";

    public static final String BROADCAST_VPN_DISCONNECTED = "com.fc.fcaevpn.VPN_DISCONNECTED";
    public static final String BROADCAST_VPN_STATE_CHANGED = "com.fc.fcaevpn.VPN_STATE_CHANGED";

    // Monotonically increasing generation counter.  Every startVpn() and
    // fullShutdown() increments it.  The broadcast carries the generation
    // so the Activity can ignore stale broadcasts from a previous cycle.
    private static final AtomicLong sGeneration = new AtomicLong(0);

    // Cleanup generation — incremented by startVpn() so stale cleanup
    // threads from a previous shutdown skip freeNativeOnce() (which
    // would otherwise join the NEW engine thread and deadlock it).
    private volatile long cleanupGeneration = 0;

    private volatile ParcelFileDescriptor vpnInterface;
    private volatile Thread vpnThread;
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false;
    private volatile boolean shuttingDown = false;
    private volatile boolean nativeFreed = false;
    private CountDownLatch shutdownLatch;

    private Intent lastStartIntent;
    private VpnNotification notification;
    private Handler handler;

    // Skip redundant manager.notify() calls (Binder call into system_server,
    // can wake SystemUI) when the displayed text hasn't actually changed —
    // meaningful during idle-but-connected periods with no traffic.
    private String lastNotifText = null;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            updateNotification();
            if (running) {
                handler.postDelayed(this, 1000);
            }
        }
    };

    private static native void nativeSetTunFd(int fd);
    public static native long[] nativeGetTrafficStats();

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Service created");
        handler = new Handler(Looper.getMainLooper());
        notification = new VpnNotification(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_STOP:
                    pauseVpn();
                    return START_STICKY;
                case ACTION_DISCONNECT:
                    // Guard: if the service was never started with a VPN config
                    // (i.e. proxy mode scenario where disconnectAll() still
                    // sends ACTION_DISCONNECT), just stop self gracefully.
                    if (vpnInterface == null && vpnThread == null && !running) {
                        handler.removeCallbacks(statsRunnable);
                        notification.dismiss();
                        stopForeground(STOP_FOREGROUND_REMOVE);
                        stopSelf();
                        return START_NOT_STICKY;
                    }
                    fullShutdown();
                    return START_NOT_STICKY;
                case ACTION_START:
                    if (!intent.hasExtra("protocol") && lastStartIntent != null) {
                        startVpn(lastStartIntent);
                    } else if (intent.hasExtra("protocol")) {
                        lastStartIntent = new Intent(intent);
                        startVpn(intent);
                    } else {
                        // Notification Start with no config — just show notification
                        notification.show("FCAE VPN — Ready (tap Connect in app)", false);
                        startForeground(VpnNotification.NOTIFICATION_ID,
                            notification.build("FCAE VPN — Ready (tap Connect in app)", false));
                    }
                    return START_STICKY;
            }
        }

        notification.show("FCAE VPN \u2014 Ready (tap Connect in app)", false);
        startForeground(VpnNotification.NOTIFICATION_ID,
            notification.build("FCAE VPN \u2014 Ready (tap Connect in app)", false));
        return START_STICKY;
    }

    private void startVpn(Intent intent) {
        sGeneration.incrementAndGet();
        cleanupGeneration++;
        vpnPaused = false;
        shuttingDown = false;
        nativeFreed = false;

        // Force-stop any previous engine — running may still be true if
        // the old cleanup thread hasn't finished yet.  nativeStop() is
        // non-blocking (sets SHUTDOWN flag), and aether_start() has its
        // own RUNNING-wait loop, so the new engine won't start until the
        // old one fully exits.
        running = false;
        try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

        notification.show("FCAE VPN \u2014 Connecting...", false);
        startForeground(VpnNotification.NOTIFICATION_ID,
            notification.build("FCAE VPN \u2014 Connecting...", false));

        final int protocol    = intent.getIntExtra("protocol", 0);
        final int mode        = intent.getIntExtra("mode", 1);
        final int scanMode    = intent.getIntExtra("scanMode", 0);
        final int ipVersion   = intent.getIntExtra("ipVersion", 4);
        final boolean quick   = intent.getBooleanExtra("quickReconnect", false);
        final boolean h2      = intent.getBooleanExtra("h2Enabled", true);
        final boolean ech     = intent.getBooleanExtra("echEnabled", true);
        final boolean lan     = intent.getBooleanExtra("lanSharing", false);
        final int socks       = intent.getIntExtra("socksPort", 1819);
        final int http        = intent.getIntExtra("httpPort", 1820);
        final String noize    = intent.getStringExtra("noizeProfile");
        final String peer     = intent.getStringExtra("forcePeer");
        final String cfg      = intent.getStringExtra("configPath");
        final String sni      = intent.getStringExtra("sni");
        final String cfgPath  = (cfg == null || cfg.isEmpty()) ? "aether.toml" : cfg;
        final String sniVal   = (sni == null) ? "" : sni;
        final String noizeVal = (noize == null || noize.isEmpty()) ? "balanced" : noize;
        final String peerVal  = (peer == null) ? "" : peer;
        final int sysProfile  = intent.getIntExtra("sysProfile", 0);
        final String teamName  = intent.getStringExtra("teamName");
        final String accessTok = intent.getStringExtra("accessToken");
        final String accessEm  = intent.getStringExtra("accessEmail");
        final String routesF   = intent.getStringExtra("routesFile");
        final String routesI   = intent.getStringExtra("routesInline");
        final String teamVal   = (teamName == null) ? "" : teamName;
        final String tokenVal  = (accessTok == null) ? "" : accessTok;
        final String emailVal  = (accessEm == null) ? "" : accessEm;
        final String routesVal = (routesF == null) ? "" : routesF;
        final String routesIVal = (routesI == null) ? "" : routesI;

        vpnThread = new Thread(() -> {
            try {
                Builder builder = new Builder();
                builder.setSession("FCAE VPN");
                builder.setMtu(1420);
                builder.addAddress("10.0.0.2", 32);
                builder.addRoute("0.0.0.0", 0);
                builder.addRoute("::", 0);
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (Exception e) {
                    Log.w(TAG, "Could not exclude own package: " + e.getMessage());
                }
                builder.addDnsServer("1.1.1.1");
                builder.addDnsServer("1.0.0.1");

                vpnInterface = builder.establish();
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN");
                    handler.post(() -> fullShutdown());
                    return;
                }

                int fd = vpnInterface.getFd();
                nativeSetTunFd(fd);
                Log.i(TAG, "VPN established, fd=" + fd);

                NativeEngine.nativeInit();

                boolean ok = NativeEngine.nativeStart(
                    protocol, mode, lan, scanMode,
                    ipVersion, quick, noizeVal,
                    false, 16, 32, 2, 10, socks, http,
                    peerVal, cfgPath, h2, ech,
                    sniVal, sysProfile,
                    teamVal, tokenVal, emailVal, routesVal, routesIVal
                );
                if (!ok) {
                    Log.e(TAG, "nativeStart failed");
                    handler.post(() -> fullShutdown());
                    return;
                }

                running = true;
                Log.i(TAG, "VPN engine started");
                lastNotifText = null;
                updateNotification();
                handler.post(statsRunnable);
                notifyUi();

                // Block until shutdown — no periodic wakeup, no CPU cost.
                shutdownLatch = new CountDownLatch(1);
                try { shutdownLatch.await(); } catch (InterruptedException ignored) {}
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
                handler.post(() -> fullShutdown());
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    /**
     * Free native engine once — guarded by {@code nativeFreed} so that
     * pauseVpn() + fullShutdown() never double-free on the Rust STOP_GUARD.
     */
    private void freeNativeOnce() {
        if (nativeFreed) return;
        nativeFreed = true;
        Thread t = new Thread(() -> {
            try { NativeEngine.nativeFree(); } catch (Exception ignored) {}
        }, "FCAE-NativeFree-Sync");
        t.setDaemon(true);
        t.start();
        try { t.join(5000); } catch (InterruptedException ignored) {}
        if (t.isAlive()) {
            Log.w(TAG, "nativeFree timed out — letting it die with process");
        }
    }

    /**
     * Full shutdown — kills everything: engine, notification, service.
     * Safe to call multiple times (idempotent) and safe to call after
     * pauseVpn().
     */
    private void fullShutdown() {
    sGeneration.incrementAndGet();
    running = false;
    vpnPaused = false;

    // Unblock the VPN worker thread immediately.
    if (shutdownLatch != null) {
        shutdownLatch.countDown();
        shutdownLatch = null;
    }

    if (!shuttingDown) {
        shuttingDown = true;
        Log.i(TAG, "fullShutdown: starting");
    }

    handler.removeCallbacks(statsRunnable);
    notification.dismiss();
    stopForeground(STOP_FOREGROUND_REMOVE);
    notifyUi();
    stopSelf();

    // Save refs — null them out so other code paths see stopped state.
    final Thread t = vpnThread;
    vpnThread = null;
    final ParcelFileDescriptor pfdToClose = vpnInterface;
    vpnInterface = null;
    lastStartIntent = null;

    // ── CRITICAL: Close the VPN fd IMMEDIATELY on the main thread ──────
    // Android tears down the VPN interface the instant the PFD is closed.
    // The dup'd fds in Rust are closed separately by aether_stop().
    if (pfdToClose != null) {
        try {
            pfdToClose.close();
            Log.i(TAG, "VPN fd closed (immediate)");
        } catch (Exception e) {
            Log.e(TAG, "Error closing fd: " + e.getMessage());
        }
    }

    // Signal Rust to stop — non-blocking, idempotent.
    try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

    // Heavy cleanup in background. nativeFree() joins the Rust engine
    // thread, but we no longer block the VPN teardown on it.
    final long myGen = cleanupGeneration;
    Thread cleanupThread = new Thread(() -> {
        if (myGen != cleanupGeneration) {
            Log.i(TAG, "cleanup: stale generation, skipping nativeFree");
            return;
        }

        freeNativeOnce();

        if (t != null) {
            t.interrupt();
            try { t.join(1000); } catch (InterruptedException ignored) {}
        }

        if (!MainActivity.activityAlive) {
            Log.i(TAG, "Activity not alive after shutdown — killing process");
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    }, "FCAE-Cleanup");
    cleanupThread.setDaemon(true);
    cleanupThread.start();
}

    /**
     * Pause VPN — stops the engine but keeps the service alive so the
     * user can tap Start in the notification to resume.
     */
    private void pauseVpn() {
        sGeneration.incrementAndGet();
        running = false;
        vpnPaused = true;

        // Unblock the VPN worker thread immediately.
        if (shutdownLatch != null) {
            shutdownLatch.countDown();
            shutdownLatch = null;
        }

        Log.i(TAG, "pauseVpn: starting");
        notifyUi();

        final Thread t = vpnThread;
        vpnThread = null;
        final ParcelFileDescriptor pfdToClose = vpnInterface;
        vpnInterface = null;

        final long myGen = cleanupGeneration;
        Thread cleanupThread = new Thread(() -> {
            if (myGen != cleanupGeneration) {
                Log.i(TAG, "pause-cleanup: stale generation, skipping nativeFree");
                return;
            }

            freeNativeOnce();

            if (t != null) {
                t.interrupt();
                try { t.join(1000); } catch (InterruptedException ignored) {}
            }

            if (pfdToClose != null) {
                try { pfdToClose.close(); } catch (Exception ignored) {}
            }

            handler.post(() -> {
                handler.removeCallbacks(statsRunnable);
                updateNotification();
                Log.i(TAG, "VPN paused");
            });
        }, "FCAE-PauseCleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    private void notifyUi() {
        Intent intent = new Intent(BROADCAST_VPN_STATE_CHANGED);
        intent.setPackage(getPackageName());
        intent.putExtra("running", running);
        intent.putExtra("paused", vpnPaused);
        intent.putExtra("generation", sGeneration.get());
        sendBroadcast(intent);
    }

    private void updateNotification() {
        if (vpnPaused) {
            lastNotifText = null;
            notification.show("FCAE VPN \u2014 Stopped (tap Start to resume)", false);
        } else if (running) {
            long rx = 0, tx = 0, totalRx = 0, totalTx = 0;
            try {
                long[] stats = nativeGetTrafficStats();
                if (stats != null && stats.length >= 4) {
                    rx = stats[0];
                    tx = stats[1];
                    totalRx = stats[2];
                    totalTx = stats[3];
                }
            } catch (Exception ignored) {}
            String text = String.format(
                "\u2193 %s  %s  |  \u2191 %s  %s",
                VpnNotification.fmtBytes(totalRx), VpnNotification.fmtRate(rx),
                VpnNotification.fmtBytes(totalTx), VpnNotification.fmtRate(tx));
            lastNotifText = text;
            notification.show(text, true);
        } else {
            lastNotifText = null;
            notification.show("FCAE VPN \u2014 Disconnected", false);
        }
    }

    @Override
    public void onDestroy() {
        fullShutdown();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        fullShutdown();
        super.onRevoke();
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (level >= TRIM_MEMORY_RUNNING_LOW) {
            // Help the system reclaim memory by clearing logs.
            try { NativeEngine.nativeClearLogs(); } catch (Exception ignored) {}
            lastNotifText = null;
        }
    }
}
