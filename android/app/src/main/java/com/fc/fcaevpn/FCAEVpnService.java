package com.fc.fcaevpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public class FCAEVpnService extends VpnService {
    private static final String TAG = "FCAE_VPN";

    public static final String ACTION_STOP      = "com.fc.fcaevpn.STOP";
    public static final String ACTION_DISCONNECT = "com.fc.fcaevpn.DISCONNECT";
    public static final String ACTION_START     = "com.fc.fcaevpn.START";

    public static final String BROADCAST_VPN_DISCONNECTED = "com.fc.fcaevpn.VPN_DISCONNECTED";
    public static final String BROADCAST_VPN_STATE_CHANGED = "com.fc.fcaevpn.VPN_STATE_CHANGED";

    private volatile ParcelFileDescriptor vpnInterface;
    private volatile Thread vpnThread;
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false;
    private volatile boolean shuttingDown = false;

    private Intent lastStartIntent;
    private VpnNotification notification;
    private Handler handler;

    private long cachedTotalRx = 0;
    private long cachedTotalTx = 0;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            updateNotification();
            if (running) {
                handler.postDelayed(this, 5000);
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
        if (running) return;
        vpnPaused = false;
        shuttingDown = false;

        // Signal any previous engine to stop (non-blocking).  aether_start()
        // has its own RUNNING-wait loop, so we do NOT block here with
        // stopNativeFree() which would add 3-5s of cold-start latency on
        // Android.  nativeStop() just sets SHUTDOWN + closes TUN fds in <1ms.
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
        final boolean iron    = intent.getBooleanExtra("ironclad", false);
        final boolean lan     = intent.getBooleanExtra("lanSharing", false);
        final int hi          = intent.getIntExtra("healthInterval", 20);
        final int hf          = intent.getIntExtra("healthMaxFails", 2);
        final int ht          = intent.getIntExtra("healthTimeout", 5);
        final int lv          = intent.getIntExtra("liveValidate", 20);
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
                    sniVal, iron, hi, hf, ht, lv
                );
                if (!ok) {
                    Log.e(TAG, "nativeStart failed");
                    handler.post(() -> fullShutdown());
                    return;
                }

                running = true;
                Log.i(TAG, "VPN engine started");
                cachedTotalRx = 0;
                cachedTotalTx = 0;
                updateNotification();
                handler.post(statsRunnable);
                notifyUi();

                while (running) {
                    try { Thread.sleep(1000); } catch (InterruptedException e) { break; }
                }
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
                handler.post(() -> fullShutdown());
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    /**
     * Call nativeStop synchronously. aether_stop() is non-blocking (sets
     * shutdown flag + closes dup'd fds + updates telemetry), so it returns
     * in under 300 ms.  The engine thread may still be alive (dropping the
     * tokio runtime) — use stopNativeFree() if you need a full drain.
     */
    private void stopNativeSync() {
        Thread t = new Thread(() -> {
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
        }, "FCAE-NativeStop-Sync");
        t.start();
        try { t.join(1500); } catch (InterruptedException ignored) {}
        if (t.isAlive()) {
            Log.w(TAG, "nativeStop timed out — letting it die with process");
        }
    }

    /**
     * Call nativeFree synchronously — blocks until the engine thread fully
     * exits (drops the tokio runtime, joins the watch thread).
     * Use this when you MUST guarantee the engine is done with the TUN fd
     * before closing it (e.g. fullShutdown, pauseVpn).
     */
    private void stopNativeFree() {
        Thread t = new Thread(() -> {
            try { NativeEngine.nativeFree(); } catch (Exception ignored) {}
        }, "FCAE-NativeFree-Sync");
        t.start();
        try { t.join(5000); } catch (InterruptedException ignored) {}
        if (t.isAlive()) {
            Log.w(TAG, "nativeFree timed out — letting it die with process");
        }
    }

    private void fullShutdown() {
        // Prevent re-entrant calls from vpnThread error handler, onDestroy, etc.
        if (shuttingDown) return;
        shuttingDown = true;

        running = false;
        vpnPaused = false;

        Log.i(TAG, "fullShutdown: starting");
        handler.removeCallbacks(statsRunnable);

        // Stop the foreground notification and dismiss it IMMEDIATELY —
        // not inside the cleanup thread which may never execute if the
        // system kills the process during nativeFree().
        notification.dismiss();
        stopForeground(STOP_FOREGROUND_REMOVE);

        // Notify UI IMMEDIATELY so the activity shows "DISCONNECTED"
        // instead of staying stuck on "DISCONNECTING..." for seconds.
        notifyUi();

        // Save refs for background cleanup — null them out now so other
        // code paths see the service as stopped.
        final Thread t = vpnThread;
        vpnThread = null;
        final ParcelFileDescriptor pfdToClose = vpnInterface;
        vpnInterface = null;

        // Run heavy cleanup on a background thread so we never block the
        // main thread for >100ms (Android ANR threshold).  nativeFree()
        // alone can take several seconds (joins engine thread, drops
        // tokio runtime).
        Thread cleanupThread = new Thread(() -> {
            stopNativeFree();

            if (t != null) {
                t.interrupt();
                try { t.join(1000); } catch (InterruptedException ignored) {}
            }

            if (pfdToClose != null) {
                try {
                    pfdToClose.close();
                    Log.i(TAG, "VPN fd closed");
                } catch (Exception e) {
                    Log.e(TAG, "Error closing fd: " + e.getMessage());
                }
            }

            handler.post(() -> {
                stopSelf();
                Log.i(TAG, "service stopped");
            });
        }, "FCAE-Cleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    /**
     * Pause VPN — stops the engine but keeps the service alive so the
     * user can tap Start in the notification to resume.
     */
    private void pauseVpn() {
        if (shuttingDown) return;

        running = false;
        vpnPaused = true;

        // Notify UI immediately.
        notifyUi();

        final Thread t = vpnThread;
        vpnThread = null;
        final ParcelFileDescriptor pfdToClose = vpnInterface;
        vpnInterface = null;

        // Run heavy cleanup on a background thread (same as fullShutdown).
        Thread cleanupThread = new Thread(() -> {
            stopNativeFree();

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
        sendBroadcast(intent);
    }

    private void updateNotification() {
        if (vpnPaused) {
            notification.show("FCAE VPN \u2014 Stopped (tap Start to resume)", false);
        } else if (running) {
            long rx = 0, tx = 0;
            try {
                long[] stats = nativeGetTrafficStats();
                if (stats != null && stats.length >= 2) {
                    rx = stats[0];
                    tx = stats[1];
                }
            } catch (Exception ignored) {}
            cachedTotalRx += rx;
            cachedTotalTx += tx;
            String text = String.format(
                "\u2193 %s  %s  |  \u2191 %s  %s",
                VpnNotification.fmtBytes(cachedTotalRx), VpnNotification.fmtRate(rx),
                VpnNotification.fmtBytes(cachedTotalTx), VpnNotification.fmtRate(tx));
            notification.show(text, true);
        } else {
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
}
