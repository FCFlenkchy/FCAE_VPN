package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

/**
 * FCAE VPN — Android VpnService with live notification stats.
 */
public class FCAEVpnService extends VpnService {
    private static final String TAG = "FCAE_VPN";
    private static final String CHANNEL_ID = "fcaevpn_service";
    private static final int NOTIFICATION_ID = 1;

    private static final int STOP_ACTION_CODE   = 10;
    private static final int DISCONNECT_ACTION_CODE = 11;

    public static final String ACTION_STOP      = "com.fc.fcaevpn.STOP";
    public static final String ACTION_DISCONNECT = "com.fc.fcaevpn.DISCONNECT";
    public static final String ACTION_START     = "com.fc.fcaevpn.START";

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false;

    // Last config used to start the VPN (for notification Start button)
    private Intent lastStartIntent;

    private Handler statsHandler;
    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            updateNotificationStats();
            if (running || vpnPaused) {
                statsHandler.postDelayed(this, 1000);
            }
        }
    };

    private static native void nativeSetTunFd(int fd);
    public static native long[] nativeGetTrafficStats();

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "FCAEVpnService created");
        statsHandler = new Handler(Looper.getMainLooper());
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_STOP:
                    stopVpnKeepNotification();
                    return START_STICKY;
                case ACTION_DISCONNECT:
                    stopVpnAndNotification();
                    return START_NOT_STICKY;
                case ACTION_START:
                    // If intent has no config extras, reuse last config
                    if (!intent.hasExtra("protocol") && lastStartIntent != null) {
                        startVpn(lastStartIntent);
                    } else {
                        lastStartIntent = new Intent(intent);
                        startVpn(intent);
                    }
                    return START_STICKY;
            }
        }

        // Fallback: show notification even if no action
        startForeground(NOTIFICATION_ID, buildNotification(
            "FCAE VPN — Ready (tap Connect in app)",
            false
        ));
        return START_STICKY;
    }

    private void startVpn(Intent intent) {
        if (running) return;
        vpnPaused = false;

        // Show foreground notification IMMEDIATELY (required within 5s of startForegroundService)
        startForeground(NOTIFICATION_ID, buildNotification("FCAE VPN — Connecting...", false));

        int protocol = intent.getIntExtra("protocol", 0);
        int mode = intent.getIntExtra("mode", 1);
        int scanMode = intent.getIntExtra("scanMode", 0);
        int ipVersion = intent.getIntExtra("ipVersion", 4);
        boolean quickReconnect = intent.getBooleanExtra("quickReconnect", false);
        boolean h2Enabled = intent.getBooleanExtra("h2Enabled", true);
        boolean echEnabled = intent.getBooleanExtra("echEnabled", true);
        boolean ironclad = intent.getBooleanExtra("ironclad", false);
        int healthInterval = intent.getIntExtra("healthInterval", 20);
        int healthMaxFails = intent.getIntExtra("healthMaxFails", 2);
        int healthTimeout = intent.getIntExtra("healthTimeout", 5);
        int liveValidate = intent.getIntExtra("liveValidate", 20);
        int socksPort = intent.getIntExtra("socksPort", 1819);
        int httpPort = intent.getIntExtra("httpPort", 1820);
        String noizeProfile = intent.getStringExtra("noizeProfile");
        String forcePeer = intent.getStringExtra("forcePeer");
        String configPathExtra = intent.getStringExtra("configPath");
        String sniExtra = intent.getStringExtra("sni");
        final String configPath =
            (configPathExtra == null || configPathExtra.isEmpty()) ? "aether.toml" : configPathExtra;
        final String sni = (sniExtra == null) ? "" : sniExtra;
        final int fProtocol = protocol;
        final int fMode = mode;
        final int fScanMode = scanMode;
        final int fIpVersion = ipVersion;
        final boolean fQuickReconnect = quickReconnect;
        final boolean fH2Enabled = h2Enabled;
        final boolean fEchEnabled = echEnabled;
        final boolean fIronclad = ironclad;
        final int fHealthInterval = healthInterval;
        final int fHealthMaxFails = healthMaxFails;
        final int fHealthTimeout = healthTimeout;
        final int fLiveValidate = liveValidate;

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
                    Log.e(TAG, "Failed to establish VPN (permission denied?)");
                    stopVpnAndNotification();
                    return;
                }

                int fd = vpnInterface.getFd();
                nativeSetTunFd(fd);
                Log.i(TAG, "VPN established, fd=" + fd);

                // Ensure native engine is initialized
                NativeEngine.nativeInit();

                boolean ok = NativeEngine.nativeStart(
                    fProtocol, fMode, false, fScanMode,
                    fIpVersion, fQuickReconnect,
                    (noizeProfile == null || noizeProfile.isEmpty()) ? "balanced" : noizeProfile,
                    false, 16, 32, 2, 10, socksPort, httpPort,
                    (forcePeer == null) ? "" : forcePeer, configPath, fH2Enabled, fEchEnabled,
                    sni, fIronclad, fHealthInterval, fHealthMaxFails, fHealthTimeout, fLiveValidate
                );
                if (!ok) {
                    Log.e(TAG, "nativeStart failed");
                    stopVpnAndNotification();
                    return;
                }

                running = true;
                Log.i(TAG, "VPN engine started in TUN mode");
                cachedTotalRx = 0;
                cachedTotalTx = 0;
                updateNotificationStats();
                statsHandler.post(statsRunnable);

                // Keep thread alive — engine runs in its own thread via FFI.
                while (running) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
                handler.post(() -> stopVpnAndNotification());
            } finally {
                cleanupVpnInterface();
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    private final Handler handler = new Handler(Looper.getMainLooper());

    private void stopVpnKeepNotification() {
        running = false;
        vpnPaused = true;

        if (vpnThread != null) {
            vpnThread.interrupt();
            try { vpnThread.join(2000); } catch (InterruptedException ignored) {}
            vpnThread = null;
        }

        NativeEngine.nativeStop();
        cleanupVpnInterface();
        statsHandler.removeCallbacks(statsRunnable);
        updateNotificationStats();
        Log.i(TAG, "VPN stopped (notification kept, Start available)");
    }

    private void stopVpnAndNotification() {
        Log.i(TAG, "stopVpnAndNotification: beginning full shutdown");
        running = false;
        vpnPaused = false;

        // 1. Stop the engine first (stops all network I/O)
        try { NativeEngine.nativeStop(); } catch (Exception e) {
            Log.e(TAG, "nativeStop failed: " + e.getMessage());
        }

        // 2. Kill the VPN thread
        if (vpnThread != null) {
            vpnThread.interrupt();
            try { vpnThread.join(3000); } catch (InterruptedException ignored) {}
            vpnThread = null;
        }

        // 3. Close the VPN interface (kills the OS VPN tunnel)
        cleanupVpnInterface();

        // 4. Cancel periodic stats
        statsHandler.removeCallbacks(statsRunnable);

        // 5. Dismiss notification and destroy service
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            @SuppressWarnings("deprecation")
            boolean removed = stopForeground(true);
        }
        stopSelf();
        Log.i(TAG, "VPN fully stopped + service destroyed");
    }

    private void cleanupVpnInterface() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
                Log.i(TAG, "VPN interface fd closed successfully");
            } catch (Exception e) {
                Log.e(TAG, "Error closing VPN fd: " + e.getMessage(), e);
            }
            vpnInterface = null;
        }
    }

    @Override
    public void onDestroy() {
        stopVpnAndNotification();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopVpnAndNotification();
        super.onRevoke();
    }

    // ── Notification ─────────────────────────────────────────────────────

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE VPN",
                NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("FCAE VPN tunnel status");
            NotificationManager mgr = getSystemService(NotificationManager.class);
            if (mgr != null) mgr.createNotificationChannel(ch);
        }
    }

    // Cached cumulative totals for notification (filled from JNI traffic stats)
    private long cachedTotalRx = 0;
    private long cachedTotalTx = 0;

    private void updateNotificationStats() {
        NotificationManager mgr = getSystemService(NotificationManager.class);
        if (mgr == null) return;

        boolean showStopBtn = running;

        String text;
        if (vpnPaused) {
            text = "FCAE VPN — Stopped (tap Start to resume)";
        } else if (running) {
            long rx = 0, tx = 0;
            try {
                long[] stats = nativeGetTrafficStats();
                if (stats != null && stats.length >= 2) {
                    rx = stats[0];
                    tx = stats[1];
                }
            } catch (UnsatisfiedLinkError e) {
                Log.w(TAG, "nativeGetTrafficStats missing: " + e.getMessage());
            } catch (Exception ignored) {}
            // nativeGetTrafficStats only returns rates; accumulate for totals
            cachedTotalRx += rx;
            cachedTotalTx += tx;
            text = String.format(
                "\u2193 %s  %s  |  \u2191 %s  %s",
                fmtBytes(cachedTotalRx), fmtRate(rx),
                fmtBytes(cachedTotalTx), fmtRate(tx));
        } else {
            text = "FCAE VPN — Disconnected";
        }

        mgr.notify(NOTIFICATION_ID, buildNotification(text, showStopBtn));
    }

    private Notification buildNotification(String text, boolean showStopButton) {
        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent piMain = PendingIntent.getActivity(this, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, CHANNEL_ID);
        } else {
            nb = new Notification.Builder(this);
        }

        nb.setContentTitle("FCAE VPN")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.ic_lock_lock)
          .setContentIntent(piMain)
          .setOngoing(true)
          .setStyle(new Notification.BigTextStyle().bigText(text));

        if (showStopButton) {
            // Disconnect button first
            Intent discIntent = new Intent(this, FCAEVpnService.class);
            discIntent.setAction(ACTION_DISCONNECT);
            PendingIntent piDisc = PendingIntent.getService(this, DISCONNECT_ACTION_CODE,
                discIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Disconnect", piDisc).build());

            // Stop button second
            Intent stopIntent = new Intent(this, FCAEVpnService.class);
            stopIntent.setAction(ACTION_STOP);
            PendingIntent piStop = PendingIntent.getService(this, STOP_ACTION_CODE,
                stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Stop", piStop).build());
        } else {
            // Disconnect always available
            Intent discIntent = new Intent(this, FCAEVpnService.class);
            discIntent.setAction(ACTION_DISCONNECT);
            PendingIntent piDisc = PendingIntent.getService(this, DISCONNECT_ACTION_CODE,
                discIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Disconnect", piDisc).build());

            // Start button second
            Intent startIntent = new Intent(this, FCAEVpnService.class);
            startIntent.setAction(ACTION_START);
            PendingIntent piStart = PendingIntent.getService(this, STOP_ACTION_CODE,
                startIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Start", piStart).build());
        }

        return nb.build();
    }

    private static String fmtBytes(long b) {
        if (b >= 1073741824L) return String.format("%.1f GB", b / 1073741824.0);
        if (b >= 1048576L)    return String.format("%.1f MB", b / 1048576.0);
        if (b >= 1024L)       return String.format("%.0f KB", b / 1024.0);
        return b + " B";
    }

    private static String fmtRate(long bps) {
        if (bps >= 1073741824L) return String.format("%.1f GB/s", bps / 1073741824.0);
        if (bps >= 1048576L)    return String.format("%.1f MB/s", bps / 1048576.0);
        if (bps >= 1024L)       return String.format("%.0f KB/s", bps / 1024.0);
        return bps + " B/s";
    }
}
