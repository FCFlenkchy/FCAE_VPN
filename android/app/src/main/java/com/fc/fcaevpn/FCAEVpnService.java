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
                    startVpn(intent);
                    return START_STICKY;
            }
        }

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification(
            "FCAE VPN \u2014 Ready (tap Connect in app)",
            false
        ));
        return START_STICKY;
    }

    private void startVpn(Intent intent) {
        if (running) return;
        vpnPaused = false;

        int protocol = intent.getIntExtra("protocol", 0);
        int mode = intent.getIntExtra("mode", 1);
        int scanMode = intent.getIntExtra("scanMode", 1);
        int ipVersion = intent.getIntExtra("ipVersion", 4);
        boolean quickReconnect = intent.getBooleanExtra("quickReconnect", true);
        boolean h2Enabled = intent.getBooleanExtra("h2Enabled", true);
        boolean echEnabled = intent.getBooleanExtra("echEnabled", true);
        boolean ironclad = intent.getBooleanExtra("ironclad", false);
        int healthInterval = intent.getIntExtra("healthInterval", 20);
        int healthMaxFails = intent.getIntExtra("healthMaxFails", 2);
        int healthTimeout = intent.getIntExtra("healthTimeout", 5);
        int liveValidate = intent.getIntExtra("liveValidate", 20);
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
                builder.setMtu(1280);
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
                    stopSelf();
                    return;
                }

                int fd = vpnInterface.getFd();
                nativeSetTunFd(fd);
                Log.i(TAG, "VPN established, fd=" + fd);

                // Ensure native engine is initialized
                NativeEngine.nativeInit();

                boolean ok = NativeEngine.nativeStart(
                    fProtocol, fMode, false, fScanMode,
                    fIpVersion, fQuickReconnect, "balanced",
                    false, 16, 32, 2, 10, 1819, 1820,
                    "", configPath, fH2Enabled, fEchEnabled,
                    sni, fIronclad, fHealthInterval, fHealthMaxFails, fHealthTimeout, fLiveValidate
                );
                if (!ok) {
                    Log.e(TAG, "nativeStart failed");
                    stopSelf();
                    return;
                }

                running = true;
                Log.i(TAG, "VPN engine started in TUN mode");
                updateNotificationStats();
                statsHandler.post(statsRunnable);

                // Keep thread alive — engine runs in its own thread via FFI.
                // TUN fd is shared with the Rust engine via nativeSetTunFd.
                while (running) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
            } finally {
                cleanupVpnInterface();
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    private void stopVpnKeepNotification() {
        running = false;
        vpnPaused = true;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        NativeEngine.nativeStop();
        cleanupVpnInterface();
        statsHandler.removeCallbacks(statsRunnable);
        updateNotificationStats();
        Log.i(TAG, "VPN stopped (notification kept)");
    }

    private void stopVpnAndNotification() {
        running = false;
        vpnPaused = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        NativeEngine.nativeStop();
        cleanupVpnInterface();
        statsHandler.removeCallbacks(statsRunnable);
        stopForeground(true);
        stopSelf();
        Log.i(TAG, "VPN fully stopped, notification dismissed");
    }

    private void cleanupVpnInterface() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing VPN fd: " + e.getMessage());
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

    private void updateNotificationStats() {
        NotificationManager mgr = getSystemService(NotificationManager.class);
        if (mgr == null) return;

        boolean showStopBtn = running;

        String text;
        if (vpnPaused) {
            text = "FCAE VPN \u2014 Stopped (tap Start to resume)";
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
            text = String.format("\u2193 %s/s  |  \u2191 %s/s",
                fmtBytesShort(rx), fmtBytesShort(tx));
        } else {
            text = "FCAE VPN \u2014 Disconnected";
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

        Intent discIntent = new Intent(this, FCAEVpnService.class);
        discIntent.setAction(ACTION_DISCONNECT);
        PendingIntent piDisc = PendingIntent.getService(this, DISCONNECT_ACTION_CODE,
            discIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        nb.addAction(new Notification.Action.Builder(null, "Disconnect", piDisc).build());

        if (showStopButton) {
            Intent stopIntent = new Intent(this, FCAEVpnService.class);
            stopIntent.setAction(ACTION_STOP);
            PendingIntent piStop = PendingIntent.getService(this, STOP_ACTION_CODE,
                stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Stop", piStop).build());
        } else {
            Intent startIntent = new Intent(this, FCAEVpnService.class);
            startIntent.setAction(ACTION_START);
            PendingIntent piStart = PendingIntent.getService(this, STOP_ACTION_CODE,
                startIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Start", piStart).build());
        }

        return nb.build();
    }

    private static String fmtBytesShort(long bps) {
        if (bps >= 1073741824L) return String.format("%.1f GB", bps / 1073741824.0);
        if (bps >= 1048576L)    return String.format("%.1f MB", bps / 1048576.0);
        if (bps >= 1024L)       return String.format("%.0f KB", bps / 1024.0);
        return bps + " B";
    }
}
