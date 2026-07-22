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
 *
 * Notification layout:
 *   [FCAE VPN] — Download: 1.23 MB/s  |  Upload: 456.78 KB/s
 *   [Stop] [Disconnect]
 *
 * Stop:     stops VPN, notification stays, button text -> "Start"
 * Disconnect: stops VPN, kills notification, exits app
 */
public class FCAEVpnService extends VpnService {
    private static final String TAG = "FCAE_VPN";
    private static final String CHANNEL_ID = "fcaevpn_service";
    private static final int NOTIFICATION_ID = 1;

    private static final int STOP_ACTION_CODE   = 10;
    private static final int DISCONNECT_ACTION_CODE = 11;
    private static final int START_ACTION_CODE  = 12;

    private static final String ACTION_STOP      = "com.fc.fcaevpn.STOP";
    private static final String ACTION_DISCONNECT = "com.fc.fcaevpn.DISCONNECT";
    private static final String ACTION_START     = "com.fc.fcaevpn.START";

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false; // true when "Stop" pressed but service alive

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

    static {
        System.loadLibrary("fcaevpn_native");
    }

    private static native void nativeSetTunFd(int fd);

    /** Called from native code every second with RX/TX rates */
    public static native long[] nativeGetTrafficStats();

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "FCAEVpnService created");
        statsHandler = new Handler(Looper.getMainLooper());
        // Point FFI engine discovery at the extracted native library directory
        // (libaether.so is packaged via jniLibs as the bundled aether binary).
        try {
            String nativeDir = getApplicationInfo().nativeLibraryDir;
            if (nativeDir != null) {
                System.setProperty("AETHER_NATIVE_LIB_DIR", nativeDir);
                // Also expose via process environment for the Rust FFI (android/libc)
                try {
                    Class<?> cl = Class.forName("android.system.Os");
                    java.lang.reflect.Method setenv = cl.getMethod(
                        "setenv", String.class, String.class, boolean.class);
                    setenv.invoke(null, "AETHER_NATIVE_LIB_DIR", nativeDir, true);
                    setenv.invoke(null, "AETHER_BIN_PATH", nativeDir + "/libaether.so", true);
                    Log.i(TAG, "AETHER engine path: " + nativeDir + "/libaether.so");
                } catch (Throwable t) {
                    Log.w(TAG, "Could not setenv AETHER paths: " + t);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "nativeLibraryDir unavailable: " + t);
        }
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
                    startVpn();
                    return START_STICKY;
            }
        }

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification(
            "FCAE VPN \u2014 Connecting...",
            true  // show Stop button
        ));

        startVpn();
        return START_STICKY;
    }

    private void startVpn() {
        if (running) return;
        vpnPaused = false;

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

                running = true;
                Log.i(TAG, "VPN established, fd=" + fd);
                updateNotificationStats();

                // Start periodic notification updates
                statsHandler.post(statsRunnable);

                while (running) {
                    Thread.sleep(500);
                }
            } catch (InterruptedException e) {
                Log.i(TAG, "VPN thread interrupted");
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
            } finally {
                cleanupVpnInterface();
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    /**
     * Stop VPN but keep notification alive.
     * Button text changes to "Start".
     */
    private void stopVpnKeepNotification() {
        running = false;
        vpnPaused = true;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        cleanupVpnInterface();

        statsHandler.removeCallbacks(statsRunnable);
        updateNotificationStats();

        Log.i(TAG, "VPN stopped (notification kept)");
    }

    /**
     * Fully stop VPN and dismiss notification.
     */
    private void stopVpnAndNotification() {
        running = false;
        vpnPaused = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

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

        boolean showStopBtn = running; // show Stop when running, Start when paused

        String text;
        if (vpnPaused) {
            text = "FCAE VPN \u2014 Stopped (tap Start to resume)";
        } else if (running) {
            long[] stats = {0, 0};
            try {
                stats = nativeGetTrafficStats();
            } catch (Exception ignored) {}
            long rx = stats[0];
            long tx = stats[1];
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

        // Disconnect button (always present)
        Intent discIntent = new Intent(this, FCAEVpnService.class);
        discIntent.setAction(ACTION_DISCONNECT);
        PendingIntent piDisc = PendingIntent.getService(this, DISCONNECT_ACTION_CODE,
            discIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        nb.addAction(new Notification.Action.Builder(null, "Disconnect", piDisc).build());

        // Stop / Start button
        if (showStopButton) {
            Intent stopIntent = new Intent(this, FCAEVpnService.class);
            stopIntent.setAction(ACTION_STOP);
            PendingIntent piStop = PendingIntent.getService(this, STOP_ACTION_CODE,
                stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            nb.addAction(new Notification.Action.Builder(null, "Stop", piStop).build());
        } else {
            Intent startIntent = new Intent(this, FCAEVpnService.class);
            startIntent.setAction(ACTION_START);
            PendingIntent piStart = PendingIntent.getService(this, START_ACTION_CODE,
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
