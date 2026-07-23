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

    private volatile ParcelFileDescriptor vpnInterface;
    private volatile Thread vpnThread;
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false;

    private Intent lastStartIntent;
    private VpnNotification notification;
    private Handler handler;

    private long cachedTotalRx = 0;
    private long cachedTotalTx = 0;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            updateNotification();
            if (running || vpnPaused) {
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
                    fullShutdown();
                    return START_NOT_STICKY;
                case ACTION_START:
                    if (!intent.hasExtra("protocol") && lastStartIntent != null) {
                        startVpn(lastStartIntent);
                    } else {
                        lastStartIntent = new Intent(intent);
                        startVpn(intent);
                    }
                    return START_STICKY;
            }
        }

        // Fallback
        notification.show("FCAE VPN \u2014 Ready (tap Connect in app)", false);
        startForeground(VpnNotification.NOTIFICATION_ID,
            notification.build("FCAE VPN \u2014 Ready (tap Connect in app)", false));
        return START_STICKY;
    }

    private void startVpn(Intent intent) {
        if (running) return;
        vpnPaused = false;

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

                while (running) {
                    try { Thread.sleep(200); } catch (InterruptedException e) { break; }
                }
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
                handler.post(() -> fullShutdown());
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    private void fullShutdown() {
        if (!running && vpnInterface == null) return;
        running = false;
        vpnPaused = false;

        Log.i(TAG, "fullShutdown: starting");
        handler.removeCallbacks(statsRunnable);

        // Kill VPN thread
        Thread t = vpnThread;
        vpnThread = null;
        if (t != null) {
            t.interrupt();
            try { t.join(1000); } catch (InterruptedException ignored) {}
        }

        // Save fd reference NOW — prevents race where user reconnects and
        // startVpn() overwrites vpnInterface before we close it
        ParcelFileDescriptor pfdToClose = vpnInterface;
        vpnInterface = null;

        // Close the TUN fd IMMEDIATELY on the main thread.
        // This is what actually tears down the OS VPN tunnel.
        // The kernel removes the TUN device when the last fd closes.
        if (pfdToClose != null) {
            try {
                pfdToClose.close();
                Log.i(TAG, "VPN fd closed");
            } catch (Exception e) {
                Log.e(TAG, "Error closing fd: " + e.getMessage());
            }
        }

        // Stop the service IMMEDIATELY — notification goes away, key icon
        // disappears. We do NOT wait for nativeStop() because it can block
        // forever and prevent stopSelf() from ever running.
        stopForeground(true);
        stopSelf();
        Log.i(TAG, "service stopped");

        // Broadcast disconnection
        Intent broadcast = new Intent("com.fc.fcaevpn.VPN_DISCONNECTED");
        broadcast.setPackage(getPackageName());
        sendBroadcast(broadcast);

        // nativeStop in background with a 3-second timeout — fire and forget.
        // The fd is already closed, so native threads will get EBADF and
        // exit on their own even if nativeStop doesn't complete.
        new Thread(() -> {
            Thread worker = new Thread(() -> {
                try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            }, "FCAE-NativeStop");
            worker.start();
            try { worker.join(3000); } catch (InterruptedException ignored) {}
            if (worker.isAlive()) {
                Log.w(TAG, "nativeStop timed out after 3s");
                worker.interrupt();
            } else {
                Log.i(TAG, "nativeStop completed");
            }
        }, "FCAE-NativeStop-Watchdog").start();
    }

    private void pauseVpn() {
        running = false;
        vpnPaused = true;

        Thread t = vpnThread;
        vpnThread = null;
        if (t != null) {
            t.interrupt();
            try { t.join(1000); } catch (InterruptedException ignored) {}
        }

        // Save and close fd immediately
        ParcelFileDescriptor pfdToClose = vpnInterface;
        vpnInterface = null;
        if (pfdToClose != null) {
            try { pfdToClose.close(); } catch (Exception ignored) {}
        }

        handler.removeCallbacks(statsRunnable);
        updateNotification();
        Log.i(TAG, "VPN paused");

        // nativeStop in background with timeout
        new Thread(() -> {
            Thread worker = new Thread(() -> {
                try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            }, "FCAE-NativeStop-Pause");
            worker.start();
            try { worker.join(3000); } catch (InterruptedException ignored) {}
            if (worker.isAlive()) worker.interrupt();
        }, "FCAE-Pause-Watchdog").start();
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
