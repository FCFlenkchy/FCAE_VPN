package com.fc.fcaevpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

public class FCAEVpnService extends VpnService {

    /**
     * MTU of the VpnService interface.
     *
     * The native side must configure tun2socks with exactly this value --
     * see cfg.tun_mtu in android_jni.cpp. If the two disagree the tunnel
     * establishes and then silently drops oversized packets.
     *
     * This is the MTU of the LOCAL tun device only; it is not the tunnel MTU.
     * tun2socks terminates TCP on this interface and re-dials through SOCKS,
     * so apps' segments are rebuilt by the engine to fit whatever the tunnel
     * carries (TUNNEL_MTU 1280, H2_TUNNEL_MTU 1500, INNER_MTU 1200 for
     * warp-in-warp). A larger local MTU therefore means fewer, bigger reads
     * across the JNI/gVisor boundary rather than oversized wire packets.
     *
     * Do NOT go below 1280: this interface carries an IPv6 address (fd00::2)
     * and Android/Linux reject IPv6 on links with MTU < 1280.
     */
    static final int kVpnServiceMtu = 1500;
    private static final String TAG = "FCAE_VPN";

    public static final String ACTION_STOP       = "com.fc.fcaevpn.STOP";
    public static final String ACTION_DISCONNECT = "com.fc.fcaevpn.DISCONNECT";
    public static final String ACTION_START      = "com.fc.fcaevpn.START";

    public static final String BROADCAST_VPN_DISCONNECTED  = "com.fc.fcaevpn.VPN_DISCONNECTED";
    public static final String BROADCAST_VPN_STATE_CHANGED = "com.fc.fcaevpn.VPN_STATE_CHANGED";

    // Package-private: ProxyNotification stamps the same generation counter on
    // its disconnect broadcast, so MainActivity's stale-broadcast filter treats
    // proxy and TUN teardowns identically.
    static final AtomicLong sGeneration = new AtomicLong(0);
    private static FCAEVpnService instance; // ADDED for instant UI disconnect

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
    private String lastNotifText = null;

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            // ── Engine-death watchdog ─────────────────────────────────────
            // nativeStart() returns as soon as the engine thread is
            // launched; the engine can still die LATER on its own (no
            // endpoint found, tunnel failed permanently, etc.). This
            // service would then keep the established TUN fd open forever:
            // the kernel keeps routing every packet into a dead VPN
            // (zombie interface, blackholed traffic, stale notification)
            // until the user manually disconnects. Poll the engine state
            // and tear down when it reaches a terminal state:
            //   0 = DISCONNECTED (engine idle/finished on its own)
            //   5 = ERROR
            // Transient states (1 provisioning, 2 scanning/reconnecting,
            // 3 connecting, 4 connected) never trigger a teardown.
            if (running && !shuttingDown && !vpnPaused) {
                int engineState = 5; // pessimistic default if the JNI call throws
                try {
                    engineState = NativeEngine.nativeGetState();
                } catch (Exception ignored) {}
                if (engineState == 0 || engineState == 5) {
                    Log.w(TAG, "Engine reached terminal state " + engineState
                            + " — tearing down VPN service");
                    fullShutdown();
                    return;
                }
            }
            updateNotification();
            if (running) handler.postDelayed(this, 1000);
        }
    };

    private static native void nativeSetTunFd(int fd);
    // Hands this VpnService to the native side so Psiphon's own sockets can be
    // excluded from the tunnel via protect(fd).
    private native void nativeRegisterVpnService();
    private static native void nativeUnregisterVpnService();
    public static native long[] nativeGetTrafficStats();

    // ADDED: Called directly from MainActivity for 0ms UI disconnect
    public static void disconnectNow() {
        if (instance != null) {
            instance.fullShutdown();
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        // Register before any tunnel starts: Psiphon may call protect() as
        // soon as it begins dialling.
        try { nativeRegisterVpnService(); } catch (Throwable ignored) {}
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
                        notification.show("FCAE VPN — Ready (tap Connect in app)", false);
                        startForeground(VpnNotification.NOTIFICATION_ID,
                            notification.build("FCAE VPN — Ready (tap Connect in app)", false));
                    }
                    return START_STICKY;
            }
        }

        notification.show("FCAE VPN — Ready (tap Connect in app)", false);
        startForeground(VpnNotification.NOTIFICATION_ID,
            notification.build("FCAE VPN — Ready (tap Connect in app)", false));
        return START_STICKY;
    }

    private void startVpn(Intent intent) {
        sGeneration.incrementAndGet();
        cleanupGeneration++;
        vpnPaused = false;
        shuttingDown = false;
        nativeFreed = false;

        running = false;

        // The previous session is stopped on the worker thread below, NOT
        // here. startVpn() runs on the main thread (onStartCommand), and
        // fcae_stop() blocks until the session thread joins -- up to its 10s
        // stop_timeout. Doing it here froze the UI and, past 5s, tripped an
        // ANR: changing a setting while connected looked like "stuck on
        // establishing, nothing happens".
        final ParcelFileDescriptor oldPfd = vpnInterface;
        vpnInterface = null;

        notification.show("FCAE VPN — Connecting...", false);
        startForeground(VpnNotification.NOTIFICATION_ID,
            notification.build("FCAE VPN — Connecting...", false));

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
        // SOCKS5 is mandatory in TUN mode (tun2socks dials the local SOCKS5
        // listener for every connection), so never hand the engine a disabled
        // SOCKS5 there. The UI locks the switch on; this is the defensive net.
        final int socksPortForMode = (mode == 1 && socks == 0) ? 1819 : socks;
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
        final int torMode      = intent.getIntExtra("torMode", 0);
        final int torBridges   = intent.getIntExtra("torBridges", 0);
        final String torLines  = intent.getStringExtra("torBridgeLines");
        final String torLinesV = (torLines == null) ? "" : torLines;
        final int engineLog    = intent.getIntExtra("engineLog", 3);
        final int backend      = intent.getIntExtra("backend", 0);
        final int torSocksPort = intent.getIntExtra("torSocksPort", 1821);
        final String psiphonCfg    = intent.getStringExtra("psiphonConfig");
        final String psiphonRegion = intent.getStringExtra("psiphonRegion");
        final String psiphonCfgV    = (psiphonCfg == null) ? "" : psiphonCfg;
        final String psiphonRegionV = (psiphonRegion == null) ? "" : psiphonRegion;
        final int psiphonSocks = intent.getIntExtra("psiphonSocksPort", 0);
        final int psiphonHttp  = intent.getIntExtra("psiphonHttpPort", 0);
        final String teamVal   = (teamName == null) ? "" : teamName;
        final String tokenVal  = (accessTok == null) ? "" : accessTok;
        final String emailVal  = (accessEm == null) ? "" : accessEm;
        final String routesVal = (routesF == null) ? "" : routesF;
        final String routesIVal = (routesI == null) ? "" : routesI;

        vpnThread = new Thread(() -> {
            try {
                // Stop any previous session and release its descriptor before
                // building a new interface. Blocking is fine here -- this is
                // the worker thread, not the main thread -- but release the
                // device first so the old interface is gone before
                // Builder.establish() creates the new one; otherwise the two
                // overlap and the system briefly routes through a TUN whose
                // backend has already been cancelled.
                try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
                if (oldPfd != null) {
                    try { oldPfd.close(); } catch (Exception ignored) {}
                }
                try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

                Builder builder = new Builder();
                builder.setSession("FCAE VPN");
                // See kVpnServiceMtu: this is the local tun device MTU, not
                // the tunnel MTU. Must stay in sync with cfg.tun_mtu on the
                // native side.
                builder.setMtu(kVpnServiceMtu);
                builder.addAddress("10.0.0.2", 32);
                builder.addAddress("fd00::2", 128);
                builder.addRoute("0.0.0.0", 0);
                builder.addRoute("::", 0);
                try { builder.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
                builder.addDnsServer("1.1.1.1");
                builder.addDnsServer("1.0.0.1");
                builder.addDnsServer("2606:4700:4700::1111");
                builder.addDnsServer("2606:4700:4700::1001");

                vpnInterface = builder.establish();
                if (vpnInterface == null) {
                    handler.post(this::fullShutdown);
                    return;
                }

                int fd = vpnInterface.getFd();
                nativeSetTunFd(fd);
                NativeEngine.nativeInit();
                try {
                    // tun2socks runs IN-PROCESS: its Go code is linked into
                    // libtun2socks_bridge.so, which the dynamic linker loads
                    // alongside libfcaevpn_native.so. There is no tun2socks
                    // binary to locate or execute any more, so the old
                    // nativeSetTun2socksBin() handshake is gone; the TUN fd set
                    // above via nativeSetTunFd() is all the bridge needs.
                    NativeEngine.nativeSetNativeLibDir(getApplicationInfo().nativeLibraryDir);
                } catch (Exception ignored) {}

                boolean ok = NativeEngine.nativeStart(
                    protocol, mode, lan, scanMode,
                    ipVersion, quick, noizeVal,
                    false, 16, 32, 2, 10, socksPortForMode, http,
                    peerVal, cfgPath, h2, ech,
                    sniVal, sysProfile,
                    teamVal, tokenVal, emailVal, routesVal, routesIVal,
                    torMode, torBridges, torLinesV, engineLog,
                    backend, torSocksPort,
                    psiphonCfgV, psiphonRegionV, psiphonSocks, psiphonHttp
                );
                if (!ok) {
                    handler.post(this::fullShutdown);
                    return;
                }

                running = true;
                lastNotifText = null;
                updateNotification();
                handler.post(statsRunnable);
                notifyUi();

                shutdownLatch = new CountDownLatch(1);
                try { shutdownLatch.await(); } catch (InterruptedException ignored) {}
            } catch (Exception e) {
                handler.post(this::fullShutdown);
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    /**
     * Release the whole native library.
     *
     * Deliberately NOT called on an ordinary disconnect. fcae_shutdown()
     * tears the library down process-wide, and the JNI layer latches
     * g_inited=false; every later call then has to re-init, and anything
     * holding state across a session (the log sink, the Psiphon region list,
     * the registered VpnService for protect()) is lost. Disconnect →
     * reconnect appeared to leave "the FFI turned off" for exactly that
     * reason. fcae_stop() alone ends a session; the library stays usable.
     *
     * This is now reserved for the process genuinely going away (onDestroy
     * with no activity alive), where releasing is correct.
     */
    private void freeNativeOnce() {
        if (nativeFreed) return;
        nativeFreed = true;
        Thread t = new Thread(() -> {
            try { NativeEngine.nativeFree(); } catch (Exception ignored) {}
        }, "FCAE-NativeFree");
        t.setDaemon(true);
        t.start();
    }
    
    private void fullShutdown() {
        sGeneration.incrementAndGet();
        running = false;
        vpnPaused = false;

        if (shutdownLatch != null) {
            shutdownLatch.countDown();
            shutdownLatch = null;
        }

        if (!shuttingDown) {
            shuttingDown = true;
        }

        final Thread t = vpnThread;
        vpnThread = null;
        final ParcelFileDescriptor pfd = vpnInterface;
        vpnInterface = null;
        lastStartIntent = null;

        // 1. INSTANT UI & NOTIFICATION CLEANUP
        Runnable uiCleanup = () -> {
            handler.removeCallbacks(statsRunnable);
            notifyUi();
            notification.dismiss();
            stopForeground(STOP_FOREGROUND_REMOVE);
        };

        if (Looper.myLooper() == Looper.getMainLooper()) {
            uiCleanup.run();
        } else {
            handler.post(uiCleanup);
        }

        // 2. TUN TEARDOWN -- two phases, neither on the main thread.
        //
        // Phase A (fcae_stop_begin) only cancels the session and drops the
        // TUN device, closing the native dup of our VpnService fd. It does
        // NOT join the worker thread, so it returns in milliseconds. That
        // matters because the kernel keeps the VPN alive -- key icon in the
        // status bar, traffic still captured -- until every descriptor for
        // the interface is closed. Previously the only path that released
        // them was the blocking fcae_stop(), so the tunnel lingered for
        // seconds after the user tapped disconnect.
        //
        // Order is still load-bearing: our own PFD may only be closed once
        // the native side has released its dup, or the Go stack reads a
        // descriptor the kernel has already recycled.
        //
        // Phase B (fcae_stop) reaps the session thread and can block; it
        // runs after the interface is already gone, so nobody is waiting.
        final long myGen = cleanupGeneration;
        Thread cleanupThread = new Thread(() -> {
            if (myGen != cleanupGeneration) return;

            try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}

            if (pfd != null) {
                try { pfd.close(); } catch (Exception ignored) {}
            }

            // The interface is down by here; the UI is already free.
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

            if (t != null) {
                t.interrupt();
                try { t.join(1000); } catch (InterruptedException ignored) {}
            }

            handler.post(this::stopSelf);

            // Only release the library when the process is actually going
            // away. On a normal disconnect it must stay initialised, or the
            // next connect finds a shut-down FFI.
            if (!MainActivity.activityAlive) {
                freeNativeOnce();
                android.os.Process.killProcess(android.os.Process.myPid());
            }
        }, "FCAE-Cleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    private void pauseVpn() {
        sGeneration.incrementAndGet();
        running = false;
        vpnPaused = true;

        if (shutdownLatch != null) {
            shutdownLatch.countDown();
            shutdownLatch = null;
        }

        final Thread t = vpnThread;
        vpnThread = null;
        final ParcelFileDescriptor pfd = vpnInterface;
        vpnInterface = null;

        // 1. INSTANT UI & NOTIFICATION UPDATE
        Runnable uiCleanup = () -> {
            notifyUi();
            handler.removeCallbacks(statsRunnable);
            updateNotification();
        };

        if (Looper.myLooper() == Looper.getMainLooper()) {
            uiCleanup.run();
        } else {
            handler.post(uiCleanup);
        }

        // 2. TUN TEARDOWN -- same two-phase release as fullShutdown(), so the
        // interface disappears immediately instead of after the join.
        //
        // freeNativeOnce() is deliberately absent: pause is resumable, and
        // releasing the library here meant resuming had to re-init a
        // shut-down FFI.
        final long myGen = cleanupGeneration;
        Thread cleanupThread = new Thread(() -> {
            if (myGen != cleanupGeneration) return;

            try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}

            if (pfd != null) {
                try { pfd.close(); } catch (Exception ignored) {}
            }

            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

            if (t != null) {
                t.interrupt();
                try { t.join(1000); } catch (InterruptedException ignored) {}
            }
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
            notification.show("FCAE VPN — Stopped (tap Start to resume)", false);
        } else if (running) {
            long rx = 0, tx = 0, totalRx = 0, totalTx = 0;
            try {
                long[] stats = nativeGetTrafficStats();
                if (stats != null && stats.length >= 4) {
                    rx = stats[0]; tx = stats[1]; totalRx = stats[2]; totalTx = stats[3];
                }
            } catch (Exception ignored) {}
            String text = String.format(
                "↓ %s  %s  |  ↑ %s  %s",
                VpnNotification.fmtBytes(totalRx), VpnNotification.fmtRate(rx),
                VpnNotification.fmtBytes(totalTx), VpnNotification.fmtRate(tx));
            if (!text.equals(lastNotifText)) {
                lastNotifText = text;
                notification.show(text, true);
            }
        } else {
            lastNotifText = null;
            notification.show("FCAE VPN — Disconnected", false);
        }
    }

    @Override
    public void onDestroy() {
        instance = null;
        fullShutdown();
        // Drop the global ref before the service object dies, or the native
        // side keeps a stale reference and protect() calls a dead object.
        try { nativeUnregisterVpnService(); } catch (Throwable ignored) {}
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
            try { NativeEngine.nativeClearLogs(); } catch (Exception ignored) {}
            lastNotifText = null;
        }
    }
}
