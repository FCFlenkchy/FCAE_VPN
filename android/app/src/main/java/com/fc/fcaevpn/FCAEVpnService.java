package com.fc.fcaevpn;

import android.app.Notification;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.telephony.TelephonyManager;
import android.util.Log;
import java.net.InetAddress;
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
    /**
     * Generation the in-flight connect belongs to.
     *
     * establishTunNow() runs on a core thread, long after startVpn() returned,
     * so it needs its own record of which session asked for the interface. A
     * disconnect that lands mid-handshake bumps cleanupGeneration and the
     * establish is refused rather than leaving a live TUN behind a UI that
     * already says DISCONNECTED.
     */
    private volatile long pendingSessionGen = -1;
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

    private final Object cmdLock = new Object();
    private volatile boolean engineOpInFlight = false;
    private volatile Intent queuedStart = null;
    private volatile boolean uiConnecting = false;

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

    // ── Psiphon network state (called from native via JNI) ──────────────
    //
    // These three describe the network BENEATH our tunnel. Psiphon dials on
    // that network with its sockets protected, so it must not be told about
    // the VPN's own interface.
    //
    // Resolved reflectively by name/signature in android_jni.cpp; keep the
    // names and signatures in sync with the GetMethodID calls there, and keep
    // them out of ProGuard's reach (proguard-rules.pro keeps this package).

    /**
     * Resolvers of the underlying (non-VPN) network, comma delimited.
     *
     * Mandatory: once the protect hook is installed, Psiphon stops using the
     * platform resolver, so this list is its only source of DNS servers. An
     * empty answer means no name resolution at all, which surfaces as a
     * tunnel that never establishes rather than as a DNS error.
     */
    @SuppressWarnings("unused")
    public String psiphonDnsServers() {
        StringBuilder out = new StringBuilder();
        try {
            ConnectivityManager cm =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return fallbackDnsServers();

            Network active = underlyingNetwork(cm);
            if (active == null) return fallbackDnsServers();

            LinkProperties lp = cm.getLinkProperties(active);
            if (lp == null) return fallbackDnsServers();

            for (InetAddress addr : lp.getDnsServers()) {
                String host = addr.getHostAddress();
                if (host == null || host.isEmpty()) continue;
                // Strip any IPv6 scope id ("fe80::1%wlan0"); Psiphon parses
                // these as plain addresses.
                int pct = host.indexOf('%');
                if (pct >= 0) host = host.substring(0, pct);
                if (out.length() > 0) out.append(',');
                out.append(host);
            }
        } catch (Throwable t) {
            Log.w(TAG, "psiphonDnsServers failed: " + t);
        }
        if (out.length() == 0) return fallbackDnsServers();
        return out.toString();
    }

    /**
     * Last resort when the platform will not name its resolvers.
     *
     * Returning "" here would leave Psiphon with no servers at all, so prefer
     * public resolvers: they are reached over protected sockets on the
     * underlying network, exactly like every other Psiphon dial.
     */
    private String fallbackDnsServers() {
        return "1.1.1.1,8.8.8.8";
    }

    /** True when a usable underlying network exists. */
    @SuppressWarnings("unused")
    public boolean psiphonHasConnectivity() {
        try {
            ConnectivityManager cm =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return true;
            Network active = underlyingNetwork(cm);
            if (active == null) return false;
            NetworkCapabilities caps = cm.getNetworkCapabilities(active);
            if (caps == null) return false;
            return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
        } catch (Throwable t) {
            // Unknown: claim connectivity rather than stalling a tunnel that
            // might have worked.
            return true;
        }
    }

    /**
     * Identity of the underlying network.
     *
     * Psiphon keys its tactics, server affinity and dial parameters on this.
     * A constant value meant parameters learned on an uncensored Wi-Fi link
     * were replayed on a censored mobile carrier, so each network change
     * started from a poisoned cache. Mirrors the scheme upstream's own client
     * uses: transport type plus a per-network discriminator.
     */
    @SuppressWarnings("unused")
    public String psiphonNetworkId() {
        try {
            ConnectivityManager cm =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return "UNKNOWN";
            Network active = underlyingNetwork(cm);
            if (active == null) return "UNKNOWN";
            NetworkCapabilities caps = cm.getNetworkCapabilities(active);
            if (caps == null) return "UNKNOWN";

            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                // The BSSID distinguishes access points. It needs location
                // permission on newer releases; without it the platform
                // returns a placeholder, which still beats one global id.
                String bssid = wifiBssid(caps);
                if (bssid != null) return "WIFI-" + bssid;
                return "WIFI";
            }

            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                try {
                    TelephonyManager tm =
                        (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
                    if (tm != null) {
                        String operator = tm.getNetworkOperator();
                        if (operator != null && !operator.isEmpty()) {
                            return "MOBILE-" + operator;
                        }
                    }
                } catch (Throwable ignored) {}
                return "MOBILE";
            }

            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return "ETHERNET";
            }
        } catch (Throwable t) {
            Log.w(TAG, "psiphonNetworkId failed: " + t);
        }
        return "UNKNOWN";
    }

    /**
     * The active network excluding our own VPN.
     *
     * getActiveNetwork() returns the VPN itself once our interface is up, and
     * its LinkProperties carry the DNS servers we configured on the Builder.
     * Handing those to Psiphon would point it at resolvers reachable only
     * through the tunnel it is still trying to build.
     */
    private Network underlyingNetwork(ConnectivityManager cm) {
        Network best = null;
        try {
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                if (caps == null) continue;
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    return n;
                }
                if (best == null) best = n;
            }
        } catch (Throwable t) {
            Log.w(TAG, "underlyingNetwork failed: " + t);
        }
        return best;
    }

    /**
     * BSSID of the current Wi-Fi network, or null when unknown.
     *
     * WifiManager.getConnectionInfo() is deprecated on API 31+; prefer
     * NetworkCapabilities.getTransportInfo() there.
     */
    @SuppressWarnings("deprecation")
    private String wifiBssid(NetworkCapabilities caps) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                Object ti = caps.getTransportInfo();
                if (ti instanceof WifiInfo) {
                    String bssid = ((WifiInfo) ti).getBSSID();
                    if (isUsableBssid(bssid)) return bssid;
                }
            } catch (Throwable ignored) {}
        }
        try {
            WifiManager wm = (WifiManager)
                getApplicationContext().getSystemService(WIFI_SERVICE);
            if (wm != null) {
                WifiInfo info = wm.getConnectionInfo();
                if (info != null && isUsableBssid(info.getBSSID())) {
                    return info.getBSSID();
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static boolean isUsableBssid(String bssid) {
        return bssid != null && !bssid.isEmpty()
            && !bssid.equals("02:00:00:00:00:00");
    }

    /**
     * startForeground(int, Notification) is deprecated on API 34; pass the
     * specialUse type already declared in the manifest.
     */
    @SuppressWarnings("deprecation")
    private void startFg(Notification n) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                VpnNotification.NOTIFICATION_ID,
                n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(VpnNotification.NOTIFICATION_ID, n);
        }
    }

    /**
     * Create the VPN interface and return its descriptor, or -1 on failure.
     *
     * Called from the core (via the fd provider registered in
     * android_jni.cpp) once a backend has reported a live SOCKS endpoint, so
     * the system routes only start pointing at us after there is something on
     * the other end to receive the traffic.
     *
     * The descriptor stays owned by this service: the native side dups it.
     * Resolved reflectively by name/signature in android_jni.cpp.
     */
    @SuppressWarnings("unused")
    public int establishTunNow() {
        // A disconnect may have arrived while the backend was still dialling.
        // Building an interface for a session nobody wants any more is what
        // used to strand a live TUN behind a disconnected UI.
        if (shuttingDown || pendingSessionGen != cleanupGeneration) {
            Log.w(TAG, "establishTunNow: session is stale, refusing");
            return -1;
        }

        try {
            Builder builder = new Builder();
            builder.setSession("FCAE VPN");
            // See kVpnServiceMtu: this is the local tun device MTU, not the
            // tunnel MTU. Must stay in sync with cfg.tun_mtu on the native
            // side.
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

            ParcelFileDescriptor pfd = builder.establish();
            if (pfd == null) {
                Log.e(TAG, "establishTunNow: the system refused to create the interface");
                return -1;
            }

            // Re-check: establish() can block, and the session may have gone
            // stale while it did.
            if (shuttingDown || pendingSessionGen != cleanupGeneration) {
                try { pfd.close(); } catch (Exception ignored) {}
                Log.w(TAG, "establishTunNow: session went stale while establishing");
                return -1;
            }

            vpnInterface = pfd;
            return pfd.getFd();
        } catch (Throwable t) {
            Log.e(TAG, "establishTunNow failed: " + t);
            return -1;
        }
    }

    /**
     * Publish a descriptor up front.
     *
     * Unused by the normal connect path, which defers creation to
     * establishTunNow(). Kept for callers that already hold an interface.
     */
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

        // Force the native libraries to load before calling ANY native method
        // on this class.
        //
        // The JNI entry points live in libfcaevpn_native.so, but only
        // NativeEngine's static initialiser loads it. This service never
        // referenced NativeEngine before its first native call, so
        // nativeRegisterVpnService() below could be the very first one --
        // throwing UnsatisfiedLinkError and killing the process on launch.
        // Touching NativeEngine first runs that initialiser.
        //
        // Wrapped because a build/ABI without the libraries must degrade to a
        // broken tunnel, never a crash on startup.
        try {
            NativeEngine.ensureLoaded();
            // Register before any tunnel starts: Psiphon may call protect()
            // as soon as it begins dialling.
            nativeRegisterVpnService();
        } catch (Throwable t) {
            android.util.Log.e("FCAE_VPN", "native register failed: " + t);
        }

        handler = new Handler(Looper.getMainLooper());
        notification = new VpnNotification(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_STOP:
                    requestPause();
                    return START_STICKY;

                case ACTION_DISCONNECT:
                    requestDisconnect();
                    return START_NOT_STICKY;

                case ACTION_START:
                    requestStart(intent);
                    return START_STICKY;
            }
        }

        showReady();
        return START_STICKY;
    }

    /**
     * Notification / UI command: Stop. Highest priority after Disconnect.
     * Cancels a queued Start; if a start is in flight the generation bump
     * in pauseVpn() makes that worker exit.
     */
    private void requestPause() {
        synchronized (cmdLock) {
            queuedStart = null;
        }
        pauseVpn();
    }

    /** Notification / UI command: Disconnect. Kills the session and the service. */
    private void requestDisconnect() {
        synchronized (cmdLock) {
            queuedStart = null;
        }
        if (vpnInterface == null && vpnThread == null && !running && !engineOpInFlight) {
            handler.removeCallbacks(statsRunnable);
            notification.dismiss();
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return;
        }
        fullShutdown();
    }

    /**
     * Notification / UI command: Start. If a stop is still joining the
     * engine, queue this until that cleanup returns — never start on top
     * of an aborting warp-in-warp task.
     */
    private void requestStart(Intent intent) {
        Intent src = intent;
        if (src == null || !src.hasExtra("protocol")) {
            if (lastStartIntent != null) {
                src = lastStartIntent;
            } else {
                src = recalledStart();
            }
        }
        if (src == null || !src.hasExtra("protocol")) {
            showReady();
            return;
        }
        lastStartIntent = new Intent(src);
        rememberStart(lastStartIntent);

        synchronized (cmdLock) {
            if (engineOpInFlight || (running && !vpnPaused)) {
                if (running && !vpnPaused) {
                    Log.i(TAG, "Start ignored: tunnel already up");
                    return;
                }
                queuedStart = lastStartIntent;
                Log.i(TAG, "Start queued until current stop finishes");
                uiConnecting = true;
                notification.show("FCAE VPN — Starting after stop…", VpnNotification.BUTTONS_CONNECTING);
                startFg(notification.build("FCAE VPN — Starting after stop…", VpnNotification.BUTTONS_CONNECTING));
                notifyUi();
                return;
            }
            engineOpInFlight = true;
        }
        startVpn(lastStartIntent);
    }

    private void showReady() {
        uiConnecting = false;
        notification.show("FCAE VPN — Ready (tap Connect in app)", VpnNotification.BUTTONS_PAUSED);
        startFg(notification.build("FCAE VPN — Ready (tap Connect in app)", VpnNotification.BUTTONS_PAUSED));
    }

    private void finishEngineOp() {
        Intent next;
        synchronized (cmdLock) {
            engineOpInFlight = false;
            next = queuedStart;
            queuedStart = null;
        }
        if (next != null && !shuttingDown) {
            Log.i(TAG, "Running queued Start from notification");
            synchronized (cmdLock) {
                engineOpInFlight = true;
            }
            final Intent src = next;
            handler.post(() -> startVpn(src));
        }
    }

    private void startVpn(Intent intent) {
        sGeneration.incrementAndGet();
        cleanupGeneration++;
        // The worker validates this after every slow step (establish,
        // nativeStart): a disconnect/pause/new connect that lands in the
        // connect window must not be overridden by a late "running=true".
        final long sessionGen = cleanupGeneration;
        vpnPaused = false;
        shuttingDown = false;
        nativeFreed = false;
        uiConnecting = true;

        running = false;

        // The previous session is stopped on the worker thread below, NOT
        // here. startVpn() runs on the main thread (onStartCommand), and
        // fcae_stop() blocks until the session thread joins -- up to its 10s
        // stop_timeout. Doing it here froze the UI and, past 5s, tripped an
        // ANR: changing a setting while connected looked like "stuck on
        // establishing, nothing happens".
        final ParcelFileDescriptor oldPfd = vpnInterface;
        vpnInterface = null;

        rememberStart(intent);
        notification.show("FCAE VPN — Connecting...", VpnNotification.BUTTONS_CONNECTING);
        startFg(notification.build("FCAE VPN — Connecting...", VpnNotification.BUTTONS_CONNECTING));
        notifyUi();

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

                // The interface is NOT established here.
                //
                // Doing so put the system routes in place before the backend
                // had connected, so every packet of the handshake depended on
                // the protect hook catching every socket; anything it missed
                // looped straight back into our own half-built tunnel. The
                // core now calls establishTunNow() through the fd provider,
                // once a backend has reported a live SOCKS endpoint. Proxy
                // mode never calls it at all, so no interface is created.
                pendingSessionGen = sessionGen;
                NativeEngine.nativeInit();
                try {
                    // tun2socks runs IN-PROCESS: its Go code is linked into
                    // libfcae_go_bridge.so, which the dynamic linker loads
                    // alongside libfcaevpn_native.so. There is no tun2socks
                    // binary to locate or execute any more, and the TUN fd is
                    // supplied on demand by establishTunNow().
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
                    synchronized (cmdLock) { engineOpInFlight = false; }
                    handler.post(this::fullShutdown);
                    return;
                }

                // The handshake is the long pole: the user can disconnect
                // (app or notification) in the middle of it. If this session
                // went stale, tear the engine down again and exit WITHOUT
                // claiming "running" — the disconnect already broadcast its
                // own state, so no extra notifyUi() here.
                if (sessionGen != cleanupGeneration || shuttingDown) {
                    try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
                    try { vpnInterface.close(); } catch (Exception ignored) {}
                    vpnInterface = null;
                    try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
                    synchronized (cmdLock) { engineOpInFlight = false; }
                    return;
                }

                running = true;
                uiConnecting = false;
                synchronized (cmdLock) { engineOpInFlight = false; }
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
        uiConnecting = false;
        synchronized (cmdLock) {
            queuedStart = null;
            engineOpInFlight = true;
        }
        forgetStart();

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

            synchronized (cmdLock) {
                engineOpInFlight = false;
                queuedStart = null;
            }

            // Disconnect from the notification (or UI) asked the process
            // to die when the activity is not in front — obey that.
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
        // Invalidate any in-flight startVpn() session: without this bump a
        // pause landing in the connect window would not stop the worker, and
        // it would resurrect "running" (live TUN) after the pause.
        cleanupGeneration++;
        running = false;
        vpnPaused = true;
        uiConnecting = false;
        synchronized (cmdLock) {
            engineOpInFlight = true;
        }

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
            if (myGen != cleanupGeneration) {
                finishEngineOp();
                return;
            }

            try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}

            if (myGen != cleanupGeneration) {
                finishEngineOp();
                return;
            }

            if (pfd != null) {
                try { pfd.close(); } catch (Exception ignored) {}
            }

            if (myGen != cleanupGeneration) {
                finishEngineOp();
                return;
            }

            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}

            if (t != null) {
                t.interrupt();
                try { t.join(1000); } catch (InterruptedException ignored) {}
            }

            finishEngineOp();
        }, "FCAE-PauseCleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    private void notifyUi() {
        Intent intent = new Intent(BROADCAST_VPN_STATE_CHANGED);
        intent.setPackage(getPackageName());
        intent.putExtra("running", running);
        intent.putExtra("paused", vpnPaused && !uiConnecting);
        intent.putExtra("connecting", uiConnecting);
        intent.putExtra("generation", sGeneration.get());
        sendBroadcast(intent);
    }

    private void updateNotification() {
        if (uiConnecting) {
            lastNotifText = null;
            notification.show("FCAE VPN — Connecting...", VpnNotification.BUTTONS_CONNECTING);
        } else if (vpnPaused) {
            lastNotifText = null;
            notification.show("FCAE VPN — Stopped (tap Start to resume)", VpnNotification.BUTTONS_PAUSED);
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
                notification.show(text, VpnNotification.BUTTONS_RUNNING);
            }
        } else {
            lastNotifText = null;
            notification.show("FCAE VPN — Disconnected", VpnNotification.BUTTONS_PAUSED);
        }
    }

    private static final String PREFS_LAST = "fcae_vpn_last_start";

    private void rememberStart(Intent i) {
        if (i == null) return;
        SharedPreferences.Editor e = getSharedPreferences(PREFS_LAST, MODE_PRIVATE).edit();
        e.putBoolean("has", true);
        putInt(e, i, "protocol", 0);
        putInt(e, i, "mode", 1);
        putInt(e, i, "scanMode", 0);
        putInt(e, i, "ipVersion", 4);
        putBool(e, i, "quickReconnect", false);
        putBool(e, i, "h2Enabled", true);
        putBool(e, i, "echEnabled", true);
        putBool(e, i, "lanSharing", false);
        putInt(e, i, "socksPort", 1819);
        putInt(e, i, "httpPort", 1820);
        putStr(e, i, "noizeProfile");
        putStr(e, i, "forcePeer");
        putStr(e, i, "configPath");
        putStr(e, i, "sni");
        putInt(e, i, "sysProfile", 0);
        putStr(e, i, "teamName");
        putStr(e, i, "accessToken");
        putStr(e, i, "accessEmail");
        putStr(e, i, "routesFile");
        putStr(e, i, "routesInline");
        putInt(e, i, "torMode", 0);
        putInt(e, i, "torBridges", 0);
        putStr(e, i, "torBridgeLines");
        putInt(e, i, "engineLog", 3);
        putInt(e, i, "backend", 0);
        putInt(e, i, "torSocksPort", 1821);
        putStr(e, i, "psiphonConfig");
        putStr(e, i, "psiphonRegion");
        putInt(e, i, "psiphonSocksPort", 0);
        putInt(e, i, "psiphonHttpPort", 0);
        e.apply();
    }

    private Intent recalledStart() {
        SharedPreferences p = getSharedPreferences(PREFS_LAST, MODE_PRIVATE);
        if (!p.getBoolean("has", false)) return null;
        Intent i = new Intent(this, FCAEVpnService.class);
        i.setAction(ACTION_START);
        copyInt(p, i, "protocol", 0);
        copyInt(p, i, "mode", 1);
        copyInt(p, i, "scanMode", 0);
        copyInt(p, i, "ipVersion", 4);
        copyBool(p, i, "quickReconnect", false);
        copyBool(p, i, "h2Enabled", true);
        copyBool(p, i, "echEnabled", true);
        copyBool(p, i, "lanSharing", false);
        copyInt(p, i, "socksPort", 1819);
        copyInt(p, i, "httpPort", 1820);
        copyStr(p, i, "noizeProfile");
        copyStr(p, i, "forcePeer");
        copyStr(p, i, "configPath");
        copyStr(p, i, "sni");
        copyInt(p, i, "sysProfile", 0);
        copyStr(p, i, "teamName");
        copyStr(p, i, "accessToken");
        copyStr(p, i, "accessEmail");
        copyStr(p, i, "routesFile");
        copyStr(p, i, "routesInline");
        copyInt(p, i, "torMode", 0);
        copyInt(p, i, "torBridges", 0);
        copyStr(p, i, "torBridgeLines");
        copyInt(p, i, "engineLog", 3);
        copyInt(p, i, "backend", 0);
        copyInt(p, i, "torSocksPort", 1821);
        copyStr(p, i, "psiphonConfig");
        copyStr(p, i, "psiphonRegion");
        copyInt(p, i, "psiphonSocksPort", 0);
        copyInt(p, i, "psiphonHttpPort", 0);
        return i;
    }

    private void forgetStart() {
        getSharedPreferences(PREFS_LAST, MODE_PRIVATE).edit().clear().apply();
        lastStartIntent = null;
    }

    private static void putInt(SharedPreferences.Editor e, Intent i, String k, int d) {
        e.putInt(k, i.getIntExtra(k, d));
    }
    private static void putBool(SharedPreferences.Editor e, Intent i, String k, boolean d) {
        e.putBoolean(k, i.getBooleanExtra(k, d));
    }
    private static void putStr(SharedPreferences.Editor e, Intent i, String k) {
        String v = i.getStringExtra(k);
        e.putString(k, v == null ? "" : v);
    }
    private static void copyInt(SharedPreferences p, Intent i, String k, int d) {
        i.putExtra(k, p.getInt(k, d));
    }
    private static void copyBool(SharedPreferences p, Intent i, String k, boolean d) {
        i.putExtra(k, p.getBoolean(k, d));
    }
    private static void copyStr(SharedPreferences p, Intent i, String k) {
        i.putExtra(k, p.getString(k, ""));
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
