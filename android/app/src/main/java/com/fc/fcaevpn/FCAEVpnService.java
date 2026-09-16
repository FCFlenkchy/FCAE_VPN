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
import java.util.concurrent.atomic.AtomicLong;

public class FCAEVpnService extends VpnService {

    /** TUN DNS defaults (also the reset-to values in the UI text fields).
     *  User-configurable in Settings; comma separated per family. */
    public static final String DEFAULT_TUN_DNS_V4 = "1.1.1.1,1.0.0.1";
    public static final String DEFAULT_TUN_DNS_V6 = "2606:4700:4700::1111,2606:4700:4700::1001";
    /** MainActivity's settings store. */
    private static final String PREFS_MAIN = "aether_vpn";

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
    private volatile int sessionTunMtu = 1500;
    /** True when Psiphon is this session's exit (protocol Psiphon, or
     *  Psiphon-through-tunnel egress). Set from the start intent before the
     *  core asks for the interface. */
    private volatile boolean sessionPsiphonExit = false;
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

    private final AtomicLong cleanupGeneration = new AtomicLong(0);
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
    /** Serialises TUN fd ownership between establishTunNow and teardown. */
    private final Object tunLock = new Object();
    /** Serialises interface CREATION between the early establish (startup
     *  worker thread) and the core's on-demand fd request (JNI thread). */
    private final Object tunEstablishLock = new Object();
    private volatile ParcelFileDescriptor vpnInterface;
    private volatile Runnable vpnThread; // queued native startup, never a waiting thread
    private volatile boolean running = false;
    private volatile boolean vpnPaused = false;
    private volatile boolean shuttingDown = false;

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
            if (running && !shuttingDown && !vpnPaused) PsiphonTunnelService.pollChainedRequest(FCAEVpnService.this);
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
     * Resolvers tunnel-core may use for its OWN lookups (fronting domains,
     * server-list hosts, tactics), comma delimited, IP:port.
     *
     * Mandatory: once the protect hook is installed, Psiphon stops using the
     * platform resolver, so this list is its only source of DNS servers.
     *
     * This deliberately does NOT report the carrier's resolvers. tunnel-core
     * appends whatever this returns behind its preferred alternate list, so
     * reporting the underlying network's servers left a path back to a
     * resolver the operator controls -- the one that answers UDP/53 with a
     * bogon on hijacking networks. Returning the same alternate-port public
     * resolvers here means every entry in tunnel-core's list is one we chose.
     * These are reached over protected sockets on the underlying network,
     * exactly like every other Psiphon dial.
     */
    @SuppressWarnings("unused")
    public String psiphonDnsServers() {
        return PSIPHON_BOOTSTRAP_DNS;
    }

    /** Same list as PsiphonTunnelService's DNSResolver*AlternateServers. */
    public static final String PSIPHON_BOOTSTRAP_DNS =
        "208.67.222.222:5353,9.9.9.9:9953,208.67.220.220:5353";

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
        ProxyNotification.handoffToVpn();
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
    /**
     * TUN DNS servers from the user's settings (comma separated per family).
     * Blank entries are skipped; invalid addresses are rejected by
     * addDnsServer() and skipped; if nothing valid remains the hardcoded
     * defaults go in so the interface never ends up resolver-less.
     */
    private void configureTunDns(Builder builder) {
        SharedPreferences p = getSharedPreferences(PREFS_MAIN, MODE_PRIVATE);
        String v4 = p.getString("tunDnsV4", DEFAULT_TUN_DNS_V4);
        // Psiphon exits are IPv4-only, and this session's TUN is v4-only
        // with them (see establishTunNow: no fd00::2, no ::/0 route).
        // Advertising a v6 DNS server here is not just dead weight: on
        // Android versions that route the query over the physical network
        // it LEAKS plain DNS outside the tunnel, and on the rest the
        // platform resolver stalls on the unreachable entry before falling
        // back to v4 (slow/broken DNS, version dependent). So in
        // Psiphon-exit sessions the v4 list is the whole DNS config; the
        // v6 field is ignored downstream (same policy as the other
        // Psiphon-incompatible fields).
        String v6 = sessionPsiphonExit
            ? null
            : p.getString("tunDnsV6", DEFAULT_TUN_DNS_V6);
        int added = 0;
        added += addDnsEach(builder, v4);
        added += addDnsEach(builder, v6);
        if (added == 0) {
            addDnsEach(builder, DEFAULT_TUN_DNS_V4);
        }
    }

    private static int addDnsEach(Builder builder, String csv) {
        int added = 0;
        if (csv == null) return 0;
        for (String entry : csv.split(",")) {
            String s = entry.trim();
            if (s.isEmpty()) continue;
            // VpnService only carries a bare resolver IP for plain DNS:
            // "1.1.1.1:53" and "[2606:...::1111]:53" are accepted with their
            // default port stripped; a non-53 port, a scheme (tls://…) or a
            // hostname cannot be honoured here and is skipped, not guessed.
            if (s.startsWith("[") && s.endsWith("]:53")) {
                s = s.substring(1, s.length() - 4);
            } else if (s.endsWith(":53") && s.indexOf(':') == s.lastIndexOf(':')) {
                s = s.substring(0, s.length() - 3);
            }
            try {
                builder.addDnsServer(s);
                added++;
            } catch (Exception e) {
                Log.w(TAG, "addDnsServer rejected '" + s + "': " + e.getMessage());
            }
        }
        return added;
    }

    /**
     * Create the session's TUN interface and hand its fd to the caller.
     *
     * Reached from two threads by design: the startup worker (early
     * establish, Psiphon sessions) and the core's on-demand fd provider
     * (JNI). tunEstablishLock serialises the two creations; the
     * double-check under tunLock makes the second call a no-op that
     * reuses the interface the first one created.
     */
    @SuppressWarnings("unused")
    public int establishTunNow() {
        synchronized (tunEstablishLock) {
            synchronized (tunLock) {
                if (vpnInterface != null) {
                    // Already up (early establish won the race): reuse it.
                    return vpnInterface.getFd();
                }
            }
            return establishTunLocked();
        }
    }

    private int establishTunLocked() {
        // A disconnect may have arrived while the backend was still dialling.
        // Building an interface for a session nobody wants any more is what
        // used to strand a live TUN behind a disconnected UI.
        synchronized (tunLock) {
            if (shuttingDown || pendingSessionGen != cleanupGeneration.get()) {
                Log.w(TAG, "establishTunNow: session is stale, refusing");
                return -1;
            }
        }

        try {
            Builder builder = new Builder();
            builder.setSession("FCAE VPN");
            // This session snapshot is shared with nativeStart: this is the local tun device MTU, not the
            // tunnel MTU. Must stay in sync with cfg.tun_mtu on the native
            // side.
            builder.setMtu(sessionTunMtu);
            builder.addAddress("10.0.0.2", 32);
            builder.addRoute("0.0.0.0", 0);
            // IPv6 on the interface ONLY when the exit can carry it. Psiphon
            // exits are IPv4-only (the official client's VPN is v4-only for
            // the same reason). Declaring fd00::2 + ::/0 here told Android
            // the VPN had IPv6, so every app lookup asked for AAAA, the exit
            // resolver answered it, and the app connected to the IPv6
            // literal FIRST: a CONNECT to [2a00:...]:443 which the exit
            // cannot dial and rejects as "administratively prohibited".
            // Result: apps using hostnames stalled/failed, apps with IPv4
            // literals worked, and every such attempt was one more "port
            // forward failure". With no v6 address/route Android marks the
            // VPN v4-only, AI_ADDRCONFIG suppresses AAAA, and every
            // connection goes straight to the v4 answer.
            if (!sessionPsiphonExit) {
                builder.addAddress("fd00::2", 128);
                builder.addRoute("::", 0);
            }
            try { builder.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
            configureTunDns(builder);

            ParcelFileDescriptor pfd = builder.establish();
            if (pfd == null) {
                Log.e(TAG, "establishTunNow: the system refused to create the interface");
                return -1;
            }

            // Re-check under the same lock as teardown. establish() can block;
            // a notification Disconnect that lands in that window used to
            // snapshot vpnInterface==null and then we assigned the new PFD
            // afterwards — live TUN, UI already DISCONNECTED.
            synchronized (tunLock) {
                if (shuttingDown || pendingSessionGen != cleanupGeneration.get()) {
                    closeQuiet(pfd);
                    Log.w(TAG, "establishTunNow: session went stale while establishing");
                    return -1;
                }
                vpnInterface = pfd;
                return pfd.getFd();
            }
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
    public static boolean disconnectNow() {
        FCAEVpnService current = instance;
        if (current == null) return false;
        current.fullShutdown();
        return true;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ProxyNotification.clearLegacyPsiphonNotification(this);
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
        androidx.core.content.ContextCompat.registerReceiver(this, psiphonStatsReceiver,
                new android.content.IntentFilter(PsiphonTunnelService.BROADCAST_STATS),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED);
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
        // Connecting defers Builder.establish() until SOCKS is up, so
        // vpnInterface is often still null. Still fullShutdown() — that
        // invalidates the session so a late establishTunNow cannot leave
        // a TUN up after notification Disconnect.
        if (vpnInterface == null && vpnThread == null && !running
                && !engineOpInFlight && !uiConnecting) {
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
    private synchronized void requestStart(Intent intent) {
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

    private synchronized void finishEngineOp() {
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
            startVpn(src);
        }
    }

    private synchronized void startVpn(Intent intent) {
        final int tunMtu = intent.getIntExtra("tunMtu", 1500);
        if (tunMtu < 1280 || tunMtu > 9000) {
            Log.e(TAG, "Invalid TUN MTU: " + tunMtu);
            return;
        }

        sGeneration.incrementAndGet();
        // The worker validates this after every slow step (establish,
        // nativeStart): a disconnect/pause/new connect that lands in the
        // connect window must not be overridden by a late "running=true".
        final long sessionGen = cleanupGeneration.incrementAndGet();
        vpnPaused = false;
        shuttingDown = false;
        uiConnecting = true;

        running = false;

        // The previous session is stopped on the worker thread below, NOT
        // here. startVpn() runs on the main thread (onStartCommand), and
        // nativeStop schedules reaping; nativeStart enforces the cleanup
        // barrier and may wait. Keep the command queue off the main thread.
        final ParcelFileDescriptor oldPfd;
        synchronized (tunLock) {
            oldPfd = vpnInterface;
            vpnInterface = null;
        }

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
        // 0 = defer to the engine default (config.rs DEFAULT_TOR_SOCKS_PORT);
        // MainActivity sends 0 when the field still holds the default.
        final int torSocksPort = intent.getIntExtra("torSocksPort", 0);
        sessionTunMtu = tunMtu;
        final int tunTcpSndbuf = intent.getIntExtra("tunTcpSndbuf", 256000);
        final int tunTcpRcvbuf = intent.getIntExtra("tunTcpRcvbuf", 256000);
        final boolean tunTcpAutoTuning = intent.getBooleanExtra("tunTcpAutoTuning", false);
        // tun2socks data-plane log level (FcaeT2sLog); 0 = silent.
        final int t2sLog = intent.getIntExtra("t2sLog", 0);
        final int torHttpPort = intent.getIntExtra("torHttpPort", 0);
        final boolean throughPsiphon = intent.getBooleanExtra("psiphonThroughTunnel", false);
        final String psiphonCfg    = intent.getStringExtra("psiphonConfig");
        final String psiphonRegion = intent.getStringExtra("psiphonRegion");
        final String psiphonCfgV    = (psiphonCfg == null) ? "" : psiphonCfg;
        final String psiphonRegionV = (psiphonRegion == null) ? "" : psiphonRegion;
        final int psiphonSocks = intent.getIntExtra("psiphonSocksPort", 0);
        final int psiphonHttp  = intent.getIntExtra("psiphonHttpPort", 0);
        sessionPsiphonExit = (backend == 1) || throughPsiphon;
        final String teamVal   = (teamName == null) ? "" : teamName;
        final String tokenVal  = (accessTok == null) ? "" : accessTok;
        final String emailVal  = (accessEm == null) ? "" : accessEm;
        final String routesVal = (routesF == null) ? "" : routesF;
        final String routesIVal = (routesI == null) ? "" : routesI;

        final Runnable startup = () -> {
            try {
                if (sessionGen != cleanupGeneration.get() || shuttingDown) {
                    closeQuiet(oldPfd);
                    return;
                }
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

                pendingSessionGen = sessionGen;

                // Psiphon sessions raise OUR TUN first, before the backend
                // starts. FCAEVpnService + tun2socks is the only VPN
                // interface on the device; the Psiphon library stays a
                // plain SOCKS/HTTP backend (setVpnMode(false)). Its
                // NetworkMonitor watches the default network, so in the
                // old order (backend first, TUN later) the monitor saw our
                // TUN appear only after the tunnel was live and the
                // controller terminated it on the network-change event --
                // a dead DNS/connection window on every session. With the
                // TUN up first, that event lands while no tunnel is active
                // yet and is harmless (a late one, if the validation lands
                // just after tunnel-up, is absorbed by the controller's
                // automatic reconnect).
                //
                // This cannot loop the way the old establish-up-front
                // design could: every process in this package (the
                // in-process core and the :psiphon process) is excluded
                // from the TUN by addDisallowedApplication() in the
                // Builder, and :psiphon is additionally pinned to the
                // physical network, so no handshake packet re-enters the
                // TUN. Non-Psiphon TUN sessions keep the on-demand order:
                // the core's fd provider still calls establishTunNow()
                // once the backend reports a live SOCKS endpoint. Proxy
                // mode never establishes an interface at all.
                if (mode == 1 && sessionPsiphonExit) {
                    establishTunNow();
                }

                NativeEngine.nativeInit();
                try {
                    // tun2socks runs IN-PROCESS: its Go code is linked into
                    // libfcae_go_bridge.so, which the dynamic linker loads
                    // alongside libfcaevpn_native.so. There is no tun2socks
                    // binary to locate or execute any more, and the TUN fd is
                    // supplied on demand by establishTunNow().
                    NativeEngine.nativeSetNativeLibDir(getApplicationInfo().nativeLibraryDir);
                } catch (Exception ignored) {}

                // The UI's TUN DNS servers (the same prefs configureTunDns
                // reads for the builder) also feed the core: the in-tunnel
                // Psiphon gateway then queries THESE resolvers. Blanks
                // collapse to "" so the core keeps its defaults.
                final android.content.SharedPreferences dnsPrefs =
                    getSharedPreferences(PREFS_MAIN, MODE_PRIVATE);
                String dnsV4 = dnsPrefs.getString("tunDnsV4", DEFAULT_TUN_DNS_V4);
                // Same v4-only rule as configureTunDns(): the resolver list
                // fed to the core must not name a v6 resolver that a v4-only
                // exit cannot carry.
                String dnsV6 = sessionPsiphonExit
                    ? null
                    : dnsPrefs.getString("tunDnsV6", DEFAULT_TUN_DNS_V6);
                StringBuilder dnsSb = new StringBuilder();
                if (dnsV4 != null && !dnsV4.trim().isEmpty()) dnsSb.append(dnsV4.trim());
                if (dnsV6 != null && !dnsV6.trim().isEmpty()) {
                    if (dnsSb.length() > 0) dnsSb.append(',');
                    dnsSb.append(dnsV6.trim());
                }
                final String tunDnsCfgV = dnsSb.toString();

                boolean ok = NativeEngine.nativeStart(
                    protocol, mode, lan, scanMode,
                    ipVersion, quick, noizeVal,
                    false, 16, 32, 2, 10, socksPortForMode, http,
                    peerVal, cfgPath, h2, ech,
                    sniVal, sysProfile,
                    teamVal, tokenVal, emailVal, routesVal, routesIVal,
                    torMode, torBridges, torLinesV, engineLog,
                    backend, torSocksPort, torHttpPort, throughPsiphon,
                    psiphonCfgV, psiphonRegionV, psiphonSocks, psiphonHttp,
                    tunTcpSndbuf, tunTcpRcvbuf, tunTcpAutoTuning, t2sLog, tunMtu,
                    tunDnsCfgV
                );
                if (!ok) {
                    handler.post(() -> {
                        if (sessionGen == cleanupGeneration.get()) fullShutdown();
                    });
                    return;
                }

                // The handshake is the long pole: the user can disconnect
                // (app or notification) in the middle of it. If this session
                // went stale, tear the engine down again and exit WITHOUT
                // claiming "running" — the disconnect already broadcast its
                // own state, so no extra notifyUi() here.
                if (sessionGen != cleanupGeneration.get() || shuttingDown) {
                    try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
                    sweepTun();
                    try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
                    return;
                }

                handler.post(() -> {
                    synchronized (FCAEVpnService.this) {
                        if (sessionGen != cleanupGeneration.get() || shuttingDown) return;
                        running = true;
                        uiConnecting = false;
                        synchronized (cmdLock) { engineOpInFlight = false; }
                        lastNotifText = null;
                        updateNotification();
                        handler.post(statsRunnable);
                        notifyUi();
                    }
                });

            } catch (Exception e) {
                Log.e(TAG, "Native startup failed", e);
                handler.post(() -> {
                    if (sessionGen == cleanupGeneration.get()) fullShutdown();
                });
            }
        };

        vpnThread = startup;
        NativeEngine.lifecycleExecutor.execute(startup);
    }

    private static void closeQuiet(ParcelFileDescriptor pfd) {
        if (pfd == null) return;
        try { pfd.close(); } catch (Exception ignored) {}
    }

    /** Close any TUN PFD that landed after teardown snapped a null. */
    private void sweepTun() {
        final ParcelFileDescriptor pfd;
        synchronized (tunLock) {
            pfd = vpnInterface;
            vpnInterface = null;
        }
        closeQuiet(pfd);
    }

    private synchronized void fullShutdown() {
        // Idempotent teardown. Disconnect (UI or notification), onRevoke
        // and onDestroy can ALL fire for the same session, and the first
        // call's cleanup thread may already be past its generation check
        // when the second call lands — the second run then repeated
        // nativeStopBegin/nativeStop, i.e. the tun2socks teardown ran
        // twice ("tun2socks 2 times torn down"). All fields below are
        // already cleared/poisoned by the first pass, so a repeat call has
        // nothing to do.
        if (shuttingDown && !running && vpnThread == null
                && vpnInterface == null) {
            return;
        }
        PsiphonTunnelService.stopBound(this);
        sGeneration.incrementAndGet();
        final long myGen = cleanupGeneration.incrementAndGet();
        running = false;
        vpnPaused = false;
        uiConnecting = false;
        shuttingDown = true;
        pendingSessionGen = -1;
        synchronized (cmdLock) {
            queuedStart = null;
            engineOpInFlight = true;
        }
        forgetStart();

        vpnThread = null;
        final ParcelFileDescriptor pfd;
        synchronized (tunLock) {
            pfd = vpnInterface;
            vpnInterface = null;
        }
        lastStartIntent = null;

        // Close our VpnService fd immediately. The native dup is a
        // different number; abort (nativeStopBegin) closes that without
        // waiting on Go. Together that drops the kernel TUN in ~1ms.
        closeQuiet(pfd);
        try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}
        sweepTun();

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

        // 2. Reap only. TUN and UI are already down — do not join the
        // worker (join(0) waits forever in Java; join(50) was a 50ms stall).
        NativeEngine.lifecycleExecutor.execute(() -> {
            if (myGen != cleanupGeneration.get()) return;
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            sweepTun();
            handler.post(() -> {
                synchronized (FCAEVpnService.this) {
                    if (myGen != cleanupGeneration.get()) return;
                    synchronized (cmdLock) {
                        engineOpInFlight = false;
                        queuedStart = null;
                    }
                    stopSelf();
                    ProxyNotification.notifyCleanupComplete(this);
                }
            });
            // Activity absence/recreation is not process shutdown. Never free
            // the global FFI or kill a process that may already be reconnecting.
        });
    }

    private synchronized void pauseVpn() {
        sGeneration.incrementAndGet();
        // Invalidate any in-flight startVpn() session: without this bump a
        // pause landing in the connect window would not stop the worker, and
        // it would resurrect "running" (live TUN) after the pause.
        final long myGen = cleanupGeneration.incrementAndGet();
        if (lastStartIntent != null && lastStartIntent.getBooleanExtra("psiphonThroughTunnel", false)) {
            PsiphonTunnelService.stopBound(this);
        }
        running = false;
        vpnPaused = true;
        uiConnecting = false;
        pendingSessionGen = -1;
        synchronized (cmdLock) {
            engineOpInFlight = true;
        }

        vpnThread = null;
        final ParcelFileDescriptor pfd;
        synchronized (tunLock) {
            pfd = vpnInterface;
            vpnInterface = null;
        }
        closeQuiet(pfd);
        try { NativeEngine.nativeStopBegin(); } catch (Exception ignored) {}

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

        // 2. Reap only. TUN already down. No join.
        //
        // freeNativeOnce() is deliberately absent: pause is resumable, and
        // releasing the library here meant resuming had to re-init a
        // shut-down FFI.
        NativeEngine.lifecycleExecutor.execute(() -> {
            if (myGen != cleanupGeneration.get()) return;
            try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
            handler.post(() -> {
                if (myGen == cleanupGeneration.get()) finishEngineOp();
            });
        });
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

    private Intent lastPsiphonStats;
    private final android.content.BroadcastReceiver psiphonStatsReceiver = new android.content.BroadcastReceiver() {
        @Override public void onReceive(android.content.Context context, Intent intent) {
            if (shuttingDown || !running || !PsiphonTunnelService.isCurrentBroadcast(intent)) return;
            lastPsiphonStats = new Intent(intent);
            updateNotification();
        }
    };

    private void updateNotification() {
        if (uiConnecting) {
            lastNotifText = null;
            notification.show("FCAE VPN — Connecting...", VpnNotification.BUTTONS_CONNECTING);
        } else if (vpnPaused) {
            lastNotifText = null;
            notification.show("FCAE VPN — Stopped (tap Start to resume)", VpnNotification.BUTTONS_PAUSED);
        } else if (running) {
            if (PsiphonTunnelService.hasActiveBinding() && lastPsiphonStats != null
                    && PsiphonTunnelService.isCurrentBroadcast(lastPsiphonStats)) {
                String text = ProxyNotification.psiphonTrafficText(lastPsiphonStats);
                if (!text.equals(lastNotifText)) {
                    lastNotifText = text;
                    notification.show(text, VpnNotification.BUTTONS_RUNNING);
                }
                return;
            }
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
        putBool(e, i, "psiphonThroughTunnel", false);
        putInt(e, i, "tunMtu", 1500);
        putInt(e, i, "tunTcpSndbuf", 256000);
        putInt(e, i, "tunTcpRcvbuf", 256000);
        putBool(e, i, "tunTcpAutoTuning", false);
        putInt(e, i, "t2sLog", 0);
        putInt(e, i, "torHttpPort", 0);
        putInt(e, i, "torSocksPort", 0); // 0 = engine default (defer)
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
        copyBool(p, i, "psiphonThroughTunnel", false);
        copyInt(p, i, "tunMtu", 1500);
        copyInt(p, i, "tunTcpSndbuf", 256000);
        copyInt(p, i, "tunTcpRcvbuf", 256000);
        copyBool(p, i, "tunTcpAutoTuning", false);
        copyInt(p, i, "t2sLog", 0);
        copyInt(p, i, "torHttpPort", 0);
        copyInt(p, i, "torSocksPort", 0); // 0 = engine default (defer)
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
        unregisterReceiver(psiphonStatsReceiver);
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
