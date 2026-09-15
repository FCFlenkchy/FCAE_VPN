package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ca.psiphon.PsiphonTunnel;

/**
 * Official Psiphon AAR ({@code ca.psiphon:psiphontunnel}) in an isolated
 * process ({@code :psiphon}) so its Go runtime ({@code libgojni.so}) never
 * shares an address space with tun2socks ({@code libfcae_go_bridge.so}).
 * Two Go runtimes in one process SIGSEGV at {@code dlopen}.
 *
 * Sockets in this process are bound to the underlying Wi‑Fi/cellular
 * network ({@code bindProcessToNetwork}) so a TUN raised in the UI
 * process cannot capture them. The UI process then points tun2socks at
 * the local SOCKS port this service broadcasts.
 */
public class PsiphonTunnelService extends Service implements PsiphonTunnel.HostService {

    private static final String TAG = "FCAE_PSI";
    public static final String ACTION_START = "com.fc.fcaevpn.PSI_START";
    public static final String ACTION_STOP  = "com.fc.fcaevpn.PSI_STOP";
    public static final String BROADCAST_READY = "com.fc.fcaevpn.PSI_READY";
    public static final String BROADCAST_FAILED = "com.fc.fcaevpn.PSI_FAILED";
    // Staged connect progress (like the Tor bootstrap percentage): INTEGER
    // stage + short label. The label is a full status phrase in the same
    // vocabulary as the Aether engine statuses (CONNECTING / ESTABLISHING
    // TUNNEL / CONNECTED) — no protocol tag baked into the text.
    public static final String BROADCAST_STAGE = "com.fc.fcaevpn.PSI_STAGE";
    public static final String BROADCAST_STOPPED = "com.fc.fcaevpn.PSI_STOPPED";
    public static final String BROADCAST_LOG = "com.fc.fcaevpn.PSI_LOG";
    // Live telemetry while the tunnel is up: byte rates, cumulative totals
    // and tunnel RTT measured through Psiphon's own local HTTP proxy.
    public static final String BROADCAST_STATS = "com.fc.fcaevpn.PSI_STATS";
    public static final String EXTRA_SOCKS = "socksPort";
    public static final String EXTRA_HTTP = "httpPort";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_REGIONS = "regions";
    public static final String EXTRA_LOG = "log";
    public static final String EXTRA_STAGE = "psiphonStage";
    public static final String EXTRA_STAGE_LABEL = "psiphonStageLabel";
    public static final String EXTRA_RTT = "rttMs";
    public static final String EXTRA_UP_BPS = "upBps";
    public static final String EXTRA_DOWN_BPS = "downBps";
    public static final String EXTRA_TOTAL_UP = "totalUp";
    public static final String EXTRA_TOTAL_DOWN = "totalDown";

    private static final String CHANNEL_ID = "fcaevpn_psiphon";
    private static final int NOTIF_ID = 3;

    // Legacy PUBLIC remote server list + signature key from the open-source
    // Psiphon 3 clients (same values community clients embed). Bootstrap
    // fallback for builds without provisioning; may be retired upstream.
    private static final String DEFAULT_SERVER_LIST_URL =
            "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed";
    // Standard ed25519 public key verifying individually signed server
    // entries (DSL fetches, server-pushed updates). Without it every tunneled
    // DSL fetch fails with "VerifySignature: missing public key". Same value
    // the open-source Psiphon clients embed; a config that sets its own wins.
    private static final String DEFAULT_SERVER_ENTRY_SIGNATURE_KEY =
            "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=";
    private static final String DEFAULT_SERVER_LIST_SIGNATURE_KEY =
            "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH"
          + "5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5"
          + "OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot"
          + "LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6"
          + "/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G"
          + "stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O"
          + "geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8"
          + "u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz"
          + "31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal"
          + "KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=";

    // Transport families (indices into TRANSPORT_GROUPS in getPsiphonConfig).
    // 0 = Auto: no LimitTunnelProtocols, tunnel-core uses its full set.
    private int transport = 0;

    private PsiphonTunnel tunnel;
    private String region = "";
    private volatile String lastRegions = "";
    private String upstreamProxy = "";
    private int wantSocks;
    private int wantHttp;
    private final AtomicInteger socksPort = new AtomicInteger(0);
    private final AtomicInteger httpPort = new AtomicInteger(0);
    // Cumulative tunneled bytes, from onBytesTransferred (EmitBytesTransferred
    // notices — the callback reports DELTAS since the previous notice, so
    // accumulate). Surfaced in the foreground notification.
    private final AtomicLong bytesUp = new AtomicLong(0);
    private final AtomicLong bytesDown = new AtomicLong(0);
    private volatile long lastCounterNotifAt = 0;
    // UI set "psiTunMode" on the start intent (TUN selected), and chain mode
    // is detected from upstreamProxy. In both cases another foreground
    // service already owns the tray entry (VpnNotification/ProxyNotification)
    // — this service detaches from the foreground after READY so the user
    // sees ONE notification per session, not two.
    private volatile boolean psiTunMode = false;
    private volatile boolean notifDetached = false;
    private volatile boolean stopping;
    // True while a start thread is inside startTunneling(); true alone
    // (psiphonUp) once the library reported itself started. Together they
    // serialize duplicate ACTION_PSIPHON_START deliveries: the library
    // wrapper begins EVERY start by stopping the previous instance
    // ("stopping Psiphon library" is logged unconditionally), so re-entering
    // while a controller is mid-boot kills it — that was the tight
    // "starting tunnel → stopping Psiphon library" crash loop.
    private volatile boolean startInFlight;
    private volatile boolean psiphonUp;
    private final Handler logHandler = new Handler(Looper.getMainLooper());
    private final StringBuilder logBuf = new StringBuilder();
    private final Runnable flushLogs = this::flushLogs;

    /**
     * Slow-connect heartbeat: while startTunneling() is still dialing this
     * emits an "establishing tunnel" line every 10 s so the UI/log never
     * looks dead on a slow or filtered egress. Self-terminates once the
     * tunnel is up, stopping, or the start thread has exited.
     */
    private volatile long dialStartedAtMs = 0L;
    private final Runnable dialHeartbeat = new Runnable() {
        @Override public void run() {
            if (startInFlight && !psiphonUp && !stopping) {
                long secs = (System.currentTimeMillis() - dialStartedAtMs) / 1000L;
                emitLog("establishing tunnel, elapsed " + secs + "s");
                logHandler.postDelayed(this, 10000L);
            }
        }
    };

    // Last measured tunnel RTT in ms (0 = no measurement yet) and the
    // background stats publisher started from onConnected().
    private volatile int lastRttMs = 0;
    private Thread statsThread;
    // Auto-recovery state for dead servers (see maybeAutoReconnect).
    private volatile int autoReconnectsDone = 0;
    private volatile long lastAutoReconnectAt = 0L;
    private volatile String lastEmbeddedList = "";

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
        // startForegroundService() times out if this process (class load of
        // libgojni.so, bind, etc.) takes too long. Promote before any of that.
        promoteForeground("FCAE Psiphon — Starting…");
        bindToUnderlyingNetwork();
        tunnel = PsiphonTunnel.newPsiphonTunnel(this);
        tunnel.setVpnMode(false);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Every startForegroundService() delivery must call startForeground,
        // including ACTION_STOP (disconnect always used that API).
        boolean stop = intent != null && ACTION_STOP.equals(intent.getAction());
        promoteForeground(stop ? "FCAE Psiphon — Stopping…" : "FCAE Psiphon — Connecting…");
        if (stop) {
            stopNow();
            return START_NOT_STICKY;
        }
        if (intent == null) {
            // Sticky restart after this process was killed: the user's
            // region/transport/ports/upstream extras died with it, so
            // replaying a blank "Auto" config would start a tunnel nobody
            // asked for and — paired with start failures below — loop
            // forever at the system's ~1s restart cadence. MainActivity is
            // the only legitimate source of psiphon starts; exit quietly.
            if (!psiphonUp && !startInFlight) {
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }
            return START_NOT_STICKY;
        }
        if (startInFlight || psiphonUp) {
            // Duplicate start (double-tap, poll re-fire, redelivery). The
            // wrapper stops the running instance before every new start, so
            // a second start mid-boot aborts the first controller — repeat
            // deliveries turned into the connect/stop crash loop. The UI
            // always stops before reconfiguring, so ignore extras here.
            emitLog("start ignored: tunnel already " + (startInFlight ? "starting" : "running"));
            flushLogs();
            return START_NOT_STICKY;
        }
        {
            String r = intent.getStringExtra("psiphonRegion");
            region = r == null ? "" : r.trim();
            transport = intent.getIntExtra("psiphonTransport", 0);
            wantSocks = intent.getIntExtra("psiphonSocksPort", 0);
            wantHttp = intent.getIntExtra("psiphonHttpPort", 0);
            String up = intent.getStringExtra("upstreamProxy");
            upstreamProxy = up == null ? "" : up.trim();
            psiTunMode = intent.getBooleanExtra("psiTunMode", false);
        }
        notifDetached = false;
        stopping = false;
        startInFlight = true;
        psiphonUp = false;
        bytesUp.set(0);
        bytesDown.set(0);
        broadcastStage(1, "CONNECTING");
        // Read the embedded server-entry list once per start: it feeds both
        // the log line and startTunneling() (two reads would double-log the
        // "importing embedded server entries" notice).
        final String embeddedList = readEmbeddedServerList();
        // Fresh user-initiated start: reset the auto-recovery budget.
        lastEmbeddedList = embeddedList;
        autoReconnectsDone = 0;
        lastAutoReconnectAt = 0L;
        emitLog("starting tunnel" + (region.isEmpty() ? " (region Auto)" : " (region " + region + ")")
                + (upstreamProxy.isEmpty() ? "" : " via " + upstreamProxy)
                + sourceSummary(embeddedList));
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try {
                // The embedded list is the body of an encoded server entry
                // list (same format as a remote server_list payload); ""
                // falls back to whatever the datastore still holds plus any
                // remote server list configured in getPsiphonConfig().
                emitLog("startTunneling: calling");
                if (t != null) t.startTunneling(embeddedList);
                else throw new Exception("Psiphon tunnel not created");
                emitLog("startTunneling: returned");
                psiphonUp = true;
            } catch (Throwable err) {
                // Throwable, not Exception: gomobile native load failures
                // (UnsatisfiedLinkError, ExceptionInInitializerError) are
                // Errors — catching Exception only lets the thread die
                // silently with nothing in the log, which is exactly the
                // "connecting / starting tunnel / stopping, then nothing"
                // symptom. The class name identifies the failure.
                Log.e(TAG, "startTunneling failed", err);
                String what = err.getClass().getSimpleName() + ": "
                        + (err.getMessage() == null ? "(no message)" : err.getMessage());
                emitLog("start failed: " + what);
                broadcastFailed(what);
                stopNow();
            } finally {
                startInFlight = false;
            }
        }, "FCAE-PsiStart").start();
        dialStartedAtMs = System.currentTimeMillis();
        logHandler.removeCallbacks(dialHeartbeat);
        logHandler.postDelayed(dialHeartbeat, 10000L);
        return START_NOT_STICKY;
    }

    // startForeground(int, Notification) (no type) is deprecated on API 34,
    // but is the correct call on < 34 — same deliberate fallback as
    // FCAEVpnService. Suppressed here rather than gated to keep one call site.
    @SuppressWarnings("deprecation")
    private void promoteForeground(String text) {
        Notification n = buildNotification(text);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIF_ID, n);
        }
    }

    private void stopNow() {
        // Idempotent: a start failure, onExiting() and an ACTION_STOP can
        // all land within the same second; only the first may run the
        // teardown (a second t.stop() would block on the already-stopping
        // controller and double the "stopping" noise).
        if (stopping) return;
        stopping = true;
        logHandler.removeCallbacks(dialHeartbeat);
        Thread st = statsThread;
        if (st != null) st.interrupt();
        // Only touch the native library when a tunnel is actually up or a
        // start is in flight (whose blocked startTunneling() needs stop()
        // to unblock it). After a FAILED start the controller never ran;
        // calling the wrapper's stop() then — its stopPsiphon() emits the
        // "stopping Psiphon library" line even for a null controller and
        // would needlessly re-enter libgojni on an already-dying service.
        final boolean needsLibraryStop = psiphonUp || startInFlight;
        psiphonUp = false;
        emitLog("stopping");
        flushLogs();
        try { stopForeground(STOP_FOREGROUND_REMOVE); } catch (Exception ignored) {}
        broadcastStopped();
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try { if (t != null && needsLibraryStop) t.stop(); } catch (Throwable ignored) {}
        }, "FCAE-PsiStop").start();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopping = true;
        logHandler.removeCallbacks(dialHeartbeat);
        Thread st = statsThread;
        if (st != null) st.interrupt();
        try { if (tunnel != null && (psiphonUp || startInFlight)) tunnel.stop(); } catch (Throwable ignored) {}
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm != null) cm.bindProcessToNetwork(null);
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    /** Keep this process off the VPN so Psiphon can reach the internet. */
    private void bindToUnderlyingNetwork() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return;
            Network chosen = null;
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities cap = cm.getNetworkCapabilities(n);
                if (cap == null) continue;
                if (!cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                if (cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                chosen = n;
                if (cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        || cap.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    break;
                }
            }
            if (chosen != null) {
                cm.bindProcessToNetwork(chosen);
                Log.i(TAG, "bound :psiphon to underlying network " + chosen);
            }
        } catch (Exception e) {
            Log.w(TAG, "bindProcessToNetwork: " + e.getMessage());
        }
    }

    // ── HostService ──────────────────────────────────────────────────────

    @Override
    public Context getContext() { return this; }

    @Override
    public String getPsiphonConfig() {
        try {
            JSONObject o = new JSONObject();
            o.put("PropagationChannelId", "FFFFFFFFFFFFFFFF");
            o.put("SponsorId", "FFFFFFFFFFFFFFFF");
            o.put("ClientVersion", "1");
            o.put("TunnelPoolSize", 1);
            o.put("DisableLocalSocksAuth", true);
            o.put("EmitDiagnosticNotices", true);
            o.put("UseIndistinguishableTLS", true);
            o.put("AllowDefaultDNSResolverWithBindToDevice", true);
            // Frequent byte-count notices: they feed onBytesTransferred,
            // which drives the notification counters. Without this a working
            // tunnel shows 0 B.
            o.put("EmitBytesTransferred", true);
            // In-proxy client participation dials WebRTC connections through
            // STUN while the tunnel is still connecting; every STUN timeout
            // then lands in the log ("Failed get server reflexive
            // address"). Off — the tunnel works without it.
            o.put("InproxyEnabled", false);
            o.put("InproxyAllowClient", false);
            // Transport family restriction: Auto (0) leaves the field out so
            // tunnel-core tries its full default protocol set.
            String[] protocols = transportProtocols(transport);
            if (protocols.length > 0) {
                org.json.JSONArray a = new org.json.JSONArray();
                for (String pr : protocols) a.put(pr);
                o.put("LimitTunnelProtocols", a);
            }
            File root = new File(getFilesDir(), "psiphon");
            if (!root.exists() && !root.mkdirs()) {
                Log.w(TAG, "could not create " + root);
            }
            o.put("DataRootDirectory", root.getAbsolutePath());
            if (!region.isEmpty()) o.put("EgressRegion", region);
            if (wantSocks > 0) o.put("LocalSocksProxyPort", wantSocks);
            if (wantHttp > 0) o.put("LocalHttpProxyPort", wantHttp);
            // "Psiphon through the tunnel": all of Psiphon's own dials
            // (servers, API calls, remote server list fetches) go through
            // this proxy — Aether's local SOCKS. This field used to be
            // logged and then dropped, so Psiphon always dialled the
            // underlay directly and the chain silently degraded to plain
            // Psiphon. tunnel-core accepts socks5://, socks4a:// and
            // http:// here (see psiphon/upstreamproxy/README.md upstream).
            if (!upstreamProxy.isEmpty()) {
                o.put("UpstreamProxyURL", normalizeUpstreamProxyUrl(upstreamProxy));
            }
            // Entry-level signature verification (see the constant's comment).
            if (!o.has("ServerEntrySignaturePublicKey")) {
                o.put("ServerEntrySignaturePublicKey", DEFAULT_SERVER_ENTRY_SIGNATURE_KEY);
            }
            // Out-of-band server entries: the LEGACY PUBLIC remote server
            // list (the URL + signature key the open-source Psiphon 3
            // clients shipped — community clients like Oblivion still embed
            // them). This is what makes an unprovisioned build connect on a
            // fresh datastore instead of sitting on CandidateServers count 0.
            // There is no UI for overriding it any more; a bundled
            // assets/psiphon_servers.txt (read in readEmbeddedServerList())
            // takes precedence as the embedded source. Legacy infrastructure:
            // partner provisioning remains the supported long-term path.
            o.put("RemoteServerListUrl", DEFAULT_SERVER_LIST_URL);
            o.put("RemoteServerListSignaturePublicKey", DEFAULT_SERVER_LIST_SIGNATURE_KEY);
            return o.toString();
        } catch (Exception e) {
            Log.e(TAG, "getPsiphonConfig: " + e.getMessage());
            return "{}";
        }
    }

    /**
     * Map a transport spinner index to tunnel-core LimitTunnelProtocols
     * values. Index 0 (Auto) returns an empty array: omit the field so the
     * full default protocol set is used. Names are the exact strings from
     * tunnel-core's config.go.
     */
    static String[] transportProtocols(int selection) {
        switch (selection) {
            case 1: return new String[]{"SSH", "OSSH"};
            case 2: return new String[]{"QUIC-OSSH"};
            case 3: return new String[]{
                    "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
                    "UNFRONTED-MEEK-SESSION-TICKET-OSSH"};
            case 4: return new String[]{"FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH"};
            default: return new String[0];
        }
    }

    /** tunnel-core dropped the bare "socks" scheme; map it to socks5. */
    static String normalizeUpstreamProxyUrl(String url) {
        String u = url.trim();
        if (u.regionMatches(true, 0, "socks://", 0, 8)) {
            return "socks5://" + u.substring(8);
        }
        return u;
    }

    /**
     * One-line summary of which server-entry sources are active. Takes the
     * already-read embedded list (see onStartCommand) rather than a path:
     * the asset location is fixed (assets/psiphon_servers.txt), and the
     * remote server list is always injected by getPsiphonConfig().
     */
    private String sourceSummary(String embeddedList) {
        java.util.List<String> s = new java.util.ArrayList<>();
        if (!embeddedList.isEmpty()) s.add("embedded:assets/psiphon_servers.txt");
        s.add("remote-list:" + DEFAULT_SERVER_LIST_URL);
        return " [server entries: " + String.join(", ", s) + "]";
    }

    /**
     * Load the embedded server entry list for startTunneling().
     *
     * Optional bundled asset: assets/psiphon_servers.txt. Returns "" when it
     * is absent or empty; the config's legacy public remote server list then
     * bootstraps.
     */
    private String readEmbeddedServerList() {
        // psiphon_servers.txt is NOT in the repo by default (an empty
        // placeholder would be dead weight and imply we ship entries). If
        // you bundle entries — your own servers or Psiphon-Labs
        // provisioning, never entries extracted from other clients — add
        // assets/psiphon_servers.txt to the app module and it is picked up
        // automatically. Without it, the config's legacy public remote
        // server list is the bootstrap source.
        try (java.io.InputStream in = getAssets().open("psiphon_servers.txt")) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            if (out.size() > 0) {
                emitLog("importing embedded server entries from assets/psiphon_servers.txt"
                        + " (" + out.size() + " bytes)");
                return out.toString("UTF-8");
            }
        } catch (Exception ignored) {
            // No bundled asset — the normal case.
        }
        return "";
    }

    private static byte[] readAll(File f) throws Exception {
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static String firstNonEmpty(String... values) {
        for (String v : values) {
            if (v != null && !v.trim().isEmpty()) return v.trim();
        }
        return "";
    }

    @Override
    public void bindToDevice(long fileDescriptor) throws PsiphonTunnel.Exception {
        // Not a VpnService. Sockets are excluded via bindProcessToNetwork.
        // Closing would recycle the fd out from under Go — leave it.
        if (fileDescriptor <= 0) {
            throw new PsiphonTunnel.Exception("bindToDevice: invalid fd");
        }
    }

    @Override
    public void onDiagnosticMessage(String message) {
        // Staged-status hooks. Diagnostic notices arrive as raw JSON here;
        // the wrapper's own lifecycle lines arrive as plain text. All of it
        // is cheap substring work on a low-rate channel.
        if (!stopping && message != null) {
            if (message.contains("starting Psiphon library")) {
                broadcastStage(2, "CONNECTING");
            } else if (message.contains("\"noticeType\":\"ConnectingServer\"")) {
                broadcastStage(3, "ESTABLISHING TUNNEL");
            } else if (message.contains("\"noticeType\":\"ConnectedServer\"")
                    || message.contains("\"noticeType\":\"ActiveTunnel\"")) {
                broadcastStage(4, "ESTABLISHING TUNNEL");
            }
        }
        // Dead-server detection: tunnel-core counts failed port-forwards per
        // server ("port forward failures for <server-id>: N") but never
        // rotates off the broken server on its own. Parse N as the digits
        // after the FIRST ':' following the phrase — lastIndexOf(':') would
        // land inside the trailing timestamp and false-trigger.
        int ff = message.indexOf("port forward failures for");
        if (ff >= 0) {
            int idx = message.indexOf(':', ff + 25);
            if (idx >= 0) {
                int end = idx + 1;
                while (end < message.length() && Character.isDigit(message.charAt(end))) end++;
                if (end > idx + 1) {
                    try {
                        maybeAutoReconnect(Integer.parseInt(message.substring(idx + 1, end)));
                    } catch (NumberFormatException ignored) {}
                }
            }
        }
        emitLog(message);
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        socksPort.set(port);
        if (!stopping) broadcastStage(5, "ESTABLISHING TUNNEL");
        emitLog("SOCKS 127.0.0.1:" + port);
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        httpPort.set(port);
        emitLog("HTTP 127.0.0.1:" + port);
    }

    @Override
    public void onBytesTransferred(long sent, long received) {
        // Values are deltas since the previous notice — accumulate.
        if (sent <= 0 && received <= 0) return;
        bytesUp.addAndGet(Math.max(0, sent));
        bytesDown.addAndGet(Math.max(0, received));
        if (!notifDetached) maybeUpdateCounterNotification();
    }

    /** Refresh the notification's byte counters at most every 2 seconds. */
    private void maybeUpdateCounterNotification() {
        long now = android.os.SystemClock.elapsedRealtime();
        if (stopping || now - lastCounterNotifAt < 2000) return;
        lastCounterNotifAt = now;
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm == null) return;
            int s = socksPort.get();
            String base = s > 0
                    ? "FCAE Psiphon — SOCKS 127.0.0.1:" + s
                    : "FCAE Psiphon — Connecting…";
            nm.notify(NOTIF_ID, buildNotification(
                    base + "  ·  \u2191" + fmtBytes(bytesUp.get())
                            + " \u2193" + fmtBytes(bytesDown.get())));
        } catch (Exception ignored) {}
    }

    private static String fmtBytes(long b) {
        if (b < 1024) return b + " B";
        double v = b;
        if ((v /= 1024) < 1024) return String.format(java.util.Locale.US, "%.1f kB", v);
        if ((v /= 1024) < 1024) return String.format(java.util.Locale.US, "%.1f MB", v);
        return String.format(java.util.Locale.US, "%.2f GB", v / 1024);
    }

    @Override
    public void onAvailableEgressRegions(List<String> regions) {
        if (regions == null || regions.isEmpty()) return;
        lastRegions = String.join(",", regions);
        emitLog("regions: " + lastRegions);
        Intent i = new Intent(BROADCAST_READY);
        i.setPackage(getPackageName());
        i.putExtra("regionsOnly", true);
        i.putExtra(EXTRA_REGIONS, lastRegions);
        sendBroadcast(i);
    }

    @Override
    public void onConnected() {
        if (stopping) return;
        int s = socksPort.get();
        if (s <= 0) s = tunnel.getLocalSocksProxyPort();
        socksPort.set(s);
        emitLog("connected, SOCKS 127.0.0.1:" + s);
        flushLogs();
        // One tray entry per session: TUN mode has VpnNotification and the
        // egress-chain has the engine's foreground service — this service
        // detaches instead of stacking a second notification on top. The
        // service itself stays alive-started; the session owns a foreground
        // notification through that other service the whole time.
        boolean ownerElsewhere = psiTunMode || !upstreamProxy.isEmpty();
        if (ownerElsewhere) {
            notifDetached = true;
            try { stopForeground(STOP_FOREGROUND_DETACH); } catch (Exception ignored) {}
        } else {
            try {
                NotificationManager nm = getSystemService(NotificationManager.class);
                if (nm != null) nm.notify(NOTIF_ID, buildNotification(
                        "FCAE Psiphon — SOCKS 127.0.0.1:" + s));
            } catch (Exception ignored) {}
        }
        Intent i = new Intent(BROADCAST_READY);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_SOCKS, s);
        i.putExtra(EXTRA_HTTP, httpPort.get());
        sendBroadcast(i);
        startStatsLoop();
    }

    @Override
    public void onExiting() {
        emitLog("exiting");
        flushLogs();
        if (!stopping) {
            broadcastFailed("Psiphon exited");
            stopNow();
        }
    }

    /** Format a notice for the UI pane. Raw JSON is collapsed to noticeType. */
    private static String formatNotice(String message) {
        if (message == null) return "";
        String m = message.trim();
        if (m.isEmpty()) return "";
        if (m.startsWith("{") && m.contains("\"noticeType\"")) {
            try {
                JSONObject o = new JSONObject(m);
                String type = o.optString("noticeType", "");
                Object data = o.opt("data");
                if (!type.isEmpty() && data != null) return type + " " + data;
                if (!type.isEmpty()) return type;
            } catch (Exception ignored) {}
        }
        return m;
    }

    private void emitLog(String message) {
        String line = formatNotice(message);
        if (line.isEmpty()) return;
        Log.i(TAG, line);
        synchronized (logBuf) {
            if (logBuf.length() > 0) logBuf.append('\n');
            logBuf.append("[psiphon] ").append(line);
            if (logBuf.length() > 12000) {
                logBuf.delete(0, logBuf.length() - 8000);
            }
        }
        // Every line is broadcast immediately. A 150 ms debounce previously
        // batched upstream JSON notices — and silently swallowed the last
        // diagnostics when the process died inside that window. Notice volume
        // here is low (BytesTransferred is excluded upstream), so immediate
        // flush costs nothing and the log survives a native crash intact.
        logHandler.removeCallbacks(flushLogs);
        flushLogs();
    }

    private void flushLogs() {
        logHandler.removeCallbacks(flushLogs);
        String chunk;
        synchronized (logBuf) {
            if (logBuf.length() == 0) return;
            chunk = logBuf.toString();
            logBuf.setLength(0);
        }
        Intent i = new Intent(BROADCAST_LOG);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_LOG, chunk);
        sendBroadcast(i);
    }

    /**
     * While the tunnel is up, publishes byte rates, cumulative totals and
     * tunnel RTT every 2 s as BROADCAST_STATS. RTT is one HTTP round trip
     * through Psiphon's own local proxy (absolute-URI HEAD against Google's
     * generate_204 edge), so it measures the actual tunnel latency to the
     * internet — the engine's RTT field is not available on this path.
     */
    private void startStatsLoop() {
        Thread prev = statsThread;
        if (prev != null && prev.isAlive()) return;
        lastRttMs = 0;
        Thread t = new Thread(() -> {
            long prevUp = bytesUp.get(), prevDown = bytesDown.get();
            long prevAt = System.currentTimeMillis();
            int rttAttempts = 0;
            long nextRttProbeAt = 0L;
            while (psiphonUp && !stopping) {
                try {
                    Thread.sleep(2000L);
                } catch (InterruptedException ie) {
                    return;
                }
                long now = System.currentTimeMillis();
                long up = bytesUp.get(), down = bytesDown.get();
                long dt = Math.max(1L, now - prevAt);
                long upBps = (up - prevUp) * 1000L / dt;
                long downBps = (down - prevDown) * 1000L / dt;
                prevUp = up;
                prevDown = down;
                prevAt = now;
                // RTT is measured ONCE per connect (probe now, then a small
                // retry budget with backoff) instead of every 2 s: periodic
                // probing spams per-second notices and, on a broken server,
                // inflates the 'port forward failures' counter.
                int port = httpPort.get();
                if (lastRttMs == 0 && rttAttempts < 4 && port > 0 && now >= nextRttProbeAt) {
                    rttAttempts++;
                    nextRttProbeAt = now + (1L << Math.min(rttAttempts, 3)) * 1000L;
                    Integer r = probeTunnelRtt(port);
                    if (r != null) lastRttMs = r;
                }
                Intent i = new Intent(BROADCAST_STATS);
                i.setPackage(getPackageName());
                i.putExtra(EXTRA_RTT, lastRttMs);
                i.putExtra(EXTRA_UP_BPS, upBps);
                i.putExtra(EXTRA_DOWN_BPS, downBps);
                i.putExtra(EXTRA_TOTAL_UP, up);
                i.putExtra(EXTRA_TOTAL_DOWN, down);
                sendBroadcast(i);
            }
        }, "FCAE-PsiStats");
        statsThread = t;
        t.start();
    }

    /** One tunnel round trip through the local HTTP proxy, or null. */
    private Integer probeTunnelRtt(int port) {
        java.net.Socket s = new java.net.Socket();
        try {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 1500);
            s.setSoTimeout(1500);
            long t0 = System.currentTimeMillis();
            s.getOutputStream().write(("HEAD http://www.gstatic.com/generate_204"
                    + " HTTP/1.1\r\nHost: www.gstatic.com\r\n"
                    + "Connection: close\r\n\r\n").getBytes());
            if (s.getInputStream().read() < 0) return null;
            return (int) Math.max(1L, System.currentTimeMillis() - t0);
        } catch (Exception e) {
            return null;
        } finally {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * A tunnel whose server cannot reach ANY destination is worse than a
     * reconnect: tunnel-core only COUNTS failed port-forwards but never
     * rotates off the broken server, so the session sits CONNECTED and
     * blackholes every connection forever. Treat many failures with
     * essentially no downloaded bytes as a dead server and restart the
     * tunnel (fresh candidate selection), capped to two attempts with a
     * 30 s cooldown to avoid churn on a globally bad network. Shown as
     * CONNECTING/ESTABLISHING — recovery, not a user-visible disconnect.
     */
    private void maybeAutoReconnect(int failures) {
        if (stopping || !psiphonUp) return;
        if (failures < 20) return;
        if (autoReconnectsDone >= 2) return;
        if (bytesDown.get() > 15000L) return;  // real traffic flows: alive
        long now = System.currentTimeMillis();
        if (now - lastAutoReconnectAt < 30000L) return;
        autoReconnectsDone++;
        lastAutoReconnectAt = now;
        emitLog("egress unreachable (" + failures + " failed port-forwards)"
                + " — switching psiphon server (attempt " + autoReconnectsDone + "/2)");
        psiphonUp = false;
        broadcastStage(1, "CONNECTING");
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try {
                if (stopping) return;
                startInFlight = true;
                try { if (t != null) t.stop(); } catch (Throwable ignored) {}
                if (stopping) return;
                dialStartedAtMs = System.currentTimeMillis();
                logHandler.removeCallbacks(dialHeartbeat);
                logHandler.postDelayed(dialHeartbeat, 10000L);
                if (t != null) t.startTunneling(lastEmbeddedList);
                psiphonUp = true;
                autoReconnectsDone = 0;   // new server, fresh budget
            } catch (Throwable err) {
                Log.e(TAG, "auto-reconnect failed", err);
                String what = err.getClass().getSimpleName() + ": "
                        + (err.getMessage() == null ? "(no message)" : err.getMessage());
                emitLog("start failed: " + what);
                broadcastFailed(what);
                stopNow();
            } finally {
                startInFlight = false;
            }
        }, "FCAE-PsiReconn").start();
    }

    private void broadcastFailed(String msg) {
        emitLog("failed: " + (msg == null ? "failed" : msg));
        flushLogs();
        Intent i = new Intent(BROADCAST_FAILED);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_ERROR, msg == null ? "failed" : msg);
        sendBroadcast(i);
    }

    private void broadcastStopped() {
        Intent i = new Intent(BROADCAST_STOPPED);
        i.setPackage(getPackageName());
        sendBroadcast(i);
    }

    /** Staged connect progress for the UI (see BROADCAST_STAGE). */
    private void broadcastStage(int stage, String label) {
        Intent i = new Intent(BROADCAST_STAGE);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_STAGE, stage);
        i.putExtra(EXTRA_STAGE_LABEL, label);
        sendBroadcast(i);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "FCAE Psiphon", NotificationManager.IMPORTANCE_HIGH);
            ch.setSound(null, null);
            ch.enableVibration(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    // The no-channel Notification.Builder is deprecated since API 26 and only
    // reached on 24/25 (minSdk 24), where channels do not exist. Deliberate
    // fallback, same as FCAEVpnService.
    @SuppressWarnings("deprecation")
    private Notification buildNotification(String text) {
        Intent main = new Intent(this, MainActivity.class);
        PendingIntent piMain = PendingIntent.getActivity(this, 30, main,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Intent stop = new Intent(this, PsiphonTunnelService.class);
        stop.setAction(ACTION_STOP);
        PendingIntent piStop = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? PendingIntent.getForegroundService(this, 31, stop,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
                : PendingIntent.getService(this, 31, stop,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder nb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        nb.setContentTitle("FCAE VPN")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.ic_lock_lock)
          .setContentIntent(piMain)
          .setOngoing(true)
          .setOnlyAlertOnce(true)
          .addAction(new Notification.Action.Builder(null, "Disconnect", piStop).build());
        return nb.build();
    }
}
