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
    // stage + short label, rendered by the UI as "CONNECTING · PSIPHON · …".
    public static final String BROADCAST_STAGE = "com.fc.fcaevpn.PSI_STAGE";
    public static final String BROADCAST_STOPPED = "com.fc.fcaevpn.PSI_STOPPED";
    public static final String BROADCAST_LOG = "com.fc.fcaevpn.PSI_LOG";
    public static final String EXTRA_SOCKS = "socksPort";
    public static final String EXTRA_HTTP = "httpPort";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_REGIONS = "regions";
    public static final String EXTRA_LOG = "log";
    public static final String EXTRA_STAGE = "psiphonStage";
    public static final String EXTRA_STAGE_LABEL = "psiphonStageLabel";

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
        }
        stopping = false;
        startInFlight = true;
        psiphonUp = false;
        bytesUp.set(0);
        bytesDown.set(0);
        broadcastStage(1, "STARTING");
        // Read the embedded server-entry list once per start: it feeds both
        // the log line and startTunneling() (two reads would double-log the
        // "importing embedded server entries" notice).
        final String embeddedList = readEmbeddedServerList();
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
                if (t != null) t.startTunneling(embeddedList);
                else throw new Exception("Psiphon tunnel not created");
                psiphonUp = true;
            } catch (Exception e) {
                Log.e(TAG, "startTunneling failed", e);
                emitLog("start failed: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                flushLogs();
                broadcastFailed(e.getMessage() == null ? "Psiphon failed to start" : e.getMessage());
                stopNow();
            } finally {
                startInFlight = false;
            }
        }, "FCAE-PsiStart").start();
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
        psiphonUp = false;
        emitLog("stopping");
        flushLogs();
        try { stopForeground(STOP_FOREGROUND_REMOVE); } catch (Exception ignored) {}
        broadcastStopped();
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try { if (t != null) t.stop(); } catch (Exception ignored) {}
        }, "FCAE-PsiStop").start();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopping = true;
        try { if (tunnel != null) tunnel.stop(); } catch (Exception ignored) {}
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
                broadcastStage(2, "BOOTSTRAP");
            } else if (message.contains("\"noticeType\":\"ConnectingServer\"")) {
                broadcastStage(3, "CONTACTING SERVER");
            } else if (message.contains("\"noticeType\":\"ConnectedServer\"")
                    || message.contains("\"noticeType\":\"ActiveTunnel\"")) {
                broadcastStage(4, "HANDSHAKE");
            }
        }
        emitLog(message);
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        socksPort.set(port);
        if (!stopping) broadcastStage(5, "PORTS UP");
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
        maybeUpdateCounterNotification();
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
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.notify(NOTIF_ID, buildNotification(
                    "FCAE Psiphon — SOCKS 127.0.0.1:" + s));
        } catch (Exception ignored) {}
        Intent i = new Intent(BROADCAST_READY);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_SOCKS, s);
        i.putExtra(EXTRA_HTTP, httpPort.get());
        sendBroadcast(i);
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
        logHandler.removeCallbacks(flushLogs);
        logHandler.postDelayed(flushLogs, 150);
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
