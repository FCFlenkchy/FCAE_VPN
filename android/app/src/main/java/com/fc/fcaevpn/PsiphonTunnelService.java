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
    public static final String BROADCAST_STOPPED = "com.fc.fcaevpn.PSI_STOPPED";
    public static final String BROADCAST_LOG = "com.fc.fcaevpn.PSI_LOG";
    public static final String EXTRA_SOCKS = "socksPort";
    public static final String EXTRA_HTTP = "httpPort";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_REGIONS = "regions";
    public static final String EXTRA_LOG = "log";

    private static final String CHANNEL_ID = "fcaevpn_psiphon";
    private static final int NOTIF_ID = 3;

    private PsiphonTunnel tunnel;
    private String region = "";
    private volatile String lastRegions = "";
    private String upstreamProxy = "";
    // Server-entry sources. tunnel-core has exactly three ways to learn its
    // first server entries, and without one of them the controller stalls on
    // CandidateServers count 0 forever ("no capable servers", then the
    // misleading "untunneled DSL fetch failed ... no broker specs" — the DSL
    // fetcher needs in-proxy broker specs, which are derived from server
    // entries). The embedded list wins when several are set.
    private String remoteServerListUrl = "";
    private String remoteServerListKey = "";
    private String embeddedListPath = "";
    private int wantSocks;
    private int wantHttp;
    private final AtomicInteger socksPort = new AtomicInteger(0);
    private final AtomicInteger httpPort = new AtomicInteger(0);
    private volatile boolean stopping;
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
        if (intent != null) {
            String r = intent.getStringExtra("psiphonRegion");
            region = r == null ? "" : r.trim();
            wantSocks = intent.getIntExtra("psiphonSocksPort", 0);
            wantHttp = intent.getIntExtra("psiphonHttpPort", 0);
            String up = intent.getStringExtra("upstreamProxy");
            upstreamProxy = up == null ? "" : up.trim();
        }
        // Server-entry sources: intent extras first (the host may rotate
        // them), then filesDir/psiphon_settings.json (the provisioning file —
        // the only path that works without shipping a new APK), then the
        // persisted values from previous starts. Everything non-empty is
        // stored so a restart (region switch, process death) keeps working
        // without the host having to repeat it.
        SharedPreferences p = getSharedPreferences("fcae_psiphon", MODE_PRIVATE);
        String extraUrl = intent == null ? null : intent.getStringExtra("psiphonRemoteUrl");
        String extraKey = intent == null ? null : intent.getStringExtra("psiphonRemoteKey");
        String extraList = intent == null ? null : intent.getStringExtra("psiphonEmbeddedListFile");
        String[] fromFile = readProvisioningFile();
        remoteServerListUrl = firstNonEmpty(extraUrl, fromFile[0], p.getString("psiphonRemoteUrl", ""));
        remoteServerListKey = firstNonEmpty(extraKey, fromFile[1], p.getString("psiphonRemoteKey", ""));
        embeddedListPath = firstNonEmpty(extraList, fromFile[2], p.getString("psiphonEmbeddedListFile", ""));
        p.edit()
                .putString("psiphonRemoteUrl", remoteServerListUrl)
                .putString("psiphonRemoteKey", remoteServerListKey)
                .putString("psiphonEmbeddedListFile", embeddedListPath)
                .apply();
        stopping = false;
        emitLog("starting tunnel" + (region.isEmpty() ? " (region Auto)" : " (region " + region + ")")
                + (upstreamProxy.isEmpty() ? "" : " via " + upstreamProxy)
                + sourceSummary());
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try {
                // The embedded list is the body of an encoded server entry
                // list (same format as a remote server_list payload); ""
                // falls back to whatever the datastore still holds plus any
                // remote server list configured in getPsiphonConfig().
                if (t != null) t.startTunneling(readEmbeddedServerList());
                else throw new Exception("Psiphon tunnel not created");
            } catch (Exception e) {
                Log.e(TAG, "startTunneling failed", e);
                emitLog("start failed: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                flushLogs();
                broadcastFailed(e.getMessage() == null ? "Psiphon failed to start" : e.getMessage());
                stopNow();
            }
        }, "FCAE-PsiStart").start();
        return START_STICKY;
    }

    private void promoteForeground(String text) {
        Notification n = buildNotification(text);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIF_ID, n);
        }
    }

    private void stopNow() {
        stopping = true;
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
            // Out-of-band server entries: the classic remote server list.
            // RemoteServerListUrl is the legacy field name, still promoted
            // upstream, so a plain https:// URL + signature key is enough.
            if (!remoteServerListUrl.isEmpty()) {
                o.put("RemoteServerListUrl", remoteServerListUrl);
                if (!remoteServerListKey.isEmpty()) {
                    o.put("RemoteServerListSignaturePublicKey", remoteServerListKey);
                }
            }
            return o.toString();
        } catch (Exception e) {
            Log.e(TAG, "getPsiphonConfig: " + e.getMessage());
            return "{}";
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
     * Optional provisioning file: filesDir/psiphon_settings.json.
     *
     * Recognised keys (all optional):
     * { "RemoteServerListUrl": "https://…/server_list",
     *   "RemoteServerListSignaturePublicKey": "base64 key",
     *   "EmbeddedServerEntryListFile": "/path/to/server_entries" }
     *
     * This is the one provisioning path that needs neither a new APK (asset)
     * nor host code (extras): push the file with run-as on a debug build and
     * restart Psiphon. Returns {url, key, embeddedPath}, empty strings when
     * absent.
     */
    private String[] readProvisioningFile() {
        String[] out = {"", "", ""};
        try {
            File f = new File(getFilesDir(), "psiphon_settings.json");
            if (!f.isFile()) return out;
            JSONObject o = new JSONObject(new String(readAll(f), "UTF-8"));
            out[0] = o.optString("RemoteServerListUrl", "").trim();
            out[1] = o.optString("RemoteServerListSignaturePublicKey", "").trim();
            out[2] = o.optString("EmbeddedServerEntryListFile", "").trim();
            emitLog("provisioning file: " + f.getAbsolutePath()
                    + (out[0].isEmpty() ? "" : " (remote list)")
                    + (out[2].isEmpty() ? "" : " (embedded list file)"));
        } catch (Exception e) {
            emitLog("could not parse psiphon_settings.json: " + e.getMessage());
        }
        return out;
    }

    /** One-line summary of which server-entry sources are configured. */
    private String sourceSummary() {
        java.util.List<String> s = new java.util.ArrayList<>();
        if (!embeddedListPath.isEmpty()) s.add("embedded:" + embeddedListPath);
        if (!remoteServerListUrl.isEmpty()) s.add("remote-list:" + remoteServerListUrl);
        return s.isEmpty()
                ? " [no server-entry source — configure one or Psiphon cannot bootstrap]"
                : " [server entries: " + String.join(", ", s) + "]";
    }

    /**
     * Load the embedded server entry list for startTunneling().
     *
     * Order: the file given via psiphonEmbeddedListFile (extra or pref), then
     * an asset named psiphon_server_list.txt shipped in the APK. Returns ""
     * when neither exists — which is legitimate only when a remote server
     * list is configured or the datastore still holds entries.
     */
    private String readEmbeddedServerList() {
        if (!embeddedListPath.isEmpty()) {
            try {
                byte[] raw = readAll(new File(embeddedListPath));
                if (raw.length > 0) {
                    emitLog("importing embedded server entries from " + embeddedListPath
                            + " (" + raw.length + " bytes)");
                    return new String(raw, "UTF-8");
                }
                emitLog("embedded list file is empty: " + embeddedListPath);
            } catch (Exception e) {
                emitLog("could not read embedded list " + embeddedListPath + ": " + e.getMessage());
            }
        }
        // filesDir/psiphon_server_list.txt: the push-without-rebuild path,
        // same provisioning idea as psiphon_settings.json.
        File sideLoaded = new File(getFilesDir(), "psiphon_server_list.txt");
        if (sideLoaded.isFile() && sideLoaded.length() > 0) {
            try {
                byte[] raw = readAll(sideLoaded);
                emitLog("importing embedded server entries from " + sideLoaded
                        + " (" + raw.length + " bytes)");
                return new String(raw, "UTF-8");
            } catch (Exception e) {
                emitLog("could not read " + sideLoaded + ": " + e.getMessage());
            }
        }
        try (java.io.InputStream in = getAssets().open("psiphon_server_list.txt")) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            if (out.size() > 0) {
                emitLog("importing embedded server entries from assets"
                        + " (" + out.size() + " bytes)");
                return out.toString("UTF-8");
            }
        } catch (Exception ignored) {
            // No bundled asset — the normal case.
        }
        if (remoteServerListUrl.isEmpty()) {
            emitLog("WARNING: no server-entry source (embedded list, asset or remote server"
                    + " list URL): on a fresh datastore Psiphon can never connect");
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
        emitLog(message);
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        socksPort.set(port);
        emitLog("SOCKS 127.0.0.1:" + port);
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        httpPort.set(port);
        emitLog("HTTP 127.0.0.1:" + port);
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
