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
import android.os.Build;
import android.os.IBinder;
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
    public static final String EXTRA_SOCKS = "socksPort";
    public static final String EXTRA_HTTP = "httpPort";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_REGIONS = "regions";

    private static final String CHANNEL_ID = "fcaevpn_psiphon";
    private static final int NOTIF_ID = 3;

    private PsiphonTunnel tunnel;
    private String region = "";
    private volatile String lastRegions = "";
    private int wantSocks;
    private int wantHttp;
    private final AtomicInteger socksPort = new AtomicInteger(0);
    private final AtomicInteger httpPort = new AtomicInteger(0);
    private volatile boolean stopping;

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
        }
        stopping = false;
        final PsiphonTunnel t = tunnel;
        new Thread(() -> {
            try {
                if (t != null) t.startTunneling("");
                else throw new Exception("Psiphon tunnel not created");
            } catch (Exception e) {
                Log.e(TAG, "startTunneling failed", e);
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
            return o.toString();
        } catch (Exception e) {
            Log.e(TAG, "getPsiphonConfig: " + e.getMessage());
            return "{}";
        }
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
        Log.i(TAG, message == null ? "" : message);
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        socksPort.set(port);
        Log.i(TAG, "SOCKS " + port);
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        httpPort.set(port);
        Log.i(TAG, "HTTP " + port);
    }

    @Override
    public void onAvailableEgressRegions(List<String> regions) {
        if (regions == null || regions.isEmpty()) return;
        lastRegions = String.join(",", regions);
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
        if (!stopping) {
            broadcastFailed("Psiphon exited");
            stopNow();
        }
    }

    private void broadcastFailed(String msg) {
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
