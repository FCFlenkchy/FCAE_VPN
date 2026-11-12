package com.fc.fcaevpn;

import android.content.Context;
import android.os.Build;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Android adapter for the Psiphon exports in libfcae_go_bridge.so. */
final class PsiphonTunnel {
    interface HostService {
        Context getContext();
        String getPsiphonConfig();
        void bindToDevice(long fd) throws Exception;
        boolean hasPhysicalNetwork();
        String physicalNetworkId();
        boolean hasPhysicalIpv6();
        void onDiagnosticMessage(String message);
        void onListeningSocksProxyPort(int port);
        void onListeningHttpProxyPort(int port);
        void onBytesTransferred(long sent, long received);
        void onAvailableEgressRegions(List<String> regions);
        void onConnected();
        void onConnecting();
        void onExiting();
    }

    private final HostService host;
    private volatile int socksPort;
    private final Object lifecycle = new Object();
    private final java.util.concurrent.atomic.AtomicBoolean stopped = new java.util.concurrent.atomic.AtomicBoolean();

    private PsiphonTunnel(HostService host) { this.host = host; }
    static PsiphonTunnel newPsiphonTunnel(HostService host) {
        if (!NativeEngine.ensureLoaded()) {
            throw new IllegalStateException("native engine unavailable: " + NativeEngine.nativeLoadFailure());
        }
        return new PsiphonTunnel(host);
    }
    int getLocalSocksProxyPort() { return socksPort; }

    void startTunneling(String entries) throws java.lang.Exception {
        JSONObject config = new JSONObject(host.getPsiphonConfig());
        Context context = host.getContext();
        if (!config.has("EstablishTunnelTimeoutSeconds")) config.put("EstablishTunnelTimeoutSeconds", 0);
        if (!config.has("MigrateDataStoreDirectory")) config.put("MigrateDataStoreDirectory", context.getFilesDir().getAbsolutePath());
        if (!config.has("RemoteServerListDownloadFilename")) config.put("MigrateRemoteServerListDownloadFilename", new java.io.File(context.getFilesDir(), "remote_server_list").getAbsolutePath());
        config.put("MigrateObfuscatedServerListDownloadDirectory", new java.io.File(context.getFilesDir(), "osl").getAbsolutePath());
        config.put("ClientPlatform", ("Android_" + Build.VERSION.RELEASE + "_" + context.getPackageName()).replaceAll("[^\\w\\-.]", "_"));
        config.put("ClientAPILevel", Build.VERSION.SDK_INT);
        config.put("DeviceRegion", Locale.getDefault().getCountry());
        synchronized (lifecycle) {
            if (stopped.get()) throw new java.lang.Exception("Psiphon start cancelled");
            int rc = nativeStart(config.toString(), entries == null ? "" : entries, this);
            if (rc != 0) {
                nativeStop(this);
                throw new java.lang.Exception("Psiphon start failed (" + rc + ")");
            }
            if (stopped.get()) nativeStop(this);
        }
    }
    void stop() {
        stopped.set(true);
        synchronized (lifecycle) { nativeStop(this); socksPort = 0; }
    }

    // Called from JNI on Go-owned threads. Never throw across the native boundary.
    private boolean bindSocket(int fd) {
        try { host.bindToDevice(fd); return true; }
        catch (Throwable error) { return false; }
    }
    private boolean networkAvailable() { try { return host.hasPhysicalNetwork(); } catch (Throwable ignored) { return false; } }
    private String networkId() { try { return host.physicalNetworkId(); } catch (Throwable ignored) { return "UNKNOWN"; } }
    private boolean ipv6Available() { try { return host.hasPhysicalIpv6(); } catch (Throwable ignored) { return false; } }

    private void notice(byte[] bytes) {
        try {
            JSONObject notice = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            String type = notice.optString("noticeType", "");
            JSONObject data = notice.optJSONObject("data");
            if (data == null) return;
            switch (type) {
                case "ListeningSocksProxyPort":
                    socksPort = data.optInt("port", 0);
                    if (socksPort > 0) host.onListeningSocksProxyPort(socksPort);
                    break;
                case "ListeningHttpProxyPort":
                    int http = data.optInt("port", 0);
                    if (http > 0) host.onListeningHttpProxyPort(http);
                    break;
                case "Tunnels":
                    if (data.optInt("count", 0) > 0) host.onConnected(); else host.onConnecting();
                    break;
                case "AvailableEgressRegions":
                    JSONArray items = data.optJSONArray("regions");
                    if (items != null) {
                        ArrayList<String> regions = new ArrayList<>();
                        for (int i = 0; i < items.length(); i++) regions.add(items.optString(i, ""));
                        host.onAvailableEgressRegions(regions);
                    }
                    break;
                case "BytesTransferred":
                    host.onBytesTransferred(data.optLong("sent", 0), data.optLong("received", 0));
                    break;
                case "Exiting": host.onExiting(); break;
                default: break;
            }
            String diagnostic = diagnosticNotice(type, data);
            if (diagnostic != null) host.onDiagnosticMessage(diagnostic);
        } catch (Throwable ignored) { }
    }

    private static String diagnosticNotice(String type, JSONObject data) throws org.json.JSONException {
        switch (type) {
            case "ConnectingServer": case "ConnectedServer": case "ActiveTunnel":
            case "ConnectedServerRegion": case "CandidateServers": case "Tunnels":
            case "EstablishTunnelTimeout": case "Warning": case "Error": case "Alert":
                break;
            default: return null;
        }
        JSONObject safe = new JSONObject();
        for (String key : new String[]{"region", "serverRegion"}) {
            Object value = data.opt(key);
            if (value instanceof String && ((String) value).matches("[A-Z]{2}")) safe.put(key, value);
        }
        Object protocol = data.opt("protocol");
        if (protocol instanceof String && isDiagnosticProtocol((String) protocol)) safe.put("protocol", protocol);
        for (String key : new String[]{"candidateNumber", "uniqueCandidateEstimate", "establishedTunnelsCount", "initialCount", "count"}) {
            Object value = data.opt(key);
            if (value instanceof Number) {
                long number = ((Number) value).longValue();
                if (number >= 0 && number <= 10000000) safe.put(key, number);
            }
        }
        Object replay = data.opt("isReplay");
        if (replay instanceof Boolean) safe.put("isReplay", replay);
        JSONObject notice = new JSONObject();
        notice.put("noticeType", type);
        notice.put("data", safe);
        return notice.toString();
    }

    private static boolean isDiagnosticProtocol(String protocol) {
        switch (protocol) {
            case "SSH": case "OSSH": case "TLS-OSSH": case "SHADOWSOCKS-OSSH":
            case "UNFRONTED-MEEK-OSSH": case "UNFRONTED-MEEK-HTTPS-OSSH":
            case "UNFRONTED-MEEK-SESSION-TICKET-OSSH": case "FRONTED-MEEK-OSSH":
            case "FRONTED-MEEK-HTTP-OSSH": case "QUIC-OSSH": case "FRONTED-MEEK-QUIC-OSSH":
            case "TAPDANCE-OSSH": case "CONJURE-OSSH": return true;
            default: return false;
        }
    }

    private static native int nativeStart(String config, String entries, PsiphonTunnel owner);
    void networkChanged() { if (!stopped.get()) nativeNetworkChanged(this); }
    private static native void nativeStop(PsiphonTunnel owner);
    private static native void nativeNetworkChanged(PsiphonTunnel owner);
}
