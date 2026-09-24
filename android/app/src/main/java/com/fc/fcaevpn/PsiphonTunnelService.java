package com.fc.fcaevpn;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ca.psiphon.PsiphonTunnel;

/**
 * Official Psiphon AAR ({@code ca.psiphon:psiphontunnel}) in its own process
 * ({@code :psiphon}): its Go runtime SIGSEGVs at dlopen if it shares an
 * address space with tun2socks' own. Its sockets are bound to the underlying
 * network so a TUN in the UI process cannot capture them, and the UI process
 * points tun2socks at the SOCKS port this service broadcasts.
 */
public class PsiphonTunnelService extends Service implements PsiphonTunnel.HostService {

    private static final String TAG = "FCAE_PSI";
    public static final String ACTION_START = "com.fc.fcaevpn.PSI_START";
    public static final String ACTION_STOP  = "com.fc.fcaevpn.PSI_STOP";
    public static final String ACTION_REGIONS = "com.fc.fcaevpn.PSI_REGIONS";
    // Which app-process notification owner the tunnel belongs to. The
    // :psiphon foreground service posts the OWNER's own connecting
    // notification (buildConnecting) under the owner's id, so the app keeps
    // exactly one status notification: VpnNotification (id 1) in TUN mode,
    // ProxyNotification (id 2) in proxy mode.
    public static final String EXTRA_OWNER = "psiOwner";
    public static final String OWNER_VPN = "vpn";
    public static final String OWNER_PROXY = "proxy";
    // Terminal-stop signal. processMustDie is a per-process class copy: the
    // UI process cannot set the :psiphon one directly, so a terminal stop
    // carries the flag across the boundary as an ACTION_STOP intent extra.
    // Session switches (stopBound) send the plain stop and never set it.
    public static final String EXTRA_DIE = "psiphonDie";
    /**
     * This service runs in the {@code :psiphon} process, so the UI process
     * killing itself does not take the tunnel down with it. Set on the way
     * out; the process ends once the service is destroyed and the tunnel has
     * had its teardown window.
     */
    private static volatile boolean processMustDie = false;
    // Cancels a pending onDestroy self-kill: a fresh session starting inside
    // the PROCESS_KILL_DELAY_MS window must not be killed mid-dial. Main
    // thread only, :psiphon process.
    private static int killTicket;
    private static final long PROCESS_KILL_DELAY_MS = 500L;
    public static final String BROADCAST_READY = "com.fc.fcaevpn.PSI_READY";
    public static final String BROADCAST_FAILED = "com.fc.fcaevpn.PSI_FAILED";
    // Staged connect progress (like the Tor bootstrap percentage): INTEGER
    // stage + short label. The label is a full status phrase in the same
    // vocabulary as the Aether engine statuses (CONNECTING / ESTABLISHING
    // TUNNEL / CONNECTED) — no protocol tag baked into the text.
    public static final String BROADCAST_STAGE = "com.fc.fcaevpn.PSI_STAGE";
    public static final String BROADCAST_STOPPED = "com.fc.fcaevpn.PSI_STOPPED";
    public static final String BROADCAST_LOG = "com.fc.fcaevpn.PSI_LOG";
    public static final String BROADCAST_REGIONS = "com.fc.fcaevpn.PSI_REGIONS_AVAILABLE";
    // Written by the isolated Psiphon process and read by the UI process.
    public static final String REGIONS_FILE = "psiphon_egress_regions.txt";
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

    // Accessed on the application main thread. The app notification owner keeps
    // this binding alive.
    private static volatile android.content.ServiceConnection connection;
    private static final java.util.concurrent.atomic.AtomicLong bindingEpoch = new java.util.concurrent.atomic.AtomicLong();
    private static volatile long activeSession;
    // EVERY live binder, not just the latest: a rebind that was already
    // accepted can outlive a session switch, and a leaked binder reference
    // would pin the :psiphon process (and its tunnel) after a disconnect.
    // stopBound unbinds all of them.
    private static final java.util.Set<android.content.ServiceConnection> liveConnections =
            java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

        /**
         * Rebind safety net. The binder dropping must not fail the session: the
         * Rust lease stays pending, so the TUN keeps running while we rebind with
         * the SAME intent (requestId + psiSession) and the restarted service
         * replays its config. Last resort only — the service enters foreground
         * itself, which is what actually survives OEM task-removal kills.
         */
    private static final int MAX_REBIND_ATTEMPTS = 5;
    private static final long REBIND_DELAY_MS = 1500L;
    private static volatile int rebindAttempts;

        /**
         * Hard deadline for the AAR's tunnel.stop(). Upstream joins the whole
         * controller — every in-flight dial and fetch — which is tens of ms when
         * healthy and seconds mid-handshake on a filtered link, long after the
         * user was told the session is over.
         *
         * Slower than this and the process is killed instead: the kernel closes
         * every socket, so the tunnel is gone at once. Bolt's datastore is
         * crash-safe and the system OOM-kills this process in production anyway.
         */
    private static final long HARD_STOP_TIMEOUT_MS = 500L;
    private long session;
    private long attachRequestId;
    private static volatile long clientAttachId;
    private static boolean attachReceiverRegistered;

    // Called on main by the foreground owner, not by the activity. Chained
    // startup therefore continues while the UI is backgrounded.
    public static void pollChainedRequest(Context context) {
        Context app = context.getApplicationContext();
        try {
            if (!attachReceiverRegistered) {
                android.content.IntentFilter filter = new android.content.IntentFilter();
                filter.addAction(BROADCAST_READY);
                filter.addAction(BROADCAST_FAILED);
                filter.addAction(BROADCAST_STOPPED);
                androidx.core.content.ContextCompat.registerReceiver(app, new android.content.BroadcastReceiver() {
                    @Override public void onReceive(Context c, Intent i) {
                        long id = i.getLongExtra("requestId", 0);
                        if (id == 0 || id != clientAttachId || !isCurrentBroadcast(i)) return;
                        if (BROADCAST_READY.equals(i.getAction())) {
                            if (i.getBooleanExtra("regionsOnly", false)) return;
                            rebindAttempts = 0; // the tunnel is alive again
                            NativeEngine.nativePsiphonAttachComplete(id,
                                i.getIntExtra(EXTRA_SOCKS, 0), i.getIntExtra(EXTRA_HTTP, 0));
                        } else { NativeEngine.nativePsiphonAttachComplete(id, 0, 0); }
                    }
                }, filter, androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED);
                attachReceiverRegistered = true;
            }
            String raw = NativeEngine.nativePsiphonAttachRequest();
            if (raw.isEmpty()) {
                if (clientAttachId != 0) { stopBound(app); clientAttachId = 0; }
                return;
            }
            org.json.JSONObject request = new org.json.JSONObject(raw);
            long id = request.getLong("requestId");
            if (id == clientAttachId) return;
            // stopBound and startBound enqueue in order on the main looper.
            if (connection != null) stopBound(app);
            clientAttachId = id;
            Intent start = new Intent(app, PsiphonTunnelService.class).setAction(ACTION_START);
            start.putExtra(EXTRA_OWNER, context instanceof ProxyNotification ? OWNER_PROXY : OWNER_VPN);
            start.putExtra("requestId", id);
            start.putExtra("upstreamProxy", request.getString("upstreamProxy"));
            start.putExtra("psiphonRegion", request.optString("psiphonRegion", ""));
            start.putExtra("psiphonTransport", request.optInt("psiphonTransport", 0));
            start.putExtra("psiphonSocksPort", request.optInt("psiphonSocksPort", 0));
            start.putExtra("psiphonHttpPort", request.optInt("psiphonHttpPort", 0));
            start.putExtra("lanSharing", request.optBoolean("lanSharing", false));
            startBound(app, start);
        } catch (Exception e) {
            Log.e(TAG, "Cannot start chained Psiphon exit", e);
            if (clientAttachId != 0) NativeEngine.nativePsiphonAttachComplete(clientAttachId, 0, 0);
        }
    }

    public static boolean hasActiveBinding() { return connection != null; }
    public static boolean isCurrentBroadcast(Intent intent) {
        return intent.getLongExtra("psiSession", -1) == activeSession;
    }
    public static void startBound(Context context, Intent intent) {
        Context app = context.getApplicationContext();
        final long epoch = bindingEpoch.incrementAndGet();
        new Handler(Looper.getMainLooper()).post(() -> {
            if (epoch != bindingEpoch.get() || connection != null) return;
            activeSession = android.os.SystemClock.elapsedRealtimeNanos();
            intent.putExtra("psiSession", activeSession);
            android.content.ServiceConnection next = makeConnection(app, intent);
            connection = next;
            liveConnections.add(next);
                        // Kept both started and bound so an orphaned service can be
                        // stopped explicitly; its lifetime belongs to the owner, which is
                        // also the party whose notification it posts. A region refresh is
                        // bind-only: starting the component again would reset Psiphon.
            if (!ACTION_REGIONS.equals(intent.getAction())) {
                try { app.startService(intent); } catch (Throwable ignored) {}
            }
            if (!app.bindService(intent, next,
                    Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT)) {
                connection = null;
                liveConnections.remove(next);
                Intent failed = new Intent(BROADCAST_FAILED).setPackage(app.getPackageName());
                failed.putExtra("psiSession", activeSession);
                failed.putExtra("requestId", intent.getLongExtra("requestId", 0));
                failed.putExtra(EXTRA_ERROR, "Unable to bind Psiphon service");
                app.sendBroadcast(failed);
            }
        });
    }

    static android.content.ServiceConnection makeConnection(final Context app, final Intent intent) {
        return new android.content.ServiceConnection() {
            @Override public void onServiceConnected(android.content.ComponentName name, IBinder binder) {
                // Claim the current-connection slot for a rebound binder.
                // startBound sets it eagerly, but the rebind path can only
                // claim it here: leaving it null makes the 20 s watchdog
                // unable to tell a healthy rebound tunnel from a bind that
                // never connected, so it rebinds a LIVE session every 20 s
                // until the counter hits MAX_REBIND_ATTEMPTS and a working
                // tunnel is failed as "rebind exhausted".
                if (connection == null && liveConnections.contains(this)) connection = this;
            }
            @Override public void onServiceDisconnected(android.content.ComponentName name) {
                // Process death: drop this binder from the live set no matter
                // what; only the CURRENT connection triggers a rebind (a
                // stale duplicate binder must not rebind twice).
                liveConnections.remove(this);
                if (connection != this) return;
                connection = null;
                // The :psiphon process died. NOT a user action: keep the
                // session alive (no 0-port completion, no BROADCAST_FAILED)
                // and rebind with the same intent instead.
                Log.w(TAG, "Psiphon process lost the binder; rebind scheduled");
                scheduleRebind(app, intent);
            }
        };
    }

    static void scheduleRebind(final Context app, final Intent original) {
        // A stopBound/startBound that lands before we fire invalidates us via
        // the epoch bump; a new binding already present means the session
        // moved on. clientAttachId == 0 means the request was dropped.
        final long epoch = bindingEpoch.get();
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            if (connection != null || clientAttachId == 0 || epoch != bindingEpoch.get()) return;
            if (rebindAttempts >= MAX_REBIND_ATTEMPTS) {
                rebindAttempts = 0;
                long req = clientAttachId;
                Intent failed = new Intent(BROADCAST_FAILED).setPackage(app.getPackageName());
                failed.putExtra("psiSession", activeSession);
                failed.putExtra("requestId", req);
                failed.putExtra(EXTRA_ERROR, "Psiphon process exited (rebind exhausted)");
                app.sendBroadcast(failed);
                NativeEngine.nativePsiphonAttachComplete(req, 0, 0);
                return;
            }
            rebindAttempts++;
            Log.w(TAG, "Psiphon rebind attempt " + rebindAttempts + "/" + MAX_REBIND_ATTEMPTS);
            try { app.startService(original); } catch (Throwable ignored) {}
            android.content.ServiceConnection rebinding = makeConnection(app, original);
            if (!app.bindService(original, rebinding,
                    Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT)) {
                Log.w(TAG, "Psiphon rebind " + rebindAttempts + " refused; retrying");
                scheduleRebind(app, original);
            } else {
                liveConnections.add(rebinding);
                // Watchdog: if the bind was accepted but the process never
                // connects (creation failed), no ServiceConnection callback
                // ever fires, so 20 s of silence counts as a failed attempt.
                new Handler(Looper.getMainLooper()).postDelayed(() -> {
                    if (connection == null && clientAttachId != 0) scheduleRebind(app, original);
                }, 20000L);
            }
        }, REBIND_DELAY_MS);
    }

    public static void stopBound(Context context) {
        Context app = context.getApplicationContext();
        // Dispatch the explicit stop FIRST, while the component is still
        // started and bound: the command reaches the live instance and its
        // stopNow() runs the real teardown. stopService() below only
        // destroys the component — it cannot reach the Go tunnel running
        // in the :psiphon process, which would keep connecting (or stay
        // connected) in an empty cached process.
        deliverStop(app, true, false);
        bindingEpoch.incrementAndGet(); // invalidate starts not yet delivered
        final java.util.List<android.content.ServiceConnection> old =
                new java.util.ArrayList<>(liveConnections);
        liveConnections.clear();
        connection = null;
        // This is an actual Psiphon stop or session replacement, not an
        // Activity lifecycle event. Drop the main-process rehydration snapshot
        // only here so pause/resume cannot erase live telemetry.
        ProxyNotification.cachePsiphonStats(app, null);
        final long request = clientAttachId;
        clientAttachId = 0;
        if (request != 0) NativeEngine.nativePsiphonAttachComplete(request, 0, 0);
        // The service is also started so unbinding alone cannot leave an
        // orphaned tunnel running. stopService is safe when nothing is
        // running and covers the binder-already-dropped case. A queued
        // startBound for the NEXT session posts its startService after the
        // unbinds below, so a fresh session is not hurt.
        try { app.stopService(new Intent(app, PsiphonTunnelService.class)); }
        catch (Throwable ignored) {}
        if (!old.isEmpty()) {
            new Handler(Looper.getMainLooper()).post(() -> {
                // unbindService must run on the thread that bound (main).
                for (android.content.ServiceConnection c : old) {
                    try { app.unbindService(c); } catch (IllegalArgumentException ignored) {}
                }
            });
        }
    }

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

    // Transport family pick (index into transportProtocols()).
    // 0 = Auto: no LimitTunnelProtocols, tunnel-core uses its full set.
    private int transport = 0;

    private static final Object LIBRARY_LOCK = new Object();
    private static final java.util.concurrent.ExecutorService libraryWorker =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> new Thread(r, "FCAE-PsiLibrary"));
    // The AAR permits one PsiphonTunnel per process (its own static
    // INSTANCE), and this service owns the :psiphon process, so the live
    // tunnel is PROCESS state, not instance state: an instance recreated
    // after its component was destroyed (binding churn, killProcessOnExit's
    // stopService) must still be able to stop the tunnel the dead instance
    // left behind.
    private static volatile PsiphonTunnel liveTunnel;
    private static PsiphonNetworkBinding liveNetworkBinding;
    // A START that arrived while a teardown was in flight (session switch:
    // stopBound() for the old request, then startBound() for the next).
    // Replayed once the library is quiet; cleared by a later ACTION_STOP.
    private volatile Intent pendingStart;
    private volatile boolean destroyed;
    private String region = "";
    // Whose notification id the :psiphon FGS posts under (EXTRA_OWNER).
    private boolean proxyOwner;
    private volatile String lastRegions = "";
    private String upstreamProxy = "";
    private boolean lanSharing;
    private volatile String lanAddress = "";
    public static final String EXTRA_LAN = "psiphonLanIp";
    /** Default local listeners; kept clear of the engine (1819/1820) and Tor (1821/1822). */
    public static final int DEFAULT_SOCKS_PORT = 1823;
    public static final int DEFAULT_HTTP_PORT = 1824;

    private int wantSocks;
    private int wantHttp;
    private final AtomicInteger socksPort = new AtomicInteger(0);
    private final AtomicInteger httpPort = new AtomicInteger(0);
    // Cumulative tunneled bytes, from onBytesTransferred (EmitBytesTransferred
    // notices — the callback reports DELTAS since the previous notice, so
    // accumulate). Published to the app-owned UI/notification.
    private final AtomicLong bytesUp = new AtomicLong(0);
    private final AtomicLong bytesDown = new AtomicLong(0);
    private volatile boolean stopping;
    // True while a start thread is inside startTunneling(); true alone
    // (psiphonUp) once the library reported itself started. Together they
    // Serialises duplicate ACTION_PSIPHON_START deliveries: the library wrapper
    // begins every start by stopping the previous instance, so re-entering
    // while a controller is mid-boot kills it (a tight
    // "starting tunnel -> stopping Psiphon library" loop).
    private volatile boolean startInFlight;
    private volatile boolean psiphonUp;
    private volatile boolean handshakeConnected;
    private volatile boolean handshakeRegion;
    private volatile boolean readyBroadcast;
    private final Handler logHandler = new Handler(Looper.getMainLooper());
    private boolean logFlushPending;
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
    private PsiphonNetworkBinding networkBinding;

    @Override
    public void onCreate() {
        super.onCreate();
        networkBinding = new PsiphonNetworkBinding(this);
        // Foreground status is entered per tunnel start in onStartCommand()
        // (see enterTunnelForeground), not here: a sticky restart with a null
        // intent must not raise a foreground service nobody asked for.
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        boolean stop = intent != null && ACTION_STOP.equals(intent.getAction());
        if (stop) {
            // The terminal stop (app exit) carries the kill flag; a session
            // switch's plain stop must not, or the next teardown would end
            // the process a fresh session still needs.
            if (intent.getBooleanExtra(EXTRA_DIE, false)) processMustDie = true;
            // A stop invalidates any restart parked below.
            pendingStart = null;
            stopNow();
            return START_NOT_STICKY;
        }
        if (intent != null && ACTION_REGIONS.equals(intent.getAction())) {
            broadcastRegions();
            return (psiphonUp || startInFlight) ? START_STICKY : START_NOT_STICKY;
        }
        if (intent == null) {
            // Sticky restart after this process was killed: the user's
            // region/transport/ports/upstream extras died with it, so
            // replaying a blank "Auto" config would start a tunnel nobody
            // asked for and — paired with start failures below — loop
            // forever at the system's ~1s restart cadence. MainActivity is
            // the only legitimate source of psiphon starts; exit quietly.
            if (!psiphonUp && !startInFlight) {
                stopSelf();
            }
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(intent.getAction())) {
            // Not a start command: most notably the task-removal redelivery,
            // which replays the launcher's base intent to every started
            // service when the user swipes the app from recents. Its blank
            // extras would dial a tunnel nobody asked for. Stop and Regions
            // are handled above; real starts come from ACTION_START only.
            return (psiphonUp || startInFlight) ? START_STICKY : START_NOT_STICKY;
        }
        if (stopping) {
            // A teardown is in flight (user disconnect or session switch).
            // Dropping a START here would hang the new session: nothing ever
            // re-sends it. Park it — the stop completion replays it once the
            // library is quiet. Checked BEFORE the session capture so the
            // teardown's own broadcasts keep the old session.
            if (ACTION_START.equals(intent.getAction())) pendingStart = intent;
            return START_NOT_STICKY;
        }
        // startBound() starts the service before Android invokes onBind().
        // Capture the session here as well as in onBind(), otherwise a very
        // fast handshake can publish a valid region list with the old
        // sentinel session and every app-process receiver will discard it.
        long requestedSession = intent.getLongExtra("psiSession", -1);
        if (requestedSession >= 0) session = requestedSession;
        if (startInFlight || psiphonUp) {
            // Duplicate start (double-tap, poll re-fire, redelivery). The
            // wrapper stops the running instance before every new start, so
            // a second start mid-boot aborts the first controller — repeat
            // deliveries turned into the connect/stop crash loop. The UI
            // always stops before reconfiguring, so ignore extras quietly;
            // this is an idempotent lifecycle race, not a tunnel error.
            Log.d(TAG, "Duplicate Psiphon start ignored while "
                    + (startInFlight ? "starting" : "running"));
            return START_NOT_STICKY;
        }
        {
            proxyOwner = OWNER_PROXY.equals(intent.getStringExtra(EXTRA_OWNER));
            String r = intent.getStringExtra("psiphonRegion");
            region = r == null ? "" : r.trim();
            transport = intent.getIntExtra("psiphonTransport", 0);
            // 0 means "let Psiphon pick", which moves the listener on every
            // connect. Pin the defaults (mirrors config.rs
            // DEFAULT_PSIPHON_*_PORT) so anything pointed at the proxy keeps
            // working across reconnects.
            wantSocks = intent.getIntExtra("psiphonSocksPort", 0);
            wantHttp = intent.getIntExtra("psiphonHttpPort", 0);
            if (wantSocks <= 0) wantSocks = DEFAULT_SOCKS_PORT;
            if (wantHttp <= 0) wantHttp = DEFAULT_HTTP_PORT;
            String up = intent.getStringExtra("upstreamProxy");
            upstreamProxy = up == null ? "" : up.trim();
            lanSharing = intent.getBooleanExtra("lanSharing", false);
            attachRequestId = intent.getLongExtra("requestId", 0);
        }
        // A fresh session outranks any stale terminal-stop flag delivered
        // while this process was being recycled: the next teardown decides
        // again whether the process dies — and a self-kill scheduled by the
        // dying previous instance is cancelled before it can fire mid-dial.
        processMustDie = false;
        killTicket++;
        enterTunnelForeground();
        stopping = false;
        startInFlight = true;
        psiphonUp = false;
        handshakeConnected = false;
        handshakeRegion = false;
        readyBroadcast = false;
        bytesUp.set(0);
        bytesDown.set(0);
        broadcastStage(1, "CONNECTING");
        libraryWorker.execute(() -> {
            try {
                synchronized (LIBRARY_LOCK) {
                    if (stopping) return;
                    if (liveNetworkBinding != null && liveNetworkBinding != networkBinding) {
                        liveNetworkBinding.close();
                    }
                    liveNetworkBinding = networkBinding;
                    networkBinding.start();
                }
                if (stopping) return;
                // Asset I/O must not delay the main-thread start/stop buttons.
                final String embeddedList = readEmbeddedServerList();
                if (stopping) return;
                emitLog("starting tunnel" + (region.isEmpty() ? " (region Auto)" : " (region " + region + ")")
                        + (upstreamProxy.isEmpty() ? "" : " via " + upstreamProxy)
                        + sourceSummary(embeddedList));
                // Populate the region selector from authoritative sources in
                // parallel with the handshake: the same remote server list
                // the core will download, plus whatever was persisted.
                fetchRemoteServerRegions();
                // The embedded list is the body of an encoded server entry
                // list (same format as a remote server_list payload); ""
                // falls back to whatever the datastore still holds plus any
                // remote server list configured in getPsiphonConfig().
                emitLog("startTunneling: calling");
                // The lock is held ONLY around create+publish, never across
                // startTunneling(): a stop must be able to swap the tunnel
                // out and call stop() from its own thread while a dial is
                // still in progress. Holding the lock across the dial is
                // what made mid-connect disconnects wait for the connect.
                final PsiphonTunnel t;
                synchronized (LIBRARY_LOCK) {
                    if (stopping) return;
                    t = PsiphonTunnel.newPsiphonTunnel(this);
                    liveTunnel = t;
                }
                try {
                    t.setVpnMode(true);
                    t.startTunneling(embeddedList);
                } finally {
                    // A stop that landed mid-dial swapped liveTunnel out and
                    // issued its own stop(), which cannot have reached a
                    // controller this dial created afterwards. Stop here, on
                    // the worker, before the restart replay can run.
                    if (stopping) {
                        try { t.stop(); } catch (Throwable ignored) {}
                    }
                }
                emitLog("startTunneling: returned");
                if (!stopping) psiphonUp = true;
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
                if (stopping) networkBinding.close();
                startInFlight = false;
            }
        });
        dialStartedAtMs = System.currentTimeMillis();
        logHandler.removeCallbacks(dialHeartbeat);
        logHandler.postDelayed(dialHeartbeat, 10000L);
        // Sticky: if the system kills this process while the user's session
        // is live, restart it (null intent -> quiet exit below; the rebind /
        // supervisor recreates it with the real extras).
        return START_STICKY;
    }

        /**
         * Raise this service to foreground before the tunnel dials: several OEM
         * task managers kill per-process on task removal, which tore the tunnel
         * down mid-session. The notification posted is the OWNER's own dial
         * notification under the owner's id, so it is indistinguishable from the
         * one the owner already posted; the owner rewrites and dismisses it.
         */
    @SuppressWarnings("deprecation")
    private void enterTunnelForeground() {
        try {
            android.app.Notification n;
            int id;
            if (proxyOwner) {
                ProxyNotification.ensureChannel(this);
                n = ProxyNotification.buildConnecting(this);
                id = ProxyNotification.NOTIFICATION_ID;
            } else {
                n = VpnNotification.buildConnecting(this);
                id = VpnNotification.NOTIFICATION_ID;
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(id, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(id, n);
            }
        } catch (Throwable t) {
            // Notification plumbing must never kill a session start; without
            // foreground status the rebind path still recovers from kills.
            Log.w(TAG, "FGS promotion failed; continuing without", t);
        }
    }

    private synchronized void stopNow() {
        // Idempotent: a start failure, onExiting() and an ACTION_STOP can
        // all land within the same second; only the first may run the
        // teardown (a second t.stop() would block on the already-stopping
        // controller and double the "stopping" noise).
        if (stopping) return;
        stopping = true;
        networkBinding.close();
        // DETACH, never REMOVE: the visible notification at this id belongs
        // to the app-process owner (it re-posts while running and dismisses
        // at teardown); cancelling it here would flash the user's status
        // away. Detach only drops this service's foreground status so the
        // FGS lifecycle ends with the tunnel.
        stopForeground(STOP_FOREGROUND_DETACH);
        logHandler.removeCallbacks(dialHeartbeat);
        Thread st = statsThread;
        psiphonUp = false;
        if (st != null) {
            st.interrupt();
            // Let the loop finish any in-flight broadcast before the final
            // sample below, so the zero-rate sample is provably the last
            // one any consumer caches. It sleeps 1 s per iteration and
            // exits on interrupt, so this returns in milliseconds.
            try { st.join(250); } catch (InterruptedException ignored) {}
        }
        // Final stats sample with the rates at zero. Without it the last
        // broadcast -- taken mid-flow -- stays the cached "latest" in the
        // notification and the UI and keeps showing a live speed after the
        // tunnel is gone. Totals are kept, so the session's byte count is
        // not lost.
        try {
            Intent fin = new Intent(BROADCAST_STATS);
            fin.setPackage(getPackageName());
            fin.putExtra("psiSession", session);
            fin.putExtra("requestId", attachRequestId);
            fin.putExtra(EXTRA_LAN, lanSharing ? lanAddress : "");
            fin.putExtra(EXTRA_SOCKS, socksPort.get());
            fin.putExtra(EXTRA_HTTP, httpPort.get());
            fin.putExtra(EXTRA_RTT, lastRttMs);
            fin.putExtra(EXTRA_UP_BPS, 0L);
            fin.putExtra(EXTRA_DOWN_BPS, 0L);
            fin.putExtra(EXTRA_TOTAL_UP, bytesUp.get());
            fin.putExtra(EXTRA_TOTAL_DOWN, bytesDown.get());
            sendBroadcast(fin);
        } catch (Exception ignored) {}
        emitLog("stopping");
        flushLogs();
        // Swap the tunnel out under the lock. The start task holds the lock
        // only while creating one, so this never queues behind a dial; a
        // start that has not created its tunnel yet sees stopping and never
        // will. t == null after a failed start is safe too: Psi.stop()
        // no-ops on a nil controller and closes a half-open datastore.
        final PsiphonTunnel t;
        synchronized (LIBRARY_LOCK) {
            t = liveTunnel;
            liveTunnel = null;
            if (liveNetworkBinding != null) {
                liveNetworkBinding.close();
                liveNetworkBinding = null;
            }
        }
        if (t != null) {
            final java.util.concurrent.CountDownLatch stopDone =
                    new java.util.concurrent.CountDownLatch(1);
            // NOT libraryWorker: that worker may itself be blocked inside
            // startTunneling(), and a stop queued behind it can never
            // interrupt the connect. A dedicated thread calls stop()
            // immediately; the AAR serializes it against an in-flight
            // startTunneling() with its own monitor — the supported way to
            // abort a connecting tunnel. The deadline watchdog below still
            // guarantees the drop.
            new Thread(() -> {
                try { t.stop(); } catch (Throwable ignored) {}
                finally { stopDone.countDown(); }
                // A pending START means a session switch is in progress,
                // not a terminal stop: the notification owner must not be
                // told "stopped" for a session it is already handing to
                // the next request.
                if (pendingStart == null) {
                    broadcastStopped();
                }
                scheduleRestartReplay();
            }, "FCAE-PsiStop").start();
            new Thread(() -> {
                try {
                    if (stopDone.await(HARD_STOP_TIMEOUT_MS,
                            java.util.concurrent.TimeUnit.MILLISECONDS)) return;
                } catch (InterruptedException ignored) { return; }
                Log.w(TAG, "Psiphon stop exceeded " + HARD_STOP_TIMEOUT_MS
                        + " ms; killing the process to drop the tunnel");
                try { android.os.Process.killProcess(android.os.Process.myPid()); }
                catch (Throwable ignored) {}
                Runtime.getRuntime().halt(2); // backstop: guaranteed exit
            }, "FCAE-PsiHardStop").start();
        } else {
            scheduleRestartReplay();
        }
        stopSelf();
    }

        /**
         * Replay a START that was parked because a teardown was in flight (the
         * session switch: stopBound() then startBound()). Queued so it runs only
         * after the in-flight start task has fully exited — otherwise the switch's
         * START lands on a stopping instance and is silently dropped.
         */
    private void scheduleRestartReplay() {
        libraryWorker.execute(() -> logHandler.post(() -> {
            if (destroyed) return;
            Intent restart = pendingStart;
            pendingStart = null;
            if (restart == null) return;
            stopping = false;
            onStartCommand(restart, 0, 0);
        }));
    }

    @Override
    public void onDestroy() {
        destroyed = true;
        // Android may recreate the owner/binding while the tunnel is live.
        // Only an explicit stop is allowed to tear down Psiphon here.
        if (stopping || processMustDie) stopNow();
        flushLogs();
        super.onDestroy();
        // Last thing this process does when the app is being closed for good.
        // Delayed so stopNow()'s controller teardown gets its window instead
        // of being cut off mid-stop.
        if (processMustDie) {
            final int ticket = ++killTicket;
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                if (ticket == killTicket) FCAEVpnService.killProcessQuietly();
            }, PROCESS_KILL_DELAY_MS);
        }
    }

        /**
         * The {@code :psiphon} process must not outlive the app. {@link
         * #processMustDie} is a per-process copy: it is the flag that ends it, and
         * the stop command carrying it is already with the system.
         */
    public static void killProcessOnExit(Context context) {
        processMustDie = true;
        // processMustDie is a per-process class copy: the assignment above
        // only marks the caller's own process. What actually ends :psiphon
        // is the ACTION_STOP command carrying EXTRA_DIE — its onStartCommand
        // sets the flag there and its onDestroy runs the delayed self-kill.
        // The command is already with the system and is delivered to
        // :psiphon even though this process exits right after.
        deliverStop(context.getApplicationContext(), false, true);
        try {
            context.getApplicationContext()
                    .stopService(new Intent(context.getApplicationContext(),
                            PsiphonTunnelService.class));
        } catch (Throwable ignored) {
        }
    }

    /**
     * Dispatch the explicit stop to the isolated service. Plain
     * startService, never startForegroundService: a recreated component must
     * not owe a startForeground call for what is only a stop. Sent while the
     * component is alive, the command reaches the live instance; if the
     * component is already gone it is briefly recreated, finds no tunnel and
     * stops itself — with {@code die}, it takes the process down too.
     */
    private static void deliverStop(Context app, boolean onlyIfBound, boolean die) {
        if (onlyIfBound && liveConnections.isEmpty()) return;
        try {
            app.startService(new Intent(app, PsiphonTunnelService.class)
                    .setAction(ACTION_STOP)
                    .putExtra(EXTRA_DIE, die));
        } catch (Throwable ignored) {
            // Background-start refusal or the caller dying: stopService
            // still destroys the component, as before.
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        session = intent.getLongExtra("psiSession", -1);
        onStartCommand(intent, 0, 0);
        return new android.os.Binder();
    }

    /** Local-proxy bind host, derived from the same flag as ListenInterface. */
    private String proxyBindHost() {
        return lanSharing ? "0.0.0.0" : "127.0.0.1";
    }

    /** " (LAN 192.168.1.5:port)" once the address is known, else "". */
    private String lanSuffix(int port) {
        if (!lanSharing || lanAddress.isEmpty()) return "";
        return " (LAN " + lanAddress + ":" + port + ")";
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
            // Upstream resolves "any" to 0.0.0.0; empty means loopback-only.
            o.put("ListenInterface", lanSharing ? "any" : "");
            o.put("EmitDiagnosticNotices", true);
            // Keep Psiphon's own server-entry scan enabled. This scan is the
            // source of AvailableEgressRegions; do not derive regions from
            // connected-server notices or from a local country list.
            o.put("DisableServerEntriesReporter", false);
            o.put("UseIndistinguishableTLS", true);
                        // tunnel-core's own resolver binds to the underlying network, so
                        // its bootstrap lookups never leave through the TUN — and carriers
                        // that hijack UDP/53 answer with a bogon, leaving the tunnel at
                        // CandidateServers 0. Pin public resolvers on alternate ports:
                        // Alternate always, Preferred at 1.0 (the default 0.0 configures
                        // the list but never picks it), and no default-resolver escape.
            org.json.JSONArray bootstrapDns = new org.json.JSONArray();
            bootstrapDns.put("208.67.222.222:5353");
            bootstrapDns.put("9.9.9.9:9953");
            bootstrapDns.put("208.67.220.220:5353");
            o.put("DNSResolverAlternateServers", bootstrapDns);
            o.put("DNSResolverPreferredAlternateServers", bootstrapDns);
            o.put("DNSResolverPreferAlternateServerProbability", 1.0);
            o.put("DNSResolverAttemptsPerPreferredServer", 2);
            o.put("AllowDefaultDNSResolverWithBindToDevice", false);
            // Frequent byte-count notices: they feed onBytesTransferred,
            // which drives the notification counters. Without this a working
            // tunnel shows 0 B.
            o.put("EmitBytesTransferred", true);
            // Do not volunteer this device as an in-proxy proxy. This does
            // NOT disable client dialing: Auto follows tunnel-core/tactics,
            // including INPROXY-WEBRTC transports. InproxyEnabled is not a
            // core field; InproxyAllowClient is a server-side parameter.
            o.put("InproxyEnableProxy", false);
            // Transport family restriction: Auto (0) leaves the field out so
            // tunnel-core tries its full default protocol set.
            String[] protocols = transportProtocols(transport);
            if (protocols.length > 0) {
                org.json.JSONArray a = new org.json.JSONArray();
                for (String pr : protocols) a.put(pr);
                o.put("LimitTunnelProtocols", a);
                // An explicit transport choice must beat server agility:
                // tunnel-core applies the tactics payload AFTER the config
                // values and the last map wins, so production tactics
                // carrying LimitTunnelProtocols silently replaced the
                // spinner's pick — the option appeared to do nothing.
                // DisableTactics skips tactics requests and parameter
                // application; Auto leaves tactics fully enabled.
                // Exception: in-proxy dials get their broker parameters
                // through the broker's tactics, so pinning an in-proxy-only
                // set must leave tactics running or the handshake never
                // starts.
                if (!protocols[0].startsWith("INPROXY-")) o.put("DisableTactics", true);
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
            // (servers, API calls, remote server list fetches) go through this
            // proxy — Aether's local SOCKS. tunnel-core accepts socks5://,
            // socks4a:// and http:// here (upstream upstreamproxy/README.md).
            if (!upstreamProxy.isEmpty()) {
                o.put("UpstreamProxyURL", normalizeUpstreamProxyUrl(upstreamProxy));
            }
            // Entry-level signature verification (see the constant's comment).
            if (!o.has("ServerEntrySignaturePublicKey")) {
                o.put("ServerEntrySignaturePublicKey", DEFAULT_SERVER_ENTRY_SIGNATURE_KEY);
            }
            // Out-of-band server entries: the LEGACY PUBLIC remote server
            // list (the URL + signature key the open-source Psiphon 3
            // clients shipped). This is what makes an unprovisioned build connect on a
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

    /** Spinner index -> protocol name; index 0 = Auto (no restriction).
     *  One entry is exactly one protocol, named with the verbatim constant
     *  from tunnel-core's protocol.go SupportedTunnelProtocols -- an
     *  unsupported name (or the client-disabled TAPDANCE-OSSH) fails config
     *  validation and the whole start. Index order is stable across
     *  versions so persisted selections never remap; new protocols append.
     *  Keep in step with the spinner adapter in MainActivity and with
     *  merge_psiphon_transport in src_cpp/ui_render.h. */
    private static final String[] TRANSPORT_PROTOCOLS = {
            "",                                    // 0: Auto
            "SSH",
            "OSSH",
            "TLS-OSSH",
            "SHADOWSOCKS-OSSH",
            "QUIC-OSSH",
            "UNFRONTED-MEEK-OSSH",
            "UNFRONTED-MEEK-HTTPS-OSSH",
            "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            "FRONTED-MEEK-OSSH",
            "FRONTED-MEEK-HTTP-OSSH",
            "FRONTED-MEEK-QUIC-OSSH",
            "CONJURE-OSSH",
            "INPROXY-WEBRTC-SSH",
            "INPROXY-WEBRTC-OSSH",
            "INPROXY-WEBRTC-TLS-OSSH",
            "INPROXY-WEBRTC-SHADOWSOCKS-OSSH",
            "INPROXY-WEBRTC-QUIC-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
            "INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
            "INPROXY-WEBRTC-FRONTED-MEEK-QUIC-OSSH",
    };

    static String[] transportProtocols(int selection) {
        if (selection <= 0 || selection >= TRANSPORT_PROTOCOLS.length) return new String[0];
        return new String[]{TRANSPORT_PROTOCOLS[selection]};
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
                String raw = out.toString("UTF-8");
                java.util.TreeSet<String> embeddedRegions = scanRegionLines(raw);
                if (!embeddedRegions.isEmpty()) mergeReportedRegions(embeddedRegions, "embedded");
                return raw;
            }
        } catch (Exception ignored) {
            // No bundled asset — the normal case.
        }
        return "";
    }

    private void persistReportedRegions(String csv) {
        File target = new File(getFilesDir(), REGIONS_FILE);
        File temporary = new File(getFilesDir(), REGIONS_FILE + ".tmp");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(temporary, false)) {
            out.write(csv.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.flush();
            if (!temporary.renameTo(target)) temporary.delete();
        } catch (Exception e) {
            temporary.delete();
            Log.w(TAG, "unable to persist Psiphon regions", e);
        }
    }

    /** Replay the non-empty learned list when the Activity returns from the background. */
    private void broadcastRegions() {
        if (lastRegions.isEmpty() || stopping) return;
        Intent i = new Intent(BROADCAST_REGIONS);
        i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
        i.putExtra(EXTRA_REGIONS, lastRegions);
        sendBroadcast(i);
    }

    private final Object regionsLock = new Object();
    private final java.util.concurrent.atomic.AtomicBoolean remoteRegionsFetching =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /** Union a newly reported region set into the learned list, persist it for
     *  the UI process and notify listeners. Sources differ in authority — core
     *  notices reflect dial candidates in the datastore, the remote list
     *  reflects the advertised network — the union answers "pick a region that
     *  can plausibly work", which is what the selector is for. */
    private void mergeReportedRegions(java.util.Collection<String> reported, String source) {
        if (reported == null || stopping) return;
        java.util.TreeSet<String> set = new java.util.TreeSet<>();
        for (String r : reported) {
            if (r == null) continue;
            String t = r.trim().toUpperCase(java.util.Locale.US);
            if (!t.isEmpty()) set.add(t);
        }
        if (set.isEmpty()) return;
        synchronized (regionsLock) {
            for (String r : lastRegions.split(",")) {
                String t = r.trim().toUpperCase(java.util.Locale.US);
                if (!t.isEmpty()) set.add(t);
            }
            String merged = android.text.TextUtils.join(",", set);
            if (merged.equals(lastRegions)) return;
            lastRegions = merged;
            persistReportedRegions(lastRegions);
        }
        emitLog("regions (" + source + "): " + lastRegions);
        broadcastRegions();
    }

    /** Actively derive the egress-region list from the same remote server
     *  list the tunnel core downloads (plain HTTPS, zlib package of hex
     *  entries — verified by the core on its own import; consumed here for
     *  discovery only). Hydrates from the persisted replay when it is fresh;
     *  otherwise fetches on a worker thread, deduplicated across connects. */
    private void fetchRemoteServerRegions() {
        File replay = new File(getFilesDir(), REGIONS_FILE);
        if (replay.isFile() && System.currentTimeMillis() - replay.lastModified() < 12L * 3600 * 1000) {
            try {
                String[] cached = new String(readAll(replay), java.nio.charset.StandardCharsets.UTF_8)
                        .split(",");
                if (cached.length > 0) {
                    mergeReportedRegions(java.util.Arrays.asList(cached), "replay");
                    return;
                }
            } catch (Exception ignored) {
            }
        }
        if (!remoteRegionsFetching.compareAndSet(false, true)) return;
        new Thread(() -> {
            java.util.TreeSet<String> regions = new java.util.TreeSet<>();
            try {
                java.net.HttpURLConnection conn =
                        (java.net.HttpURLConnection) new java.net.URL(DEFAULT_SERVER_LIST_URL).openConnection();
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(30000);
                try {
                    if (conn.getResponseCode() != java.net.HttpURLConnection.HTTP_OK) return;
                    java.util.zip.InflaterInputStream in = new java.util.zip.InflaterInputStream(conn.getInputStream());
                    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                        if (out.size() > 16 * 1024 * 1024) return;
                    }
                    regions = scanRegionLines(new String(out.toByteArray(),
                            java.nio.charset.StandardCharsets.UTF_8));
                } finally {
                    conn.disconnect();
                }
            } catch (Exception ignored) {
            } finally {
                remoteRegionsFetching.set(false);
            }
            if (!regions.isEmpty()) mergeReportedRegions(regions, "remote-list");
        }, "psi-remote-regions").start();
    }

    /** Extract region codes from either representation of the psiphon server
     *  list: the signed download package {"data":"<hex lines>",...} or a bare
     *  body of one entry per line (hex-encoded or plaintext JSON). */
    private static java.util.TreeSet<String> scanRegionLines(String text) {
        java.util.TreeSet<String> regions = new java.util.TreeSet<>();
        if (text == null) return regions;
        String body = text.trim();
        if (body.isEmpty()) return regions;
        if (body.startsWith("{")) {
            try {
                body = new JSONObject(body).optString("data", "");
            } catch (Exception ignored) {
                return regions;
            }
        }
        for (String line : body.split("\n")) {
            line = line.trim();
            if (line.isEmpty()) continue;
            try {
                String entry = line;
                if (!line.startsWith("{")) {
                    byte[] raw = hexToBytes(line);
                    if (raw != null)
                        entry = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
                    int brace = entry.indexOf('{');
                    // Legacy entries carry a numeric padding prefix ahead of
                    // the JSON object; drop it.
                    if (brace < 0) continue;
                    entry = entry.substring(brace);
                }
                String region = new JSONObject(entry).optString("region", "")
                        .trim().toUpperCase(java.util.Locale.US);
                if (region.length() == 2) regions.add(region);
            } catch (Exception ignored) {
            }
        }
        return regions;
    }

    private static byte[] hexToBytes(String hex) {
        int n = hex.length();
        if ((n & 1) != 0) return null;
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
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
        try {
            networkBinding.bindSocket(fileDescriptor);
        } catch (java.io.IOException | RuntimeException error) {
            throw new PsiphonTunnel.Exception("bindToDevice failed", error);
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
            } else if (message.contains("ConnectedServerRegion")) {
                handshakeRegion = true;
                broadcastStage(4, "ESTABLISHING TUNNEL");
                maybeBroadcastReady();
            } else if (message.contains("\"noticeType\":\"ConnectedServer\"")
                    || message.contains("\"noticeType\":\"ActiveTunnel\"")) {
                broadcastStage(4, "ESTABLISHING TUNNEL");
            }
        }
        tryMineRegionsFromNotice(message);
        emitLog(message);
    }

    // The AvailableEgressRegions payload traverses this channel as raw JSON
    // regardless of the typed AAR callback, so the selector list is derived
    // here too — region discovery must not hinge on a single notice-to-
    // callback chain.
    private void tryMineRegionsFromNotice(String message) {
        if (stopping || message == null || !message.contains("\"AvailableEgressRegions\"")) return;
        try {
            JSONObject data = new JSONObject(message).optJSONObject("data");
            if (data == null) return;
            org.json.JSONArray reported = data.optJSONArray("regions");
            if (reported == null || reported.length() == 0) return;
            java.util.ArrayList<String> regions = new java.util.ArrayList<>(reported.length());
            for (int i = 0; i < reported.length(); i++) regions.add(reported.optString(i, ""));
            mergeReportedRegions(regions, "core-notice");
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        socksPort.set(port);
        if (!stopping) broadcastStage(5, "ESTABLISHING TUNNEL");
        emitLog("SOCKS " + proxyBindHost() + ":" + port + lanSuffix(port));
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        httpPort.set(port);
        emitLog("HTTP " + proxyBindHost() + ":" + port + lanSuffix(port));
    }

    @Override
    public void onBytesTransferred(long sent, long received) {
        // Values are deltas since the previous notice — accumulate.
        if (sent <= 0 && received <= 0) return;
        bytesUp.addAndGet(Math.max(0, sent));
        bytesDown.addAndGet(Math.max(0, received));
    }

    @Override
    public void onAvailableEgressRegions(List<String> regions) {
        mergeReportedRegions(regions, "core");
    }

    @Override
    public void onConnected() {
        if (stopping) return;
        psiphonUp = true;
        handshakeConnected = true;
        int s = socksPort.get();
        PsiphonTunnel t = liveTunnel;
        if (s <= 0 && t != null) s = t.getLocalSocksProxyPort();
        socksPort.set(s);
        emitLog("connected, SOCKS " + proxyBindHost() + ":" + s + lanSuffix(s));
        flushLogs();
        // Last-chance discovery when nothing reported regions during
        // establishing (e.g. a stale replay older than the freshness window).
        if (lastRegions.isEmpty()) fetchRemoteServerRegions();
        startStatsLoop();
        maybeBroadcastReady();
    }

    private synchronized void maybeBroadcastReady() {
        if (stopping || readyBroadcast) return;
        if (!handshakeConnected || !handshakeRegion) return;
        int s = socksPort.get();
        PsiphonTunnel t = liveTunnel;
        if (s <= 0 && t != null) s = t.getLocalSocksProxyPort();
        if (s > 0) socksPort.set(s);
        readyBroadcast = true;
        Intent i = new Intent(BROADCAST_READY);
        i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
        i.putExtra(EXTRA_SOCKS, s);
        i.putExtra(EXTRA_LAN, lanSharing ? lanAddress : "");
        i.putExtra(EXTRA_HTTP, httpPort.get());
        if (!lastRegions.isEmpty()) i.putExtra(EXTRA_REGIONS, lastRegions);
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

    // Keep notice JSON and diagnostic text intact. Batching is only transport,
    // not a severity/content filter. Small logcat chunks avoid its entry limit.
    private void emitLog(String message) {
        if (message == null || message.isEmpty()) return;
        for (int offset = 0; offset < message.length();) {
            int end = chunkEnd(message, offset, 1000);
            Log.i(TAG, message.substring(offset, end));
            offset = end;
        }
        boolean flushNow;
        synchronized (logBuf) {
            if (logBuf.length() > 0) logBuf.append('\n');
            logBuf.append("[psiphon] ").append(message);
            // Flush bursts instead of silently deleting the oldest notices.
            flushNow = logBuf.length() >= 12000;
            if (!logFlushPending) {
                logFlushPending = true;
                logHandler.postDelayed(flushLogs, 250L);
            }
        }
        if (flushNow) flushLogs();
    }

    private static int chunkEnd(String text, int offset, int limit) {
        int end = Math.min(text.length(), offset + limit);
        if (end < text.length() && Character.isHighSurrogate(text.charAt(end - 1))) end--;
        return end;
    }

    private synchronized void flushLogs() {
        logHandler.removeCallbacks(flushLogs);
        String chunk;
        synchronized (logBuf) {
            logFlushPending = false;
            if (logBuf.length() == 0) return;
            chunk = logBuf.toString();
            logBuf.setLength(0);
        }
        // Stay well below Binder's transaction limit, even for a large JSON
        // notice. Every character is delivered; the UI retains a bounded tail.
        for (int offset = 0; offset < chunk.length();) {
            int end = chunkEnd(chunk, offset, 12000);
            Intent i = new Intent(BROADCAST_LOG);
            i.setPackage(getPackageName());
            i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
            i.putExtra(EXTRA_LOG, chunk.substring(offset, end));
            sendBroadcast(i);
            offset = end;
        }
    }

    /**
     * While the tunnel is up, publishes byte rates, cumulative totals and
     * tunnel RTT every 1 s as BROADCAST_STATS — the same cadence (and rate
     * window) as the native telemetry pump, so the notification and the
     * Psiphon-only UI refresh their bytes/s once per second everywhere. RTT is one HTTP round trip
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
                    Thread.sleep(1000L);
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
                if (lastRttMs == 0 && rttAttempts < 12 && port > 0 && now >= nextRttProbeAt) {
                    rttAttempts++;
                    nextRttProbeAt = now + (1L << Math.min(rttAttempts, 3)) * 1000L;
                    Integer r = probeTunnelRtt(port);
                    if (r != null) lastRttMs = r;
                }
                Intent i = new Intent(BROADCAST_STATS);
                i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
                i.putExtra(EXTRA_LAN, lanSharing ? lanAddress : "");
                i.putExtra(EXTRA_SOCKS, socksPort.get());
                i.putExtra(EXTRA_HTTP, httpPort.get());
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
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(s.getInputStream(), java.nio.charset.StandardCharsets.US_ASCII));
            String status = reader.readLine();
            // Connectivity-check endpoints may answer 204, 200, or another
            // successful 2xx response depending on the exit and cache path.
            if (status == null || !status.matches("HTTP/1\\.[01] [23]\\d\\d(?: .*|)")) return null;
            return (int) Math.max(1L, System.currentTimeMillis() - t0);
        } catch (Exception e) {
            return null;
        } finally {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    private void broadcastFailed(String msg) {
        emitLog("failed: " + (msg == null ? "failed" : msg));
        flushLogs();
        Intent i = new Intent(BROADCAST_FAILED);
        i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
        i.putExtra(EXTRA_ERROR, msg == null ? "failed" : msg);
        sendBroadcast(i);
    }

    private void broadcastStopped() {
        Intent i = new Intent(BROADCAST_STOPPED);
        i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
        sendBroadcast(i);
    }

    /** Staged connect progress for the UI (see BROADCAST_STAGE). */
    private void broadcastStage(int stage, String label) {
        Intent i = new Intent(BROADCAST_STAGE);
        i.setPackage(getPackageName());
        i.putExtra("psiSession", session);
        i.putExtra("requestId", attachRequestId);
        i.putExtra(EXTRA_STAGE, stage);
        i.putExtra(EXTRA_STAGE_LABEL, label);
        sendBroadcast(i);
    }

    private static final class PsiphonNetworkBinding implements AutoCloseable {
        private final ConnectivityManager manager;
        private final Object lock = new Object();
        private ConnectivityManager.NetworkCallback callback;
        private Network network;

        PsiphonNetworkBinding(Context context) {
            manager = context.getSystemService(ConnectivityManager.class);
        }

        void start() throws IOException {
            synchronized (lock) {
                if (callback != null) return;
                if (manager == null) throw new IOException("ConnectivityManager unavailable");
                ConnectivityManager.NetworkCallback next = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network available) {
                        synchronized (lock) {
                            if (callback != this) return;
                            try {
                                if (!available.equals(manager.getBoundNetworkForProcess())
                                        && !manager.bindProcessToNetwork(available)) {
                                    network = null;
                                    Log.w(TAG, "Unable to bind Psiphon to the physical network");
                                    return;
                                }
                                network = available;
                            } catch (RuntimeException error) {
                                network = null;
                                Log.w(TAG, "Physical network binding failed", error);
                            }
                        }
                    }

                    @Override
                    public void onLost(Network lost) {
                        synchronized (lock) {
                            if (callback == this && lost.equals(network)) network = null;
                        }
                    }
                };
                callback = next;
                try {
                    manager.requestNetwork(new NetworkRequest.Builder()
                            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                            .build(), next);
                } catch (RuntimeException error) {
                    callback = null;
                    throw new IOException("Cannot monitor the physical network", error);
                }
            }
        }

        void bindSocket(long fileDescriptor) throws IOException {
            if (fileDescriptor < 0 || fileDescriptor > Integer.MAX_VALUE) {
                throw new IOException("Invalid socket descriptor");
            }
            final Network selected;
            synchronized (lock) {
                selected = network;
            }
            if (selected == null) throw new IOException("No physical network available");
            try (ParcelFileDescriptor borrowed = ParcelFileDescriptor.fromFd((int) fileDescriptor)) {
                selected.bindSocket(borrowed.getFileDescriptor());
            }
        }

        @Override
        public void close() {
            final ConnectivityManager.NetworkCallback previous;
            synchronized (lock) {
                previous = callback;
                callback = null;
                network = null;
            }
            if (previous != null && manager != null) {
                try {
                    manager.unregisterNetworkCallback(previous);
                } catch (RuntimeException error) {
                    Log.w(TAG, "Physical network callback cleanup failed", error);
                }
            }
        }
    }
}
