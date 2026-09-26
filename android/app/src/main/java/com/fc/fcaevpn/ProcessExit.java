package com.fc.fcaevpn;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import java.util.concurrent.atomic.AtomicLong;

public final class ProcessExit {
    private static final Handler main = new Handler(Looper.getMainLooper());
    private static final AtomicLong ticket = new AtomicLong();
    private static final long UI_GRACE_MS = 1600L;
    private static final long CLEANUP_DEADLINE_MS = 7000L;

    private ProcessExit() {}

    /** A new connect can be pending before the service bumps its generation. */
    public static void cancel() {
        ticket.incrementAndGet();
    }

    public static void request(Context context) {
        request(context, false);
    }

    /** A widget, tile or notification Disconnect explicitly ends the process;
     *  an in-app Disconnect leaves the visible Activity ready to reconnect. */
    public static void request(Context context, boolean remoteDisconnect) {
        Context app = context.getApplicationContext();
        long request = ticket.incrementAndGet();
        long generation = FCAEVpnService.stateGeneration();
        long started = SystemClock.elapsedRealtime();
        Runnable finish = () -> {
            boolean deadline = SystemClock.elapsedRealtime() - started >= CLEANUP_DEADLINE_MS;
            if (request == ticket.get() && mayExit(app, generation, true, deadline, remoteDisconnect)) {
                FCAEVpnService.killProcessQuietly();
            }
        };
        main.postDelayed(finish, CLEANUP_DEADLINE_MS);
        if (!NativeEngine.Loaded.value) {
            main.postDelayed(finish, UI_GRACE_MS);
            return;
        }
        try {
            NativeEngine.lifecycleExecutor.execute(() -> {
                if (request == ticket.get() && mayExit(app, generation, false, false, remoteDisconnect)) {
                    try { NativeEngine.nativeStopBegin(); } catch (Throwable ignored) {}
                    try { NativeEngine.nativeFree(); } catch (Throwable ignored) {}
                }
                long remaining = UI_GRACE_MS - (SystemClock.elapsedRealtime() - started);
                main.postDelayed(finish, Math.max(0L, remaining));
            });
        } catch (Throwable ignored) {
            main.postDelayed(finish, UI_GRACE_MS);
        }
    }

    private static boolean mayExit(Context app, long generation,
                                   boolean afterGrace, boolean deadline,
                                   boolean remoteDisconnect) {
        if (generation != FCAEVpnService.stateGeneration()) return false;
        if (!remoteDisconnect && (afterGrace ? FCAEApplication.uiOnScreen()
                                              : FCAEApplication.uiVisibleNow())) return false;
        if (FCAEVpnService.sessionActive() || ProxyNotification.sessionActive()) {
            // A remote Disconnect that never reached the owner would otherwise
            // pin this process forever. After the deadline the command stands.
            if (!remoteDisconnect || !deadline) return false;
        }
        if (!deadline && FCAEVpnService.ownsSession()) return false;
        return !SessionState.commandInFlight() || !SessionState.snapshot(app).getActive();
    }
}
