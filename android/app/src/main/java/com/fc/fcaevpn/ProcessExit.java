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

    public static void request(Context context) {
        Context app = context.getApplicationContext();
        long request = ticket.incrementAndGet();
        long generation = FCAEVpnService.stateGeneration();
        long started = SystemClock.elapsedRealtime();
        Runnable finish = () -> {
            boolean deadline = SystemClock.elapsedRealtime() - started >= CLEANUP_DEADLINE_MS;
            if (request == ticket.get() && mayExit(app, generation, true, deadline)) {
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
                if (request == ticket.get() && mayExit(app, generation, false, false)) {
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
                                   boolean afterGrace, boolean deadline) {
        if (generation != FCAEVpnService.stateGeneration()) return false;
        if (afterGrace ? FCAEApplication.uiOnScreen() : FCAEApplication.uiVisibleNow()) return false;
        if (FCAEVpnService.sessionActive() || ProxyNotification.sessionActive()) return false;
        if (!deadline && FCAEVpnService.ownsSession()) return false;
        return !SessionState.commandInFlight() || !SessionState.snapshot(app).getActive();
    }
}
