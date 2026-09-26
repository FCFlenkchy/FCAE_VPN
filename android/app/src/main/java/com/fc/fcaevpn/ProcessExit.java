package com.fc.fcaevpn;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class ProcessExit {
    private static final Handler main = new Handler(Looper.getMainLooper());
    private static final AtomicLong ticket = new AtomicLong();
    private static final AtomicLong terminalStartedAt = new AtomicLong();
    private static final AtomicBoolean terminalPending = new AtomicBoolean();
    private static final long UI_GRACE_MS = 250L;
    private static final long CLEANUP_DEADLINE_MS = 2000L;

    private ProcessExit() {}

    /** A new connect can be pending before the service bumps its generation. */
    public static void cancel() {
        terminalPending.set(false);
        terminalStartedAt.set(0L);
        ticket.incrementAndGet();
    }

    public static void request(Context context) {
        request(context, false);
    }

    public static boolean deferForTileBinding() {
        if (!terminalPending.get()) return false;
        ticket.incrementAndGet();
        return true;
    }

    /** A widget, tile or notification Disconnect explicitly ends the process;
     *  an in-app Disconnect leaves the visible Activity ready to reconnect. */
    public static void request(Context context, boolean remoteDisconnect) {
        Context app = context.getApplicationContext();
        boolean terminal = remoteDisconnect || terminalPending.get();
        long now = SystemClock.elapsedRealtime();
        if (terminal) {
            terminalPending.set(true);
            terminalStartedAt.compareAndSet(0L, now);
        }
        long request = ticket.incrementAndGet();
        long started = terminal ? terminalStartedAt.get() : now;
        if (terminal && now - started < CLEANUP_DEADLINE_MS
                && VpnTileService.deferTerminalExit()) {
            main.postDelayed(() -> request(app, true), UI_GRACE_MS);
            return;
        }
        Runnable finish = () -> {
            boolean deadline = SystemClock.elapsedRealtime() - started >= CLEANUP_DEADLINE_MS;
            if (request == ticket.get() && mayExit(app, true, deadline, terminal)) {
                if (terminal) stopStartedServices(app);
                FCAEVpnService.killProcessQuietly();
            }
        };
        main.postDelayed(
                finish,
                Math.max(0L, CLEANUP_DEADLINE_MS
                        - (SystemClock.elapsedRealtime() - started)));
        if (!NativeEngine.Loaded.value) {
            main.postDelayed(finish, UI_GRACE_MS);
            return;
        }
        try {
            NativeEngine.lifecycleExecutor.execute(() -> {
                if (request == ticket.get() && mayExit(app, false, false, terminal)) {
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

    private static void stopStartedServices(Context app) {
        try { app.stopService(new android.content.Intent(app, FCAEVpnService.class)); }
        catch (Throwable ignored) {}
        try { app.stopService(new android.content.Intent(app, ProxyNotification.class)); }
        catch (Throwable ignored) {}
        try { app.stopService(new android.content.Intent(app, IdleTaskService.class)); }
        catch (Throwable ignored) {}
        try { PsiphonTunnelService.killProcessOnExit(app); }
        catch (Throwable ignored) {}
    }

    private static boolean mayExit(Context app, boolean afterGrace,
                                   boolean deadline, boolean remoteDisconnect) {
        if (!remoteDisconnect && (afterGrace ? FCAEApplication.uiOnScreen()
                                              : FCAEApplication.uiVisibleNow())) return false;
        // A terminal control is the user's final instruction. A late owner
        // generation change, stale active flag, or wedged cleanup must not
        // leave the application resident forever. A real reconnect cancels
        // this request through cancel() before starting its owner.
        if (remoteDisconnect && deadline) return true;
        if (FCAEVpnService.sessionActive() || ProxyNotification.sessionActive()) return false;
        if (FCAEVpnService.ownsSession()) return false;
        return !SessionState.commandInFlight() || !SessionState.snapshot(app).getActive();
    }
}
