package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;

import java.util.concurrent.atomic.AtomicInteger;

/** Tracks whether services may end the process because no app Activity is visible. */
public class FCAEApplication extends Application {

    private static final AtomicInteger visibleActivities = new AtomicInteger();

    /** When the UI last appeared or disappeared, for {@link #uiOnScreen()}. */
    private static volatile long lastVisibilityChangeAt = 0L;

    /** Keeps a recently hidden UI visible through rotation without treating it as an intent to stay. */
    private static final long VISIBLE_GRACE_MS = 1500L;

    public static boolean uiVisibleNow() {
        return visibleActivities.get() > 0;
    }

    public static boolean uiOnScreen() {
        if (uiVisibleNow()) return true;
        return android.os.SystemClock.elapsedRealtime() - lastVisibilityChangeAt
                < VISIBLE_GRACE_MS;
    }

    private final BroadcastReceiver psiphonLogReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (!PsiphonTunnelService.isCurrentBroadcast(intent)) return;
            String chunk = intent.getStringExtra(PsiphonTunnelService.EXTRA_LOG);
            if (chunk == null || chunk.trim().isEmpty()) return;
            try {
                if (NativeEngine.ensureLoaded()) NativeEngine.nativeAppendLog(chunk);
            } catch (Throwable ignored) { }
        }
    };

    private final ActivityLifecycleCallbacks callbacks = new ActivityLifecycleCallbacks() {
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityStarted(Activity activity) {
            visibleActivities.incrementAndGet();
            lastVisibilityChangeAt = android.os.SystemClock.elapsedRealtime();
        }
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {
            visibleActivities.decrementAndGet();
            lastVisibilityChangeAt = android.os.SystemClock.elapsedRealtime();
        }
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
        @Override public void onActivityDestroyed(Activity activity) {}
    };

    @Override public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(callbacks);
        if (getPackageName().equals(Application.getProcessName())) {
            androidx.core.content.ContextCompat.registerReceiver(this, psiphonLogReceiver,
                    new IntentFilter(PsiphonTunnelService.BROADCAST_LOG),
                    androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED);
        }
    }
}
