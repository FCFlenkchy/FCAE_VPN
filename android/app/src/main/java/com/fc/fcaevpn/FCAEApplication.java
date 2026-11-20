package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

import java.util.concurrent.atomic.AtomicInteger;

/** Tracks UI ownership separately from visibility for safe background cleanup. */
public class FCAEApplication extends Application {

    private static final AtomicInteger visibleActivities = new AtomicInteger();
    // A minimized MainActivity still owns an ImGui context. Visibility alone
    // must not authorize nativeFree()/process exit during remote Disconnect.
    private static final AtomicInteger uiActivities = new AtomicInteger();
    private static volatile String logFilePath = "";
    public static String logFilePath() { return logFilePath; }

    /** When the UI last appeared or disappeared, for {@link #uiOnScreen()}. */
    private static volatile long lastVisibilityChangeAt = 0L;

    /** Keeps a recently hidden UI visible through rotation without treating it as an intent to stay. */
    private static final long VISIBLE_GRACE_MS = 1500L;

    public static boolean uiSessionAlive() {
        return uiActivities.get() > 0;
    }

    public static boolean uiVisibleNow() {
        return visibleActivities.get() > 0;
    }

    public static boolean uiOnScreen() {
        if (uiVisibleNow()) return true;
        return android.os.SystemClock.elapsedRealtime() - lastVisibilityChangeAt
                < VISIBLE_GRACE_MS;
    }

    private final ActivityLifecycleCallbacks callbacks = new ActivityLifecycleCallbacks() {
        @Override public void onActivityCreated(Activity activity, Bundle state) {
            if (activity instanceof MainActivity) {
                uiActivities.incrementAndGet();
                ProcessExit.cancel();
            }
        }
        @Override public void onActivityStarted(Activity activity) {
            visibleActivities.incrementAndGet();
            lastVisibilityChangeAt = android.os.SystemClock.elapsedRealtime();
            if (activity instanceof MainActivity) ProcessExit.cancel();
        }
        @Override public void onActivityResumed(Activity activity) {
            if (activity instanceof MainActivity) ProcessExit.cancel();
        }
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {
            visibleActivities.decrementAndGet();
            lastVisibilityChangeAt = android.os.SystemClock.elapsedRealtime();
        }
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
        @Override public void onActivityDestroyed(Activity activity) {
            if (activity instanceof MainActivity) uiActivities.decrementAndGet();
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        logFilePath = new java.io.File(getFilesDir(), "logs.txt").getAbsolutePath();
        registerActivityLifecycleCallbacks(callbacks);
    }
}
