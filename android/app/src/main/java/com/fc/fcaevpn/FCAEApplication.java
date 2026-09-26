package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Activity lifecycle registration, and the one answer services cannot get
 * anywhere else: whether the user has this app on screen. Ending a session is
 * the app's business; ending the process is the user's.
 */
public class FCAEApplication extends Application {

    private static final AtomicInteger visibleActivities = new AtomicInteger();

    /** When the UI last appeared or disappeared, for {@link #uiOnScreen()}. */
    private static volatile long lastVisibilityChangeAt = 0L;

    /**
     * How long a UI that just went away still counts as the user's.
     *
     * Longer than a rotation and shorter than any real decision to leave. A
     * teardown must not end the process in the gap between two of the user's
     * own gestures.
     */
    private static final long VISIBLE_GRACE_MS = 1500L;

    public static boolean uiVisibleNow() {
        return visibleActivities.get() > 0;
    }

    public static boolean uiOnScreen() {
        if (uiVisibleNow()) return true;
        return android.os.SystemClock.elapsedRealtime() - lastVisibilityChangeAt
                < VISIBLE_GRACE_MS;
    }

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
    }
}
