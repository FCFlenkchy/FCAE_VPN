package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Activity lifecycle registration. Services own the session's lifetime, but they
 * need one fact this class is the only place to observe: whether the UI is on
 * screen. A session that ends with no UI behind it has nothing left to keep the
 * process for, and that is a decision a teardown has to make for itself — the
 * Activity is not there to make it.
 */
public class FCAEApplication extends Application {

    private static final AtomicInteger visibleActivities = new AtomicInteger();

    /** Whether any of this app's UI is on screen right now. */
    public static boolean hasVisibleUi() {
        return visibleActivities.get() > 0;
    }

    private final ActivityLifecycleCallbacks callbacks = new ActivityLifecycleCallbacks() {
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityStarted(Activity activity) {
            visibleActivities.incrementAndGet();
        }
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {
            visibleActivities.decrementAndGet();
        }
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
        @Override public void onActivityDestroyed(Activity activity) {}
    };

    @Override public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(callbacks);
    }
}
