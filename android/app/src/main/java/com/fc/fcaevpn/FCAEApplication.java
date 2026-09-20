package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

/** Activity lifecycle registration only; services own background session lifetime. */
public class FCAEApplication extends Application {
    private final ActivityLifecycleCallbacks callbacks = new ActivityLifecycleCallbacks() {
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityStarted(Activity activity) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivityStopped(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
        @Override public void onActivityDestroyed(Activity activity) {}
    };

    @Override public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(callbacks);
    }
}
