package com.fc.fcaevpn;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

/** Reaps an idle process after the last activity leaves the foreground. */
public class FCAEApplication extends Application {

    private static final String TAG = "FCAE_APP";
    private final Handler main = new Handler(Looper.getMainLooper());
    private int startedActivities;

    private final ActivityLifecycleCallbacks reaper = new ActivityLifecycleCallbacks() {
        @Override public void onActivityCreated(Activity activity, Bundle state) {}
        @Override public void onActivityResumed(Activity activity) {}
        @Override public void onActivityPaused(Activity activity) {}
        @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
        @Override public void onActivityDestroyed(Activity activity) {}

        @Override public void onActivityStarted(Activity activity) {
            startedActivities++;
            main.removeCallbacks(reapIfIdle);
        }

        @Override public void onActivityStopped(Activity activity) {
            if (startedActivities > 0) startedActivities--;
            if (startedActivities == 0) main.postDelayed(reapIfIdle, 500);
        }
    };

    private final Runnable reapIfIdle = () -> {
        if (startedActivities != 0
                || ProxyNotification.isAlive()
                || PsiphonTunnelService.hasActiveBinding()
                || FCAEVpnService.ownsSession()) return;
        Log.i(TAG, "UI gone and nothing connected — ending the process");
        try {
            PsiphonTunnelService.killProcessOnExit(FCAEApplication.this);
        } catch (Throwable ignored) {
        }
        FCAEVpnService.killProcessQuietly();
    };

    @Override public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(reaper);
    }
}
