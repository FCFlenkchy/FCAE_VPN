package com.fc.fcaevpn;

import android.app.Application;
import android.content.ComponentCallbacks2;
import android.content.res.Configuration;
import android.util.Log;

/**
 * Owns the "nothing is running, so do not linger" rule.
 *
 * An Activity cannot observe its task being removed — {@code onTaskRemoved}
 * is a {@link android.app.Service} callback, and the activity is already
 * destroyed by the time the process gets the memory signal. Registering here
 * instead covers both cases the rule cares about: the task being swiped away,
 * and a process left with no activity at all.
 */
public class FCAEApplication extends Application {

    private static final String TAG = "FCAE_APP";

    private final ComponentCallbacks2 reaper = new ComponentCallbacks2() {
        @Override
        public void onTrimMemory(int level) {
            if (level != ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) return;
            // A live session is torn down by the service that owns it — both
            // services get their own onTaskRemoved and end the process once
            // their engine has stopped. Only an idle process is reaped here.
            if (ProxyNotification.isAlive() || FCAEVpnService.ownsSession()) return;
            Log.i(TAG, "UI gone and nothing connected — ending the process");
            try {
                PsiphonTunnelService.killProcessOnExit(FCAEApplication.this);
            } catch (Throwable ignored) {
            }
            FCAEVpnService.killProcessQuietly();
        }

        @Override
        public void onConfigurationChanged(Configuration newConfig) {
        }

        @Override
        public void onLowMemory() {
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        registerComponentCallbacks(reaper);
    }
}
