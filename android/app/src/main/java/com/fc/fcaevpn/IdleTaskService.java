package com.fc.fcaevpn;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;

public class IdleTaskService extends Service {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean taskRemoved;
    private long taskRemovedAt;
    private final Runnable check = new Runnable() {
        @Override public void run() {
            if (!taskRemoved) return;
            if (FCAEApplication.uiVisibleNow()) {
                if (SystemClock.elapsedRealtime() - taskRemovedAt >= 2000L) {
                    stopSelf();
                } else {
                    handler.postDelayed(this, 250L);
                }
                return;
            }
            if (FCAEApplication.uiOnScreen()) {
                handler.postDelayed(this, 750L);
                return;
            }
            if (SessionState.snapshot(IdleTaskService.this).getActive()
                    && SessionState.isLive()) {
                stopSelf();
                return;
            }
            if (SessionState.commandInFlight()
                    || FCAEVpnService.sessionActive()
                    || ProxyNotification.sessionActive()) {
                handler.postDelayed(this, 750L);
                return;
            }
            SessionState.command(SessionState.Command.NONE);
            SessionState.markIdle(IdleTaskService.this);
            try { PsiphonTunnelService.killProcessOnExit(IdleTaskService.this); }
            catch (Throwable ignored) {}
            ProcessExit.request(IdleTaskService.this);
            stopSelf();
        }
    };

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        taskRemoved = false;
        handler.removeCallbacks(check);
        return START_NOT_STICKY;
    }

    @Override public void onTaskRemoved(Intent rootIntent) {
        taskRemoved = true;
        taskRemovedAt = SystemClock.elapsedRealtime();
        handler.post(check);
        super.onTaskRemoved(rootIntent);
    }

    @Override public void onDestroy() {
        handler.removeCallbacks(check);
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
