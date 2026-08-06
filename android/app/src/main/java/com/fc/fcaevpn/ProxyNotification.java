package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

public class ProxyNotification extends Service {

    private static final String TAG = "FCAE_ProxyNotif";

    public static final String ACTION_START = "com.fc.fcaevpn.PROXY_START";
    public static final String ACTION_STOP  = "com.fc.fcaevpn.PROXY_STOP";

    public static final int NOTIFICATION_ID = 200;
    private static final String CHANNEL_ID = "fcae_proxy";

    private volatile boolean running = false;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getAction() != null) {
            switch (intent.getAction()) {
                case ACTION_START:
                    if (!running) {
                        running = true;
                        try {
                            startForeground(NOTIFICATION_ID, build("Proxy running", true));
                        } catch (Exception e) {
                            Log.e(TAG, "startForeground failed: " + e.getMessage());
                        }
                        try { NativeEngine.nativeInit(); } catch (Exception ignored) {}
                        Log.i(TAG, "proxy started");
                    }
                    return START_STICKY;

                case ACTION_STOP:
                    running = false;
                    try { NativeEngine.nativeStop(); } catch (Exception ignored) {}
                    
                    try {
                        stopForeground(STOP_FOREGROUND_REMOVE);
                    } catch (Exception e) {
                        Log.w(TAG, "stopForeground failed: " + e.getMessage());
                    }
                    
                    stopSelf();
                    Log.i(TAG, "proxy stopped");
                    return START_NOT_STICKY;
            }
        }
        return START_STICKY;
    }

    private Notification build(String text, boolean ongoing) {
        Intent stopIntent = new Intent(this, ProxyNotification.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent openIntent = getPackageManager().getLaunchIntentForPackage(getPackageName());
        PendingIntent openPi = PendingIntent.getActivity(this, 2, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }

        b.setContentTitle("FCAE VPN")
         .setContentText(text)
         .setSmallIcon(android.R.drawable.ic_lock_lock)
         .setContentIntent(openPi)
         .setOngoing(ongoing)
         .setOnlyAlertOnce(true);

        if (ongoing) {
            b.addAction(new Notification.Action.Builder(null, "Stop", stopPi).build());
        }

        return b.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE Proxy", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
