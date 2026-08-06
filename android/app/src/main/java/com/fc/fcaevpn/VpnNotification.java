package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

public class VpnNotification {

    public static final int NOTIFICATION_ID = 100;
    private static final String CHANNEL_ID = "fcae_vpn";

    private final Context ctx;
    private final NotificationManager nm;

    public VpnNotification(Context ctx) {
        this.ctx = ctx;
        this.nm = ctx.getSystemService(NotificationManager.class);
        createChannel();
    }

    public void show(String text, boolean ongoing) {
        try {
            if (nm != null) {
                nm.notify(NOTIFICATION_ID, build(text, ongoing));
            }
        } catch (Exception e) {
            Log.w("VpnNotification", "show failed: " + e.getMessage());
        }
    }

    public void dismiss() {
        try {
            if (nm != null) {
                nm.cancel(NOTIFICATION_ID);
            }
        } catch (Exception e) {
            Log.w("VpnNotification", "dismiss failed: " + e.getMessage());
        }
    }

    public Notification build(String text, boolean ongoing) {
        Intent openIntent = ctx.getPackageManager()
            .getLaunchIntentForPackage(ctx.getPackageName());
        PendingIntent openPi = PendingIntent.getActivity(ctx, 10, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(ctx, CHANNEL_ID);
        } else {
            b = new Notification.Builder(ctx);
        }

        b.setContentTitle("FCAE VPN")
         .setContentText(text)
         .setSmallIcon(android.R.drawable.ic_lock_lock)
         .setContentIntent(openPi)
         .setOngoing(ongoing)
         .setOnlyAlertOnce(true);

        return b.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    public static String fmtBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    public static String fmtRate(long bytesPerSec) {
        if (bytesPerSec < 1024) return bytesPerSec + " B/s";
        if (bytesPerSec < 1024 * 1024) return String.format("%.1f KB/s", bytesPerSec / 1024.0);
        return String.format("%.1f MB/s", bytesPerSec / (1024.0 * 1024));
    }
}
