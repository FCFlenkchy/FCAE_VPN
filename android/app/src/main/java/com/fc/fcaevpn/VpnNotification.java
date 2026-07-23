package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class VpnNotification {
    public static final String CHANNEL_ID = "fcaevpn_service";
    public static final int NOTIFICATION_ID = 1;
    private static final int DISCONNECT_ACTION_CODE = 11;

    private final Context context;
    private final NotificationManager manager;

    public VpnNotification(Context context) {
        this.context = context;
        this.manager = context.getSystemService(NotificationManager.class);
        createChannel();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE VPN",
                NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("FCAE VPN tunnel status");
            if (manager != null) manager.createNotificationChannel(ch);
        }
    }

    public Notification build(String text) {
        Intent mainIntent = new Intent(context, MainActivity.class);
        PendingIntent piMain = PendingIntent.getActivity(context, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(context, CHANNEL_ID);
        } else {
            nb = new Notification.Builder(context);
        }

        nb.setContentTitle("FCAE VPN")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.ic_lock_lock)
          .setContentIntent(piMain)
          .setOngoing(true)
          .setStyle(new Notification.BigTextStyle().bigText(text));

        // Disconnect button — only action
        Intent discIntent = new Intent(context, FCAEVpnService.class);
        discIntent.setAction(FCAEVpnService.ACTION_DISCONNECT);
        PendingIntent piDisc = PendingIntent.getService(context, DISCONNECT_ACTION_CODE,
            discIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        nb.addAction(new Notification.Action.Builder(null, "Disconnect", piDisc).build());

        return nb.build();
    }

    public void show(String text) {
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, build(text));
        }
    }

    public void dismiss() {
        if (manager != null) manager.cancel(NOTIFICATION_ID);
    }

    static String fmtBytes(long b) {
        if (b >= 1073741824L) return String.format("%.1f GB", b / 1073741824.0);
        if (b >= 1048576L)    return String.format("%.1f MB", b / 1048576.0);
        if (b >= 1024L)       return String.format("%.0f KB", b / 1024.0);
        return b + " B";
    }

    static String fmtRate(long bps) {
        if (bps >= 1073741824L) return String.format("%.1f GB/s", bps / 1073741824.0);
        if (bps >= 1048576L)    return String.format("%.1f MB/s", bps / 1048576.0);
        if (bps >= 1024L)       return String.format("%.0f KB/s", bps / 1024.0);
        return bps + " B/s";
    }
}
