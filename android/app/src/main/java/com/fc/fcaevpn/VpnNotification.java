package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

public class VpnNotification {
    public static final String CHANNEL_ID = "fcaevpn_service";
    public static final int NOTIFICATION_ID = 1;

    private final Context context;
    private final NotificationManager manager;
    // Cached PendingIntents — created once, reused every 5s notification update.
    // Saves 2 Binder IPC calls to ActivityManagerService per update.
    private final PendingIntent piMain;
    private final Notification.Action disconnectAction;
    private final Notification.Action stopAction;
    private final Notification.Action startAction;

    public VpnNotification(Context context) {
        this.context = context;
        this.manager = context.getSystemService(NotificationManager.class);
        createChannel();

        Intent mainIntent = new Intent(context, MainActivity.class);
        piMain = PendingIntent.getActivity(context, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        disconnectAction = buildAction("Disconnect", FCAEVpnService.ACTION_DISCONNECT, 11);
        stopAction = buildAction("Stop", FCAEVpnService.ACTION_STOP, 10);
        startAction = buildAction("Start", FCAEVpnService.ACTION_START, 10);
    }

    private void createChannel() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE VPN",
                NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("FCAE VPN tunnel status");
            if (manager != null) manager.createNotificationChannel(ch);
        }
    }

    public Notification build(String text, boolean showStopButton) {
        Notification.Builder nb = new Notification.Builder(context, CHANNEL_ID);

        nb.setContentTitle("FCAE VPN")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.ic_lock_lock)
          .setContentIntent(piMain)
          .setOngoing(true)
          .setStyle(new Notification.BigTextStyle().bigText(text));

        if (showStopButton) {
            nb.addAction(disconnectAction);
            nb.addAction(stopAction);
        } else {
            nb.addAction(disconnectAction);
            nb.addAction(startAction);
        }

        return nb.build();
    }

    public void show(String text, boolean showStopButton) {
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, build(text, showStopButton));
        }
    }

    public void dismiss() {
        if (manager != null) manager.cancel(NOTIFICATION_ID);
    }

    private Notification.Action buildAction(String label, String action, int requestCode) {
        Intent intent = new Intent(context, FCAEVpnService.class);
        intent.setAction(action);
        PendingIntent pi = PendingIntent.getService(context, requestCode,
            intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Action.Builder(null, label, pi).build();
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
        if (bps >= 1024L)       return String.format("%.1f KB/s", bps / 1024.0);
        return bps + " B/s";
    }
}
