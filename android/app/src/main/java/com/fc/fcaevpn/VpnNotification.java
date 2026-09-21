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
    // New id: Android ignores importance changes on an existing channel.
    public static final String CHANNEL_ID = "fcaevpn_service_hi";
    public static final int NOTIFICATION_ID = 1;

    /** Connecting / establishing: Disconnect cancels. */
    public static final int BUTTONS_CONNECTING = 0;
    /** Tunnel up: Disconnect (kill) + Stop (pause, keep process). */
    public static final int BUTTONS_RUNNING = 1;
    /** Paused from Stop: Disconnect + Start (resume last session). */
    public static final int BUTTONS_PAUSED = 2;

    private final Context context;
    private final NotificationManager manager;
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
        startAction = buildAction("Start", FCAEVpnService.ACTION_START, 12);
    }

    private void createChannel() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "FCAE VPN",
                NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("FCAE VPN tunnel controls");
            ch.setShowBadge(false);
            ch.setSound(null, null);
            ch.enableVibration(false);
            if (manager != null) {
                manager.createNotificationChannel(ch);
                // Drop the old low-importance channel so it is not used.
                try { manager.deleteNotificationChannel("fcaevpn_service"); } catch (Exception ignored) {}
            }
        }
    }

    // Notification.Builder.setPriority is deprecated since API 26 (channels
    // own importance there), but is the only lever on API 24/25 -- the app's
    // minSdk. Kept deliberately for those two levels; ignored elsewhere.
    @SuppressWarnings("deprecation")
    public Notification build(String text, int buttons) {
        Notification.Builder nb = new Notification.Builder(context, CHANNEL_ID);

        nb.setContentTitle("FCAE VPN")
          .setContentText(text)
          .setSmallIcon(android.R.drawable.ic_lock_lock)
          .setContentIntent(piMain)
          .setOngoing(true)
          .setOnlyAlertOnce(true)
          .setCategory(Notification.CATEGORY_SERVICE)
          .setVisibility(Notification.VISIBILITY_PUBLIC)
          .setPriority(Notification.PRIORITY_HIGH)
          .setStyle(new Notification.BigTextStyle().bigText(text));

        // Notification actions are the command source of truth. The app UI
        // follows whatever these send into FCAEVpnService.
        switch (buttons) {
            case BUTTONS_RUNNING:
                nb.addAction(disconnectAction);
                nb.addAction(stopAction);
                break;
            case BUTTONS_PAUSED:
                nb.addAction(disconnectAction);
                nb.addAction(startAction);
                break;
            case BUTTONS_CONNECTING:
            default:
                nb.addAction(disconnectAction);
                break;
        }

        return nb.build();
    }

    /**
     * The only text the status notifications ever show: byte flow. Shared by
     * every state and every mode, so a Psiphon exit and a plain Aether
     * protocol look exactly alike.
     */
    public static String trafficText(long rx, long tx, long totalRx, long totalTx) {
        return String.format(
            "↓ %s  %s  |  ↑ %s  %s",
            fmtBytes(totalRx), fmtRate(rx),
            fmtBytes(totalTx), fmtRate(tx));
    }

    /** Byte flow before the first sample: zeroed, same shape. */
    public static String zeroTrafficText() {
        return trafficText(0, 0, 0, 0);
    }

    /**
     * The notification shown while a tunnel dials, buildable from any process
     * of the package: the :psiphon foreground service posts it under this
     * same id, so the shared entry never differs from what this owner shows
     * at that moment. Runs this class's own build path, channel creation
     * included.
     */
    public static Notification buildConnecting(Context context) {
        return new VpnNotification(context)
                .build(zeroTrafficText(), BUTTONS_CONNECTING);
    }

    public void show(String text, int buttons) {
        try {
            if (manager != null) {
                manager.notify(NOTIFICATION_ID, build(text, buttons));
            }
        } catch (Exception e) {
            Log.w("VpnNotification", "show failed: " + e.getMessage());
        }
    }

    public void dismiss() {
        try {
            if (manager != null) manager.cancel(NOTIFICATION_ID);
        } catch (Exception e) {
            Log.w("VpnNotification", "dismiss failed: " + e.getMessage());
        }
    }

    private Notification.Action buildAction(String label, String action, int requestCode) {
        Intent intent = new Intent(context, FCAEVpnService.class);
        intent.setAction(action);
        // Explicit component + foreground service so a tap is delivered even
        // when the app is backgrounded (Android 12+).
        PendingIntent pi;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            pi = PendingIntent.getForegroundService(context, requestCode,
                intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        } else {
            pi = PendingIntent.getService(context, requestCode,
                intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        }
        return new Notification.Action.Builder(null, label, pi).build();
    }

    static String fmtBytes(long b) {
        if (b >= 1073741824L) {
            double v = b / 1073741824.0;
            long whole = (long) v;
            long frac = (long) ((v - whole) * 10.0);
            return whole + "." + frac + " GB";
        }
        if (b >= 1048576L) {
            double v = b / 1048576.0;
            long whole = (long) v;
            long frac = (long) ((v - whole) * 10.0);
            return whole + "." + frac + " MB";
        }
        if (b >= 1024L) {
            return (b / 1024L) + " KB";
        }
        return b + " B";
    }

    static String fmtRate(long bps) {
        if (bps >= 1073741824L) {
            double v = bps / 1073741824.0;
            long whole = (long) v;
            long frac = (long) ((v - whole) * 10.0);
            return whole + "." + frac + " GB/s";
        }
        if (bps >= 1048576L) {
            double v = bps / 1048576.0;
            long whole = (long) v;
            long frac = (long) ((v - whole) * 10.0);
            return whole + "." + frac + " MB/s";
        }
        if (bps >= 1024L) {
            double v = bps / 1024.0;
            long whole = (long) v;
            long frac = (long) ((v - whole) * 10.0);
            return whole + "." + frac + " KB/s";
        }
        return bps + " B/s";
    }
}
