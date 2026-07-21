package com.fc.fcaevpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileDescriptor;

/**
 * FCAE VPN — Android VpnService implementation.
 *
 * When FCAE VPN switches to TUN mode, this service:
 *   1. Requests VPN permission from the user.
 *   2. Establishes the virtual network interface via VpnService.Builder.
 *   3. Passes the ParcelFileDescriptor (tun0 fd) across JNI to Rust
 *      via aether_set_android_tun_fd(int fd).
 *   4. Runs as a foreground service with a persistent notification.
 */
public class FCAEVpnService extends VpnService {
    private static final String TAG = "FCAE_VPN";
    private static final String CHANNEL_ID = "fcaevpn_service";
    private static final int NOTIFICATION_ID = 1;

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private volatile boolean running = false;

    // Load the native library containing the Rust FFI bridge + ImGui frontend
    static {
        System.loadLibrary("fcaevpn_native");
    }

    // JNI: pass the tun fd to the Rust aether-ffi crate
    private static native void nativeSetTunFd(int fd);

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "FCAEVpnService created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildNotification("FCAE VPN — Connecting..."));

        startVpn();

        return START_STICKY;
    }

    private void startVpn() {
        if (running) return;

        vpnThread = new Thread(() -> {
            try {
                // Build the TUN interface
                Builder builder = new Builder();
                builder.setSession("FCAE VPN");
                builder.setMtu(1280);
                builder.addAddress("10.0.0.2", 32);
                builder.addRoute("0.0.0.0", 0);
                builder.addRoute("::", 0);

                // Exclude our own app from the VPN to prevent loops
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (Exception e) {
                    Log.w(TAG, "Could not exclude own package: " + e.getMessage());
                }

                // Add DNS servers
                builder.addDnsServer("1.1.1.1");
                builder.addDnsServer("1.0.0.1");

                vpnInterface = builder.establish();
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN interface (user denied permission?)");
                    stopSelf();
                    return;
                }

                // Pass the raw file descriptor to Rust FFI
                FileDescriptor fd = vpnInterface.getFileDescriptor();
                nativeSetTunFd(fd.getInt());

                running = true;
                Log.i(TAG, "VPN interface established, fd=" + fd.getInt());
                updateNotification("FCAE VPN — TUN Active");

                // Keep the service alive while the VPN is running
                while (running) {
                    Thread.sleep(1000);
                }

            } catch (InterruptedException e) {
                Log.i(TAG, "VPN thread interrupted");
            } catch (Exception e) {
                Log.e(TAG, "VPN error: " + e.getMessage(), e);
            } finally {
                stopVpn();
            }
        }, "FCAE-VPN-Worker");

        vpnThread.start();
    }

    private void stopVpn() {
        running = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing VPN interface: " + e.getMessage());
            }
            vpnInterface = null;
        }

        stopForeground(true);
        stopSelf();
        Log.i(TAG, "VPN service stopped");
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopVpn();
        super.onRevoke();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "FCAE VPN Service",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("FCAE VPN tunnel status");
            NotificationManager mgr = getSystemService(NotificationManager.class);
            if (mgr != null) {
                mgr.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildNotification(String text) {
        Intent mainIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingMain = PendingIntent.getActivity(
            this, 0, mainIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Intent stopIntent = new Intent(this, FCAEVpnService.class);
        stopIntent.setAction("STOP");
        PendingIntent pendingStop = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb = new Notification.Builder(this, CHANNEL_ID);
        } else {
            nb = new Notification.Builder(this);
        }

        return nb
            .setContentTitle("FCAE VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingMain)
            .addAction(new Notification.Action.Builder(
                null, "Disconnect", pendingStop).build())
            .setOngoing(true)
            .build();
    }

    private void updateNotification(String text) {
        NotificationManager mgr = getSystemService(NotificationManager.class);
        if (mgr != null) {
            mgr.notify(NOTIFICATION_ID, buildNotification(text));
        }
    }
}
