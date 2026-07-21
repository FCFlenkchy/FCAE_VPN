package com.fc.fcaevpn;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;

/**
 * FCAE VPN — Main entry Activity.
 *
 * Handles VPN permission requests and launches the native activity
 * for the ImGui rendering loop (or the VpnService for TUN mode).
 */
public class MainActivity extends Activity {
    private static final String TAG = "FCAE_VPN";
    private static final int VPN_REQUEST_CODE = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "MainActivity created");

        // Request VPN permission on first launch
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            onVpnPermissionGranted();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                onVpnPermissionGranted();
            } else {
                Log.w(TAG, "VPN permission denied by user");
                finish();
            }
        }
    }

    private void onVpnPermissionGranted() {
        Log.i(TAG, "VPN permission granted");

        // Start the native ImGui activity (Android NativeActivity)
        // The ImGui rendering loop runs in native code (main_android_gles3.cpp)
        // The VpnService is started from the native toggle button via JNI

        // Launch the VPN service
        Intent serviceIntent = new Intent(this, FCAEVpnService.class);
        startForegroundService(serviceIntent);
    }
}
