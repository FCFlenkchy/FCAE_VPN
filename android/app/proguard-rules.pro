# Add project specific ProGuard rules here.
-keep class com.fc.fcaevpn.** { *; }
-keepclassmembers class com.fc.fcaevpn.FCAEVpnService {
    private static native void nativeSetTunFd(int);
}
