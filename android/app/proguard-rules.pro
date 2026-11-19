# JNI exports use name-based lookup from libfcaevpn_native.so. Keep the
# Kotlin object itself as well: FCAEVpnService starts before an Activity and
# must resolve NativeEngine even in an R8-minified process.
-keep class com.fc.fcaevpn.NativeEngine { *; }
-keep class com.fc.fcaevpn.NativeEngine$Loaded { *; }
-keepclasseswithmembernames,includedescriptorclasses class com.fc.fcaevpn.** {
    native <methods>;
}

# Native callbacks resolved with GetMethodID.
-keepclassmembers,allowoptimization class com.fc.fcaevpn.FCAEVpnService {
    java.lang.String psiphonDnsServers();
    boolean psiphonHasConnectivity();
    java.lang.String psiphonNetworkId();
    int establishTunNow();
}

# JNI calls these methods by name from Go-owned threads.
-keep class com.fc.fcaevpn.PsiphonTunnel { *; }

# Shared ImGui host callbacks are looked up by JNI.
-keep class com.fc.fcaevpn.ImGuiBridge { *; }
