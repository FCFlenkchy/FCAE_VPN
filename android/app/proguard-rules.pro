# JNI exports use name-based lookup from libfcaevpn_native.so.
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

# Constructed and populated directly by nativePollUpdate.
-keep,allowoptimization class com.fc.fcaevpn.FcaeUpdateInfo {
    <fields>;
}

# Constructed and populated directly by nativePollSponsor. JNI resolves every
# field by its source name, so R8 must not rename or remove this DTO.
-keep,allowoptimization class com.fc.fcaevpn.FcaeSponsorInfo {
    <fields>;
}

# Official Psiphon AAR (gomobile)
-keep class ca.psiphon.** { *; }
-keep class psi.** { *; }
-keep class go.** { *; }
-dontwarn ca.psiphon.**
-dontwarn psi.**
-dontwarn go.**
