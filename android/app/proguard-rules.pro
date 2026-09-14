# Keep JNI entry points
-keep class com.fc.fcaevpn.** { *; }
-keepclassmembers class * {
    native <methods>;
}

# Official Psiphon AAR (gomobile)
-keep class ca.psiphon.** { *; }
-keep class psi.** { *; }
-keep class go.** { *; }
-dontwarn ca.psiphon.**
-dontwarn psi.**
-dontwarn go.**
