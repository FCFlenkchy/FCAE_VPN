# Keep JNI entry points
-keep class com.fc.fcaevpn.** { *; }
-keepclassmembers class * {
    native <methods>;
}
