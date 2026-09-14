plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

// Official Psiphon Android library wrapper.
//
// NOT included in settings.gradle.kts — Gradle will not compile this
// module. When re-enabling Psiphon:
//   1. include(":psiphon") in settings.gradle.kts
//   2. implementation(project(":psiphon")) in app/build.gradle.kts
//   3. uncomment the AAR / Maven dependency below
// Do not compile MobileLibrary/psi into libfcae_go_bridge.so.

android {
    namespace = "com.fc.fcaevpn.psiphon"
    compileSdk = 34
    defaultConfig {
        minSdk = 24
    }
}

dependencies {
    // Official distribution. Uncomment when re-enabling; pin a real version.
    // implementation("ca.psiphon:psiphontunnel:<version>")
    // or: implementation(files("libs/ca.psiphon.aar")) from MobileLibrary/Android
}
