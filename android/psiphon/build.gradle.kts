plugins {
    id("com.android.library")
}

// Official Psiphon Android library (gomobile AAR). Loaded only in the
// :psiphon process so libgojni.so never shares an address space with
// tun2socks' libfcae_go_bridge.so.

android {
    namespace = "com.fc.fcaevpn.psiphon"
    compileSdk = 34
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // Built in CI from the core/psiphon submodule (workflow step
    // "build psiphon AAR from submodule"), so the library always matches
    // the pinned tunnel-core instead of a lagging Maven release.
    api(files("libs/ca.psiphon.aar"))
}
