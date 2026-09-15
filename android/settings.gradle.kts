pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://raw.github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library/master")
        }
    }
}

rootProject.name = "FCAE_VPN"
include(":app")
// The official prebuilt Psiphon AAR (ca.psiphon:psiphontunnel) comes from the
// Maven repository declared above, so the old ":psiphon" pass-through module
// facade for a CI-built AAR is no longer needed. android/psiphon/ is still
// kept on disk for history but is not part of the build.
