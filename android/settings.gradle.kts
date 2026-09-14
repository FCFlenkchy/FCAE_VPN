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
    }
}

rootProject.name = "FCAE_VPN"
include(":app")
// Psiphon AAR wrapper lives in android/psiphon/. Not included — do not
// compile it. When re-enabling: include(":psiphon")
