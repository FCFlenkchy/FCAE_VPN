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
include(":psiphon")
