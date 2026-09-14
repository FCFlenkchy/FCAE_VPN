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
// NOTE: no ":psiphon" library module. AGP refuses to build a library AAR
// that has a direct local .aar file dependency (:psiphon:bundleReleaseAar
// failed with "Direct local .aar file dependencies are not supported when
// building an AAR" — the wrapped psiphon/libs/ca.psiphon.aar was never going
// to be merged). :app consumes the CI-built AAR from psiphon/libs/ directly;
// android/psiphon keeps only its README and the libs/ staging directory.
