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
// ":psiphon" is a plain pass-through Gradle module (no AGP applied) whose
// only artifact is the CI-built AAR — see android/psiphon/build.gradle.kts.
// A real Android *library* module cannot carry a local .aar (AGP's
// bundleReleaseAar rejects them), so this facade is used: :app gets proper
// project wiring while the AAR merges as a file artifact exactly like a
// files(...) dependency would.
// android/psiphon keeps its README and the libs/ staging directory.
