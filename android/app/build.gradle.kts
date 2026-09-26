plugins {
    id("com.android.application")
}

data class ReleaseVersion(
    val text: String,
    val components: List<Int>,
    val prerelease: Boolean,
    val revision: String
) : Comparable<ReleaseVersion> {
    override fun compareTo(other: ReleaseVersion): Int {
        for (i in components.indices) {
            val result = components[i].compareTo(other.components[i])
            if (result != 0) return result
        }
        if (prerelease != other.prerelease) return if (prerelease) -1 else 1
        val lengthOrder = revision.length.compareTo(other.revision.length)
        if (lengthOrder != 0) return lengthOrder
        val revisionOrder = revision.compareTo(other.revision)
        return if (revisionOrder != 0) revisionOrder else text.compareTo(other.text)
    }
}

fun parseReleaseVersion(value: String): ReleaseVersion {
    val match = Regex("""^([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)(_pre-release(?:\.([0-9]+))?)?$""")
        .matchEntire(value) ?: error("Invalid release version: $value")
    val components = match.groupValues[1].split('.').map {
        require(it == "0" || !it.startsWith('0')) { "Invalid release version: $value" }
        val number = it.toIntOrNull() ?: error("Invalid release version: $value")
        require(number in 0..65535) { "Version components must be in 0..65535: $value" }
        number
    }.toMutableList()
    while (components.size < 4) components.add(0)
    val revision = match.groupValues[3]
    require(revision.isEmpty() || revision == "0" || !revision.startsWith('0')) {
        "Invalid prerelease revision: $value"
    }
    require(revision.length < 20 || revision.length == 20 && revision <= "18446744073709551615") {
        "Prerelease revision is too large: $value"
    }
    return ReleaseVersion(value, components, match.groupValues[2].isNotEmpty(), revision)
}

val selectedVersion = System.getenv("FCAE_VERSION")?.let { parseReleaseVersion(it) } ?: run {
    val releases = groovy.json.JsonSlurper().parse(
        file("${rootProject.projectDir}/../version.json")
    ) as? List<*> ?: error("version.json must be a release array")
    releases.map { entry ->
        val release = entry as? Map<*, *> ?: error("Each release must be an object")
        val version = release["version"] as? String ?: error("Release version must be a string")
        parseReleaseVersion(version)
    }.maxOrNull() ?: error("version.json must contain a release")
}

val isPrerelease = System.getenv("FCAE_IS_PRERELEASE")?.toBoolean() ?: selectedVersion.prerelease
val appVersion = when {
    !isPrerelease -> selectedVersion.text.substringBefore("_pre-release")
    selectedVersion.prerelease -> selectedVersion.text
    else -> "${selectedVersion.text}_pre-release"
}

android {
    namespace = "com.fc.fcaevpn"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.fc.fcaevpn"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = appVersion
        resourceConfigurations += "en"

        buildConfigField("String", "APP_VERSION", "\"${appVersion}\"")
        buildConfigField("Boolean", "IS_PRERELEASE", "${isPrerelease}")

        val universal = (project.findProperty("UNIVERSAL") as? String)?.toBoolean() ?: false
        val buildType = (project.findProperty("BUILD_TYPE") as? String)
            ?: System.getenv("BUILD_TYPE")
            ?: ""
        val isAndroidUniversal = buildType == "android_universal"

        val ndkAbi = if (universal || isAndroidUniversal) ""
            else (project.findProperty("NDK_ABI") as? String)
                ?: System.getenv("NDK_ABI")
                ?: "arm64-v8a"

        ndk {
            if (isAndroidUniversal) {
                abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
            } else if (ndkAbi.isNotEmpty()) {
                abiFilters += ndkAbi
            }
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf(
                    "-std=c++17",
                    "-O3",
                    "-g0",
                    "-fPIC",
                    "-flto",
                    "-DNDEBUG"
                )

                val cmakeTarget = if (isAndroidUniversal) {
                    "ANDROID_UNIVERSAL"
                } else when (ndkAbi) {
                    "arm64-v8a" -> "ANDROID_ARM64"
                    "armeabi-v7a" -> "ANDROID_ARM32"
                    "x86_64", "x86" -> "ANDROID_X86_64"
                    else -> "ANDROID_ARM64"
                }

                arguments += listOf(
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DFCAE_VERSION_OVERRIDE=$appVersion",
                    "-DFCAE_IS_PRERELEASE=$isPrerelease",
                    "-DANDROID_STL=c++_shared",
                    // Android 15 uses 16 KB memory pages on new devices and
                    // its loader rejects shared objects laid out for 4 KB
                    // pages, so System.loadLibrary() throws
                    // UnsatisfiedLinkError from NativeEngine's static
                    // initialiser and the app dies at launch. Honoured by NDK
                    // r27+; CMakeLists.txt also passes the raw linker flags
                    // for older NDKs.
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON",
                    "-DAETHER_TARGET=${cmakeTarget}"
                )
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true

            ndk {
                debugSymbolLevel = "none"
            }

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )

            signingConfig = signingConfigs.getByName("debug")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("../../CMakeLists.txt")
            version = "3.22.1"
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        jniLibs {
            // Replaces android:extractNativeLibs in the manifest (AGP warns if
            // that attribute is set there).
            //
            // `false` = load the .so straight from the APK without unpacking to
            // disk, which is smaller and faster. The old build needed the
            // legacy behaviour because it EXECUTED a packaged tun2socks binary,
            // which requires a real file on disk. tun2socks now runs in-process
            // as libfcae_go_bridge.so, loaded by the dynamic linker, so the
            // extraction is no longer needed.
            useLegacyPackaging = false
            // Both our own CMake output and the staged Go bridge land in
            // jniLibs/<abi>/; keep the first of any duplicate.
            pickFirsts += listOf(
                "**/libfcae_go_bridge.so"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

// javac only prints "Some input files use or override a deprecated API" and
// asks for -Xlint:deprecation; turn that on unconditionally so every build
// lists exactly which file:line uses a deprecated API instead of hiding the
// details. Remaining hits are deliberate pre-API-26/34 fallbacks, each kept
// quiet at the call site with @SuppressWarnings("deprecation") + a comment.
tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:deprecation")
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    // Built in CI from the pinned core/psiphon source and its vendored tools.
    // The Go runtime remains isolated in :psiphon.
    implementation(project(":psiphon"))
}
