plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Read version from repo-root version.json (single source of truth)
fun readVersionFromJson(): String {
    val versionFile = file("${rootProject.projectDir}/../version.json")
    if (!versionFile.exists()) return "dev"
    try {
        val content = versionFile.readText()
        // Extract "version" field with regex (avoids needing json lib at build time)
        val regex = Regex(""""version"\s*:\s*"([^"]+)"""")
        return regex.find(content)?.groupValues?.getOrNull(1) ?: "dev"
    } catch (_: Exception) {
        return "dev"
    }
}

val appVersion = readVersionFromJson()

android {
    namespace = "com.fc.fcaevpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.fc.fcaevpn"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = appVersion

        buildConfigField("String", "APP_VERSION", "\"${appVersion}\"")

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
            isMinifyEnabled = true
            isShrinkResources = true

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

    kotlinOptions {
        jvmTarget = "17"
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
    // Official AAR, built in CI from core/psiphon into psiphon/libs/ —
    // consumed DIRECTLY as a local file dependency. App modules may do this
    // (AGP fully merges classes, jni libgojni.so, manifest and assets); a
    // library module may not, which is why the old `:psiphon` wrapper module
    // failed at :psiphon:bundleReleaseAar ("Direct local .aar file
    // dependencies are not supported when building an AAR"). Process
    // isolation is unchanged: PsiphonTunnelService still runs in :psiphon
    // via android:process, so libgojni.so never shares an address space with
    // tun2socks. processR8 keeps are in proguard-rules.pro.
    implementation(files("../psiphon/libs/ca.psiphon.aar"))
}
