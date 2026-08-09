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

        // Expose version to Kotlin via BuildConfig
        buildConfigField("String", "APP_VERSION", "\"${appVersion}\"")

        // Support arm64-v8a, armeabi-v7a, and x86_64 (Chromebook/emulator).
        // The CI workflow passes -PNDK_ABI="arm64-v8a", "armeabi-v7a", "x86_64",
        // or an empty string / -PUNIVERSAL=true for a universal APK with all ABIs.
        // If not set via -P, fall back to environment variable NDK_ABI, then default to arm64-v8a.
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
            if (ndkAbi.isNotEmpty()) {
                abiFilters += ndkAbi
            }
            // Empty string = include all ABIs (universal APK)
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-O3", "-fPIC", "-flto", "-DNDEBUG")
                val cmakeTarget = if (isAndroidUniversal) {
                    "ANDROID_UNIVERSAL"
                } else when (ndkAbi) {
                    "arm64-v8a" -> "ANDROID_ARM64"
                    "armeabi-v7a" -> "ANDROID_ARM32"
                    "x86_64" -> "ANDROID_X86_64"
                    else -> "ANDROID_ARM64"
                }
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
}
