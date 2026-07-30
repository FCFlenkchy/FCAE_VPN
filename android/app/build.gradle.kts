plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.fc.fcaevpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.fc.fcaevpn"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        // Support arm64-v8a, armeabi-v7a, and x86_64 (Chromebook/emulator).
        // The CI workflow passes -PNDK_ABI="arm64-v8a", "armeabi-v7a", or "x86_64" as project property;
        // if not set via -P, fall back to environment variable NDK_ABI, then default to arm64-v8a.
        val ndkAbi = (project.findProperty("NDK_ABI") as? String)
            ?: System.getenv("NDK_ABI")
            ?: "arm64-v8a"
        ndk {
            abiFilters += ndkAbi
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-O2", "-fPIC")
                val cmakeTarget = when (ndkAbi) {
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
