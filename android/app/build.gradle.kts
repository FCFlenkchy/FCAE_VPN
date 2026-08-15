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
