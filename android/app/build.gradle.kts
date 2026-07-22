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

        ndk {
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-O2", "-fPIC")
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DAETHER_TARGET=ANDROID_ARM64"
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

    // Bundle aether engine as libaether.so so the FFI can exec it from nativeLibraryDir.
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
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

// Copy cargo-built aether binary into jniLibs before each assemble.
tasks.register("copyAetherEngine") {
    doLast {
        val abi = "arm64-v8a"
        val candidates = listOf(
            file("../../aether/aether/target/aarch64-linux-android/release/aether"),
            file("../../aether/target/aarch64-linux-android/release/aether"),
            file("../../target/aarch64-linux-android/release/aether"),
        )
        val src = candidates.firstOrNull { it.exists() }
        if (src == null) {
            logger.warn("aether engine binary not found; APK will not include libaether.so")
            return@doLast
        }
        val destDir = file("src/main/jniLibs/$abi")
        destDir.mkdirs()
        val dest = file("$destDir/libaether.so")
        src.copyTo(dest, overwrite = true)
        logger.lifecycle("Bundled ${src.absolutePath} -> ${dest.absolutePath}")
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.contains("JniLib") }.configureEach {
    dependsOn("copyAetherEngine")
}
tasks.matching { it.name.startsWith("externalNativeBuild") }.configureEach {
    dependsOn("copyAetherEngine")
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
}
