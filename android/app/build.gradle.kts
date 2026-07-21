plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}

android {
    namespace 'com.fc.fcaevpn'
    compileSdk 34

    defaultConfig {
        applicationId "com.fc.fcaevpn"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0.0"

        ndk {
            abiFilters 'arm64-v8a'
        }

        externalNativeBuild {
            cmake {
                cppFlags "-std=c++17 -O2 -fPIC"
                arguments "-DANDROID_STL=c++_shared",
                          "-DAETHER_TARGET=ANDROID_ARM64"
            }
        }
    }

    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
            signingConfig signingConfigs.debug
        }
    }

    externalNativeBuild {
        cmake {
            path "../../CMakeLists.txt"
            version "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
}
