#!/usr/bin/env bash
if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  cd "$ANDROID_HOME/cmdline-tools"
  wget -q --tries=3 --timeout=60 https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O tools.zip
  unzip -q tools.zip
  mv cmdline-tools latest
fi
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
yes | sdkmanager --licenses || true
sdkmanager "platforms;android-36" "build-tools;36.0.0" "ndk;30.0.16248370"

cd android
if [ "${FCAE_MATRIX_NAME}" = "android-universal" ]; then
  ./gradlew assembleRelease -PUNIVERSAL=true -PBUILD_TYPE=android_universal
else
  ./gradlew assembleRelease -PNDK_ABI=${FCAE_MATRIX_ABI}
fi
