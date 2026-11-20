set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING "" FORCE)
set(CMAKE_OSX_SYSROOT "$ENV{SDKROOT}" CACHE PATH "" FORCE)
set(CMAKE_OSX_DEPLOYMENT_TARGET "$ENV{IPHONEOS_DEPLOYMENT_TARGET}" CACHE STRING "" FORCE)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
# This toolchain builds native dependencies, not the Xcode app/extension.
# iOS otherwise defaults every add_executable() to an app bundle, breaking
# BoringSSL's install(TARGETS bssl) rule (which has no BUNDLE destination).
set(CMAKE_MACOSX_BUNDLE OFF CACHE BOOL "Dependency executables are not app bundles" FORCE)
# Only the dependency libraries are needed; do not configure device tests or
# Google Benchmark's cross-compilation feature probes.
set(BUILD_TESTING OFF CACHE BOOL "Do not build dependency tests" FORCE)
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED NO)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
