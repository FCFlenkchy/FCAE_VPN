cmake_minimum_required(VERSION 3.22)
project(fcaevpn LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ───────────────────────────────────────────────────────────────
option(AETHER_TARGET "Build target" "LINUX_X64")

function(fcae_version_parts value prefix)
  if(NOT "${value}" MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)(_pre-release(\\.([0-9]+))?)?$")
    message(FATAL_ERROR "Invalid release version: ${value}")
  endif()
  set(_base "${CMAKE_MATCH_1}")
  set(_suffix "${CMAKE_MATCH_3}")
  set(_revision "${CMAKE_MATCH_5}")
  string(REPLACE "." ";" _components "${_base}")
  foreach(_component IN LISTS _components)
    string(LENGTH "${_component}" _length)
    if(_component MATCHES "^0[0-9]" OR _length GREATER 5)
      message(FATAL_ERROR "Invalid release version: ${value}")
    endif()
    if(_component GREATER 65535)
      message(FATAL_ERROR "Version components must be in 0..65535: ${value}")
    endif()
  endforeach()
  string(LENGTH "${_revision}" _revision_length)
  if(_revision MATCHES "^0[0-9]" OR _revision_length GREATER 20)
    message(FATAL_ERROR "Invalid prerelease revision: ${value}")
  endif()
  if(_revision_length EQUAL 20 AND "${_revision}" STRGREATER "18446744073709551615")
    message(FATAL_ERROR "Prerelease revision is too large: ${value}")
  endif()
  set(${prefix}_base "${_base}" PARENT_SCOPE)
  set(${prefix}_pre FALSE PARENT_SCOPE)
  if(NOT _suffix STREQUAL "")
    set(${prefix}_pre TRUE PARENT_SCOPE)
  endif()
  set(${prefix}_revision "${_revision}" PARENT_SCOPE)
  set(${prefix}_revision_length "${_revision_length}" PARENT_SCOPE)
endfunction()

if(DEFINED FCAE_VERSION_OVERRIDE)
  set(FCAE_VERSION "${FCAE_VERSION_OVERRIDE}")
  fcae_version_parts("${FCAE_VERSION}" _selected)
else()
  file(READ "${CMAKE_SOURCE_DIR}/version.json" _ver_json)
  string(JSON _release_type TYPE "${_ver_json}")
  if(NOT _release_type STREQUAL "ARRAY")
    message(FATAL_ERROR "version.json must be a release array")
  endif()
  string(JSON _release_count LENGTH "${_ver_json}")
  if(_release_count EQUAL 0)
    message(FATAL_ERROR "version.json must contain a release")
  endif()
  math(EXPR _release_last "${_release_count} - 1")
  set(FCAE_VERSION "")
  foreach(_index RANGE 0 ${_release_last})
    string(JSON _version_type TYPE "${_ver_json}" ${_index} version)
    if(NOT _version_type STREQUAL "STRING")
      message(FATAL_ERROR "Release version must be a string")
    endif()
    string(JSON _version GET "${_ver_json}" ${_index} version)
    fcae_version_parts("${_version}" _candidate)
    set(_choose FALSE)
    if(FCAE_VERSION STREQUAL "")
      set(_choose TRUE)
    elseif(_candidate_base VERSION_GREATER _selected_base)
      set(_choose TRUE)
    elseif(_candidate_base VERSION_EQUAL _selected_base)
      if(_selected_pre AND NOT _candidate_pre)
        set(_choose TRUE)
      elseif("${_candidate_pre}" STREQUAL "${_selected_pre}")
        if(_candidate_revision_length GREATER _selected_revision_length)
          set(_choose TRUE)
        elseif(_candidate_revision_length EQUAL _selected_revision_length)
          if("${_candidate_revision}" STRGREATER "${_selected_revision}")
            set(_choose TRUE)
          elseif("${_candidate_revision}" STREQUAL "${_selected_revision}" AND "${_version}" STRGREATER "${FCAE_VERSION}")
            set(_choose TRUE)
          endif()
        endif()
      endif()
    endif()
    if(_choose)
      set(FCAE_VERSION "${_version}")
      fcae_version_parts("${FCAE_VERSION}" _selected)
    endif()
  endforeach()
endif()

# Determine prerelease status
if(NOT DEFINED FCAE_IS_PRERELEASE)
  # Try to read from version.json
  if(NOT DEFINED FCAE_VERSION_OVERRIDE)
    string(JSON _selected_pre GET "${_ver_json}" ${_release_last} prerelease)
    set(FCAE_IS_PRERELEASE "${_selected_pre}")
  else()
    set(FCAE_IS_PRERELEASE "false")
  endif()
endif()

message(STATUS "FCAE_VERSION = ${FCAE_VERSION}")
message(STATUS "FCAE_IS_PRERELEASE = ${FCAE_IS_PRERELEASE}")

# ── Parse version into MAJOR.MINOR.PATCH.BUILD for Windows RC ────────────
# FCAE_VERSION is e.g. "v0.2.0-beta", "v1.4.1", or "v1.0.9.4"
set(FCAE_VERSION_MAJOR 0)
set(FCAE_VERSION_MINOR 0)
set(FCAE_VERSION_PATCH 0)
set(FCAE_VERSION_BUILD 0)
# Try 4-component first (v1.0.9.4), then 3-component (v1.4.1)
string(REGEX MATCH "^[vV]?([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)" _v4_match "${FCAE_VERSION}")
if(_v4_match)
  set(FCAE_VERSION_MAJOR "${CMAKE_MATCH_1}")
  set(FCAE_VERSION_MINOR "${CMAKE_MATCH_2}")
  set(FCAE_VERSION_PATCH "${CMAKE_MATCH_3}")
  set(FCAE_VERSION_BUILD "${CMAKE_MATCH_4}")
else()
  string(REGEX MATCH "^[vV]?([0-9]+)\\.([0-9]+)\\.([0-9]+)" _v3_match "${FCAE_VERSION}")
  if(_v3_match)
    set(FCAE_VERSION_MAJOR "${CMAKE_MATCH_1}")
    set(FCAE_VERSION_MINOR "${CMAKE_MATCH_2}")
    set(FCAE_VERSION_PATCH "${CMAKE_MATCH_3}")
  endif()
endif()
message(STATUS "FCAE_VERSION_WIN = ${FCAE_VERSION_MAJOR}.${FCAE_VERSION_MINOR}.${FCAE_VERSION_PATCH}.${FCAE_VERSION_BUILD}")

# Generate version header for Windows .rc file
configure_file(
  "${CMAKE_SOURCE_DIR}/src_cpp/version_rc.h.in"
  "${CMAKE_BINARY_DIR}/version_rc.h"
  @ONLY
)
# Add binary dir to include path so icon.rc can find version_rc.h
if(WIN32 OR AETHER_TARGET STREQUAL "WIN_X64")
  include_directories("${CMAKE_BINARY_DIR}")
endif()

# ── Source files ──────────────────────────────────────────────────────────
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
set(IMGUI_BACKEND_DIR ${IMGUI_DIR}/backends)

set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
)

set(UI_SOURCES
    ${CMAKE_SOURCE_DIR}/src_cpp/ui_render.cpp
)

# Public C header for the shared FFI layer. Every C++ target gets this on its
# include path, so sources say #include "fcae.h" rather than reaching up out of
# the tree with a relative path.
set(FCAE_FFI_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/core/fcae-ffi/include)

# Resolve libfcae_ffi.a from cargo.
#
# This one staticlib now contains everything: the shared core, the selected
# backends, and the tun2socks Go bridge as a c-archive. There is no separate
# tun2socks executable to build, sign, package or ship any more.
function(fcae_ffi_lib_path out_var triple)
    set(candidates
        ${CMAKE_SOURCE_DIR}/core/fcae-ffi/target/${triple}/release/libfcae_ffi.a
        ${CMAKE_SOURCE_DIR}/target/${triple}/release/libfcae_ffi.a
    )
    foreach(c ${candidates})
        if(EXISTS "${c}")
            set(${out_var} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${out_var} "${CMAKE_SOURCE_DIR}/core/fcae-ffi/target/${triple}/release/libfcae_ffi.a" PARENT_SCOPE)
endfunction()

# Link the Rust staticlib once as a full path.
# Do NOT use --whole-archive: cargo packs C objects (BoringSSL bcm.o, the Go
# runtime from the tun2socks c-archive, etc.) that can appear more than once in
# the archive; whole-archive then causes thousands of "multiple definition"
# errors. Normal archive linking is enough because the C++ frontend references
# fcae_init/start/stop/... which pull the rest of the graph.
function(fcae_link_ffi target_name lib_path)
    if(NOT EXISTS "${lib_path}")
        message(WARNING "libfcae_ffi.a not found at ${lib_path} (build rust first)")
    endif()
    # IMPORTED static library so CMake does not re-scan/duplicate the archive
    if(NOT TARGET fcae_ffi_imported)
        add_library(fcae_ffi_imported STATIC IMPORTED GLOBAL)
        set_target_properties(fcae_ffi_imported PROPERTIES
            IMPORTED_LOCATION "${lib_path}"
        )
    endif()
    target_link_libraries(${target_name} PRIVATE fcae_ffi_imported)
    target_include_directories(${target_name} PRIVATE ${FCAE_FFI_INCLUDE_DIR})
endfunction()

# Give an Android shared object 16 KB-aligned LOAD segments.
#
# Android 15 runs with 16 KB memory pages on new devices, and its loader
# rejects a .so whose segments are laid out for the historical 4 KB pages.
# The Go bridge already asks for this through CGO_LDFLAGS in buildtools/go.rs,
# but libfcaevpn_native.so is linked here by CMake and inherited none of it --
# so on a 16 KB device System.loadLibrary() threw UnsatisfiedLinkError from
# NativeEngine's static initialiser and the process died at launch.
#
# NDK r27+ honours ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES; the explicit linker
# flags cover older NDKs and cost nothing on newer ones.
#
# Verify with:  llvm-readelf -l libfcaevpn_native.so | grep LOAD   (Align 0x4000)
function(fcae_align_16k target_name)
    target_link_options(${target_name} PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384"
    )
    message(STATUS "16 KB page alignment enabled for ${target_name}")
endfunction()

# Link the tun2socks Go bridge (Android only).
#
# On Android the Go toolchain rejects -buildmode=c-archive, so tun2socks
# is built as libfcae_go_bridge.so and staged into jniLibs/<abi>/.
# It is therefore NOT inside libfcae_ffi.a: the Rust side only *references*
# t2s_start/t2s_stop/... and cargo emits `rustc-link-lib=dylib=...` directives
# that apply when rustc links a final artifact. Here CMake performs the link,
# so cargo's directives never reach it and we must name the .so explicitly --
# otherwise ld.lld reports "undefined symbol: t2s_start" and friends.
#
# Psiphon is not in this .so. Android Psiphon is the official AAR
# (android/psiphon, not in the Gradle graph). Do not link a second Go
# runtime next to this library — that SIGSEGVs at dlopen.
function(fcae_link_go_bridges target_name abi)
    set(jni_dir ${CMAKE_SOURCE_DIR}/android/app/src/main/jniLibs/${abi})
    # tun2socks_bridge is a hard dependency: TUN mode always needs it.
    set(t2s ${jni_dir}/libfcae_go_bridge.so)
    if(EXISTS "${t2s}")
        target_link_libraries(${target_name} PRIVATE "${t2s}")
        message(STATUS "linking Go bridge: ${t2s}")
    endif()

    # The .so sits next to our library in the APK's native lib dir.
    target_link_options(${target_name} PRIVATE "-Wl,-rpath,\\$ORIGIN")
endfunction()

# Desktop Psiphon: second Go runtime as libfcae_psiphon (c-shared). Cargo
# stages it next to libfcae_ffi.a. CMake must link and copy it because rustc's
# dylib directives never reach this link. Missing is a warning so a build
# without psiphon-live still configures.
function(fcae_link_psiphon target_name triple)
    set(dirs
        ${CMAKE_SOURCE_DIR}/target/${triple}/release
        ${CMAKE_SOURCE_DIR}/core/fcae-ffi/target/${triple}/release
    )
    set(found "")
    set(found_dir "")
    foreach(d ${dirs})
        if(EXISTS "${d}/libfcae_psiphon.dll")
            set(found "${d}/libfcae_psiphon.dll")
            set(found_dir "${d}")
            break()
        elseif(EXISTS "${d}/libfcae_psiphon.so")
            set(found "${d}/libfcae_psiphon.so")
            set(found_dir "${d}")
            break()
        elseif(EXISTS "${d}/libfcae_psiphon.dylib")
            set(found "${d}/libfcae_psiphon.dylib")
            set(found_dir "${d}")
            break()
        endif()
    endforeach()
    if(found STREQUAL "")
        message(STATUS "libfcae_psiphon not staged for ${triple} (psiphon-live off?)")
        return()
    endif()
    message(STATUS "linking desktop Psiphon: ${found}")
    if(EXISTS "${found_dir}/libfcae_psiphon.dll.a")
        target_link_libraries(${target_name} PRIVATE "${found_dir}/libfcae_psiphon.dll.a")
    else()
        target_link_libraries(${target_name} PRIVATE "${found}")
    endif()
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${found}" "$<TARGET_FILE_DIR:${target_name}>"
        COMMENT "stage libfcae_psiphon next to ${target_name}"
    )
endfunction()

# Android Psiphon: official AAR, not a second Go library.

# ── Target-specific configuration ────────────────────────────────────────
if(AETHER_TARGET STREQUAL "ANDROID_ARM64")

    # Kotlin UI + JNI bridge only (no ImGui / NativeActivity)
    add_library(fcaevpn_native SHARED
        ${CMAKE_SOURCE_DIR}/src_cpp/android_jni.cpp
    )

    target_include_directories(fcaevpn_native PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
    )

    target_compile_definitions(fcaevpn_native PRIVATE
        ANDROID
        AETHER_TARGET_ANDROID_ARM64
    )

    find_library(log-lib log)
    find_library(android-lib android)

    fcae_ffi_lib_path(FCAE_FFI_A aarch64-linux-android)
    fcae_link_ffi(fcaevpn_native "${FCAE_FFI_A}")
    fcae_link_go_bridges(fcaevpn_native arm64-v8a)

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)
    fcae_align_16k(fcaevpn_native)

elseif(AETHER_TARGET STREQUAL "ANDROID_ARM32")

    # Kotlin UI + JNI bridge for armeabi-v7a
    add_library(fcaevpn_native SHARED
        ${CMAKE_SOURCE_DIR}/src_cpp/android_jni.cpp
    )

    target_include_directories(fcaevpn_native PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
    )

    target_compile_definitions(fcaevpn_native PRIVATE
        ANDROID
        AETHER_TARGET_ANDROID_ARM32
    )

    find_library(log-lib log)
    find_library(android-lib android)

    fcae_ffi_lib_path(FCAE_FFI_A armv7-linux-androideabi)
    fcae_link_ffi(fcaevpn_native "${FCAE_FFI_A}")
    fcae_link_go_bridges(fcaevpn_native armeabi-v7a)

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)
    fcae_align_16k(fcaevpn_native)

elseif(AETHER_TARGET STREQUAL "ANDROID_X86_64")

    # Kotlin UI + JNI bridge for x86_64 (Chromebook / emulator)
    add_library(fcaevpn_native SHARED
        ${CMAKE_SOURCE_DIR}/src_cpp/android_jni.cpp
    )

    target_include_directories(fcaevpn_native PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
    )

    target_compile_definitions(fcaevpn_native PRIVATE
        ANDROID
        AETHER_TARGET_ANDROID_X86_64
    )

    find_library(log-lib log)
    find_library(android-lib android)

    fcae_ffi_lib_path(FCAE_FFI_A x86_64-linux-android)
    fcae_link_ffi(fcaevpn_native "${FCAE_FFI_A}")
    fcae_link_go_bridges(fcaevpn_native x86_64)

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)
    fcae_align_16k(fcaevpn_native)

elseif(AETHER_TARGET STREQUAL "ANDROID_UNIVERSAL")

    # Universal Android build — all ABIs in a single APK.
    # Each ABI variant is compiled separately by CMake (via ANDROID_ABI loop in build.gradle).
    # This branch acts as a fallback/sentinel; actual ABI selection happens in the
    # Gradle script which invokes CMake once per ABI with the correct ANDROID_ABI.
    # We default to arm64-v8a here just so CMake configuration succeeds.
    message(STATUS "ANDROID_UNIVERSAL: building for all Android ABIs (arm64-v8a, armeabi-v7a, x86_64)")
    
    add_library(fcaevpn_native SHARED
        ${CMAKE_SOURCE_DIR}/src_cpp/android_jni.cpp
    )

    target_include_directories(fcaevpn_native PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
    )

    target_compile_definitions(fcaevpn_native PRIVATE
        ANDROID
        AETHER_TARGET_ANDROID_UNIVERSAL
    )

    find_library(log-lib log)
    find_library(android-lib android)

    # Try to find any available ABI lib; Gradle will handle per-ABI builds
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        fcae_ffi_lib_path(FCAE_FFI_A aarch64-linux-android)
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        fcae_ffi_lib_path(FCAE_FFI_A armv7-linux-androideabi)
    elseif(ANDROID_ABI STREQUAL "x86_64" OR ANDROID_ABI STREQUAL "x86")
        fcae_ffi_lib_path(FCAE_FFI_A x86_64-linux-android)
    else()
        fcae_ffi_lib_path(FCAE_FFI_A aarch64-linux-android)
    endif()
    fcae_link_ffi(fcaevpn_native "${FCAE_FFI_A}")
    fcae_link_go_bridges(fcaevpn_native ${ANDROID_ABI})

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)
    fcae_align_16k(fcaevpn_native)

elseif(WIN32 OR AETHER_TARGET STREQUAL "WIN_X64")

    add_executable(fcaevpn
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_win32.cpp
        ${IMGUI_BACKEND_DIR}/imgui_impl_dx11.cpp
        ${CMAKE_SOURCE_DIR}/src_cpp/main_win32_dx11.cpp
        ${UI_SOURCES}
        ${CMAKE_SOURCE_DIR}/src_cpp/icon.rc
    )

    target_include_directories(fcaevpn PRIVATE
        ${IMGUI_DIR} ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
        ${CMAKE_BINARY_DIR}
    )

    target_compile_definitions(fcaevpn PRIVATE
        UNICODE _UNICODE
        IMGUI_IMPL_WIN32_DISABLE_GAMEPAD
        AETHER_TARGET_WIN_X64
        FCAE_VERSION="${FCAE_VERSION}"
    )
    if(FCAE_IS_PRERELEASE)
      target_compile_definitions(fcaevpn PRIVATE FCAE_IS_PRERELEASE)
    endif()

    target_compile_options(fcaevpn PRIVATE -municode)

    fcae_ffi_lib_path(FCAE_FFI_A x86_64-pc-windows-gnu)
    fcae_link_ffi(fcaevpn "${FCAE_FFI_A}")
    fcae_link_psiphon(fcaevpn x86_64-pc-windows-gnu)

    # System libs only — crypto is inside the Rust staticlib (BoringSSL), not OpenSSL.
    # pthread MUST come after libfcae_ffi.a (BoringSSL thread_pthread needs it).
    target_link_libraries(fcaevpn PRIVATE
        d3d11 dxgi d3dcompiler dwmapi ntdll
        ws2_32 userenv bcrypt shell32 ole32 uuid crypt32 secur32 ncrypt
        iphlpapi
        # winmm: the Go runtime (tun2socks c-archive) calls timeBeginPeriod.
        # The rest of the Go runtime's imports (ws2_32/ntdll/userenv/bcrypt/
        # iphlpapi) happen to be listed above already.
        winmm
    )

    if(MINGW)
        set(MINGW_LIB /usr/x86_64-w64-mingw32/lib)
        target_link_options(fcaevpn PRIVATE
            -L${MINGW_LIB}
            -static-libgcc -static-libstdc++
            -s -mwindows -municode
        )
        # After Rust staticlib: static pthread for winpthread + stdc++
        target_link_libraries(fcaevpn PRIVATE
            -Wl,-Bstatic -lstdc++ -lpthread -lwinpthread -Wl,-Bdynamic
        )
    endif()

elseif(APPLE OR AETHER_TARGET STREQUAL "MACOS_ARM64" OR AETHER_TARGET STREQUAL "MACOS_X64")

    # Find GLFW: look for static lib in custom prefixes first (from CI build),
    # then fall back to system/dynamic GLFW.
    # Prefer glfw3Config.cmake which handles IMPORTED targets properly.
    set(GLFW_PREFIX_HINT "")
    if(AETHER_TARGET STREQUAL "MACOS_X64" OR (APPLE AND NOT AETHER_TARGET STREQUAL "MACOS_ARM64" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64"))
        set(GLFW_PREFIX_HINT /usr/local/glfw_x64)
    elseif(AETHER_TARGET STREQUAL "MACOS_ARM64" OR (APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64"))
        set(GLFW_PREFIX_HINT /usr/local/glfw_arm64)
    endif()

    if(GLFW_PREFIX_HINT AND EXISTS "${GLFW_PREFIX_HINT}")
        # Add the prefix to CMAKE_PREFIX_PATH so find_package finds our static build
        list(APPEND CMAKE_PREFIX_PATH "${GLFW_PREFIX_HINT}")
        message(STATUS "GLFW hint prefix: ${GLFW_PREFIX_HINT}")
    endif()

    find_package(glfw3 3.3 QUIET)
    if(NOT glfw3_FOUND)
        # Try pkg-config for GLFW
        find_package(PkgConfig QUIET)
        if(PKG_CONFIG_FOUND)
            pkg_check_modules(GLFW glfw3)
        endif()
    endif()
    if(NOT glfw3_FOUND AND NOT GLFW_FOUND)
        message(FATAL_ERROR "GLFW 3.3+ not found. Install glfw or set CMAKE_PREFIX_PATH")
    endif()
    find_package(OpenGL REQUIRED)

    add_executable(fcaevpn
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_glfw.cpp
        ${IMGUI_BACKEND_DIR}/imgui_impl_opengl3.cpp
        ${CMAKE_SOURCE_DIR}/src_cpp/main_macos_glfw.cpp
        ${UI_SOURCES}
    )

    target_include_directories(fcaevpn PRIVATE
        ${IMGUI_DIR} ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
        ${CMAKE_BINARY_DIR}
    )

    target_compile_definitions(fcaevpn PRIVATE
        IMGUI_IMPL_OPENGL_LOADER_GL3W
        AETHER_TARGET_MACOS
        FCAE_VERSION="${FCAE_VERSION}"
    )
    if(FCAE_IS_PRERELEASE)
      target_compile_definitions(fcaevpn PRIVATE FCAE_IS_PRERELEASE)
    endif()

    if(AETHER_TARGET STREQUAL "MACOS_ARM64")
        fcae_ffi_lib_path(FCAE_FFI_A aarch64-apple-darwin)
    elseif(AETHER_TARGET STREQUAL "MACOS_X64")
        fcae_ffi_lib_path(FCAE_FFI_A x86_64-apple-darwin)
    else()
        # Native build on macOS host — detect arch
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
            fcae_ffi_lib_path(FCAE_FFI_A aarch64-apple-darwin)
        else()
            fcae_ffi_lib_path(FCAE_FFI_A x86_64-apple-darwin)
        endif()
    endif()
    fcae_link_ffi(fcaevpn "${FCAE_FFI_A}")
    if(AETHER_TARGET STREQUAL "MACOS_ARM64")
        fcae_link_psiphon(fcaevpn aarch64-apple-darwin)
    elseif(AETHER_TARGET STREQUAL "MACOS_X64")
        fcae_link_psiphon(fcaevpn x86_64-apple-darwin)
    else()
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
            fcae_link_psiphon(fcaevpn aarch64-apple-darwin)
        else()
            fcae_link_psiphon(fcaevpn x86_64-apple-darwin)
        endif()
    endif()

    # Link GLFW: use target if available (static), otherwise fall back to lib name
    if(TARGET glfw)
        target_link_libraries(fcaevpn PRIVATE glfw)
    else()
        target_link_libraries(fcaevpn PRIVATE ${GLFW_LIBRARIES})
    endif()

    target_link_libraries(fcaevpn PRIVATE
        OpenGL::GL
        "-framework Cocoa"
        "-framework IOKit"
        "-framework CoreFoundation"
        "-framework CoreVideo"
        # Required by the Go runtime inside libfcae_ffi.a (tun2socks c-archive):
        # crypto/x509 calls SecCertificate*/SecTrust* to read the system trust
        # store, and net resolves DNS through libresolv. Cargo emits these as
        # rustc-link-lib directives, but they only take effect when rustc links
        # the final artifact -- here CMake does, so they must be repeated or the
        # link fails with "Undefined symbols: _SecTrustEvaluateWithError", etc.
        "-framework Security"
        resolv
        pthread dl m
        z bz2 lzma
    )

    # macOS-specific linker flags
    target_link_options(fcaevpn PRIVATE
        -Wl,-dead_strip
        -Wl,-rpath,@executable_path/../Frameworks
        -Wl,-rpath,@executable_path
    )

elseif(UNIX)

    # Find GLFW with static library preference for portability
    find_package(glfw3 3.3 QUIET)
    if(NOT glfw3_FOUND)
        find_package(PkgConfig QUIET)
        if(PKG_CONFIG_FOUND)
            pkg_check_modules(GLFW glfw3)
        endif()
    endif()
    if(NOT glfw3_FOUND AND NOT GLFW_FOUND)
        message(FATAL_ERROR "GLFW 3.3+ not found. Install glfw3-dev or set CMAKE_PREFIX_PATH")
    endif()
    find_package(OpenGL REQUIRED)
    find_package(X11 REQUIRED)

    add_executable(fcaevpn
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_glfw.cpp
        ${IMGUI_BACKEND_DIR}/imgui_impl_opengl3.cpp
        ${CMAKE_SOURCE_DIR}/src_cpp/main_linux_glfw.cpp
        ${UI_SOURCES}
    )

    target_include_directories(fcaevpn PRIVATE
        ${IMGUI_DIR} ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
        ${CMAKE_BINARY_DIR}
    )

    target_compile_definitions(fcaevpn PRIVATE
        IMGUI_IMPL_OPENGL_LOADER_GL3W
        AETHER_TARGET_LINUX_X64
        FCAE_VERSION="${FCAE_VERSION}"
    )
    if(FCAE_IS_PRERELEASE)
      target_compile_definitions(fcaevpn PRIVATE FCAE_IS_PRERELEASE)
    endif()

    fcae_ffi_lib_path(FCAE_FFI_A x86_64-unknown-linux-gnu)
    fcae_link_ffi(fcaevpn "${FCAE_FFI_A}")
    fcae_link_psiphon(fcaevpn x86_64-unknown-linux-gnu)

    # Link GLFW: use imported target if available, otherwise raw lib name
    if(TARGET glfw)
        target_link_libraries(fcaevpn PRIVATE glfw)
    elseif(GLFW_LIBRARIES)
        target_link_libraries(fcaevpn PRIVATE ${GLFW_LIBRARIES})
    else()
        target_link_libraries(fcaevpn PRIVATE glfw)
    endif()

    # Do not link system OpenSSL (ssl/crypto) — BoringSSL is already in libfcae_ffi.a
    target_link_libraries(fcaevpn PRIVATE
        OpenGL::GL X11::X11 X11::Xi pthread dl m
        z bz2 lzma
        # The Go runtime in the tun2socks c-archive resolves names through
        # libresolv when cgo is enabled.
        resolv
    )

endif()

# ── Common compile flags ─────────────────────────────────────────────────
if(AETHER_TARGET STREQUAL "ANDROID_ARM64" OR AETHER_TARGET STREQUAL "ANDROID_ARM32" OR AETHER_TARGET STREQUAL "ANDROID_X86_64" OR AETHER_TARGET STREQUAL "ANDROID_UNIVERSAL")
    set(AETHER_COMPILE_TARGET fcaevpn_native)
else()
    set(AETHER_COMPILE_TARGET fcaevpn)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${AETHER_COMPILE_TARGET} PRIVATE -O3 -Wall -Wextra -Wpedantic)
endif()
