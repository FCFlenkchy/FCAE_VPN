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

if(NOT DEFINED FCAE_IS_PRERELEASE)
  if(DEFINED ENV{FCAE_IS_PRERELEASE})
    set(FCAE_IS_PRERELEASE "$ENV{FCAE_IS_PRERELEASE}")
  else()
    set(FCAE_IS_PRERELEASE "${_selected_pre}")
  endif()
endif()

if(FCAE_IS_PRERELEASE)
  if(NOT _selected_pre)
    string(APPEND FCAE_VERSION "_pre-release")
  endif()
else()
  set(FCAE_VERSION "${_selected_base}")
endif()

message(STATUS "FCAE_VERSION = ${FCAE_VERSION}")
message(STATUS "FCAE_IS_PRERELEASE = ${FCAE_IS_PRERELEASE}")

# ── Parse version into MAJOR.MINOR.PATCH.BUILD for the Windows RC ────────
set(FCAE_VERSION_MAJOR 0)
set(FCAE_VERSION_MINOR 0)
set(FCAE_VERSION_PATCH 0)
set(FCAE_VERSION_BUILD 0)
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
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/src_cpp/imgui)
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

# Public C header for the FFI layer, so sources just #include "fcae.h".
set(FCAE_FFI_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/core/fcae-ffi/include)

# Resolve libfcae_ffi.a from cargo; it carries the whole Rust side (core,
# selected backends, Go bridges) — there is no separate engine executable to
# build, sign or ship any more.
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

# Link the Rust staticlib once, as a full path, through an IMPORTED target so
# CMake does not re-scan or duplicate the archive.
# Do NOT use --whole-archive: the archive packs C objects (BoringSSL, the Go
# runtime) that appear more than once and whole-archive then fails with
# thousands of "multiple definition" errors; normal linking is enough because
# the C++ frontend references fcae_init/start/stop/... and pulls the graph.
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

# Give an Android shared object 16 KB-aligned LOAD segments: Android 15 runs
# with 16 KB pages on new devices and its loader rejects 4 KB-layout .so's
# (System.loadLibrary threw UnsatisfiedLinkError at launch). NDK r27+ honours
# ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES; the explicit flags cover older NDKs.
# Verify: llvm-readelf -l libfcaevpn_native.so | grep LOAD  (Align 0x4000)
function(fcae_align_16k target_name)
    target_link_options(${target_name} PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384"
    )
    message(STATUS "16 KB page alignment enabled for ${target_name}")
endfunction()

# Link the Go bridge on Android. The Go toolchain rejects
# -buildmode=c-archive there, so tun2socks is built as
# libfcae_go_bridge.so and staged into jniLibs/<abi>/ — it is NOT inside
# libfcae_ffi.a, and cargo's dylib directives never reach this CMake link,
# so the .so must be named explicitly (or ld.lld reports undefined t2s_*).
# Do not link a second Go runtime next to it — that SIGSEGVs at dlopen.
function(fcae_link_go_bridges target_name abi)
    set(jni_dir ${CMAKE_SOURCE_DIR}/android/app/src/main/jniLibs/${abi})
    # TUN mode always needs it: a hard dependency.
    set(t2s ${jni_dir}/libfcae_go_bridge.so)
    if(EXISTS "${t2s}")
        target_link_libraries(${target_name} PRIVATE "${t2s}")
        message(STATUS "linking Go bridge: ${t2s}")
    endif()

    # The .so sits next to our library in the APK's native lib dir.
    target_link_options(${target_name} PRIVATE "-Wl,-rpath,\\$ORIGIN")
endfunction()

# Desktop Psiphon: a second Go runtime as libfcae_psiphon (c-shared).
#
# Deliberately NOT linked and NOT copied. The Rust bridge embeds the built
# library with include_bytes!, writes it under the temp directory on first
# use, and binds its psi_* exports with dlopen/dlsym. Linking it here would
# put it back in the executable's import table and make the loader require a
# copy beside the app -- which is the one thing the embedding exists to
# avoid. This stays a configuration-time report so a missing bridge is still
# visible in the log.
function(fcae_link_psiphon target_name triple)
    set(dirs
        ${CMAKE_SOURCE_DIR}/target/${triple}/release
        ${CMAKE_SOURCE_DIR}/core/fcae-ffi/target/${triple}/release
    )
    foreach(d ${dirs})
        foreach(ext dll so dylib)
            if(EXISTS "${d}/libfcae_psiphon.${ext}")
                message(STATUS
                    "desktop Psiphon embedded in ${target_name} "
                    "(built at ${d}/libfcae_psiphon.${ext}; loaded at runtime, not linked)")
                return()
            endif()
        endforeach()
    endforeach()
    message(STATUS "libfcae_psiphon not built for ${triple} (psiphon-live off?)")
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

    # Universal Android build: a sentinel so configuration succeeds; Gradle
    # invokes CMake once per ABI with the correct ANDROID_ABI.
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
    # Cargo native-link metadata is not propagated through the CMake link.
    # Add the static zeptun archive explicitly after libfcae_ffi.a so the
    # bridge's zeptun_* references resolve without importing zeptun.dll.
    set(FCAE_ZEPTUN_A "${CMAKE_SOURCE_DIR}/core/zeptun/zig-out/lib/libzeptun.a")
    if(NOT EXISTS "${FCAE_ZEPTUN_A}")
        message(FATAL_ERROR "static zeptun archive missing: ${FCAE_ZEPTUN_A}")
    endif()
    target_link_options(fcaevpn PRIVATE "-Wl,-Bstatic")
    target_link_libraries(fcaevpn PRIVATE "${FCAE_ZEPTUN_A}")
    target_link_options(fcaevpn PRIVATE "-Wl,-Bdynamic")
    fcae_link_psiphon(fcaevpn x86_64-pc-windows-gnu)

    # System libs only — crypto lives in the Rust staticlib (BoringSSL).
    # pthread MUST come after libfcae_ffi.a (BoringSSL thread_pthread needs it).
    target_link_libraries(fcaevpn PRIVATE
        d3d11 dxgi d3dcompiler dwmapi ntdll
        ws2_32 userenv bcrypt shell32 ole32 uuid crypt32 secur32 ncrypt
        iphlpapi
        # fwpuclnt: the statically linked zeptun engine drives the Windows
        # Filtering Platform (Fwpm*) to keep the tunnel's own sockets out of
        # the tunnel; its imports land in libfcae_ffi.a, and cargo's link
        # directives never reach this link.
        fwpuclnt
        # winmm: the Go runtime in libfcae_ffi.a calls timeBeginPeriod.
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

    # Find GLFW: CI-built static prefixes first, then system GLFW.
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
        # Go runtime in libfcae_ffi.a: Security for the system trust store,
        # resolv for DNS — cargo's directives never reach this CMake link.
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
    # Prefer the concrete GL implementation (libGL.so.1) over the Khronos
    # dispatcher (libOpenGL.so.0): on every glvnd distro libGL.so.1 is a hard
    # dependency of libgl1, while libOpenGL.so.0 ships only in the optional
    # `libopengl0` package, so a binary linked against it refuses to start on
    # minimal / server installs. macOS has no choice but libGL.so.1.
    find_package(OpenGL REQUIRED)
    set(FCAE_GL_LIB OpenGL::GL)
    if(NOT APPLE)
        # Concrete path for libGL.so.1 (always present with libgl1); the
        # CMake `OpenGL::GL` imported target on glvnd setups emits a DT_NEEDED
        # for libOpenGL.so.0 instead, which is a hard failure on minimal
        # installs. Fall back to the imported target only when we genuinely
        # cannot locate libGL.so.1.
        set(_fcae_gl_paths)
        foreach(_lib_name IN ITEMS libGL.so.1 libGL.so.3 libGL.so.0)
            find_library(_fcae_gl_lib_${_lib_name} NAMES ${_lib_name}
                PATHS /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib /lib/x86_64-linux-gnu
                NO_DEFAULT_PATH)
            if(_fcae_gl_lib_${_lib_name})
                list(APPEND _fcae_gl_paths "${_fcae_gl_lib_${_lib_name}}")
            endif()
        endforeach()
        if(_fcae_gl_paths)
            list(GET _fcae_gl_paths 0 FCAE_GL_LIB)
            message(STATUS "OpenGL library for Linux: ${FCAE_GL_LIB} (avoids libOpenGL.so.0 dep)")
        else()
            message(WARNING "Could not locate libGL.so.1; using OpenGL::GL (may require libopengl0 at runtime)")
        endif()
    endif()
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

    # Do not link system OpenSSL (ssl/crypto) — BoringSSL is in libfcae_ffi.a.
    # Compression libs link statically. X11/GL stay dynamic (driver dispatch
    # through dlopen), as do glibc and its NSS plugins.
    target_link_libraries(fcaevpn PRIVATE
        ${FCAE_GL_LIB} X11::X11 X11::Xi pthread dl m
        -Wl,-Bstatic z bz2 lzma -Wl,-Bdynamic
        # libresolv: the Go runtime in libfcae_ffi.a resolves names through it.
        resolv
    )

    # Static toolchain runtime: no libstdc++/libgcc_s dependency at startup.
    target_link_options(fcaevpn PRIVATE
        -static-libgcc -static-libstdc++
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
