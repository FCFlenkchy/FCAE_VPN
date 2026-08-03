cmake_minimum_required(VERSION 3.22)
project(fcaevpn LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ───────────────────────────────────────────────────────────────
option(AETHER_TARGET "Build target" "LINUX_X64")

# ── Extract version from version.json (used by desktop UI for update check) ─
if(EXISTS "${CMAKE_SOURCE_DIR}/version.json")
  file(READ "${CMAKE_SOURCE_DIR}/version.json" _ver_json)
  string(REGEX MATCH "\"version\"[ ]*:[ ]*\"([^\"]+)\"" _ver_match "${_ver_json}")
  if(CMAKE_MATCH_1)
    set(FCAE_VERSION "${CMAKE_MATCH_1}")
  else()
    set(FCAE_VERSION "dev")
  endif()
else()
  set(FCAE_VERSION "dev")
endif()
message(STATUS "FCAE_VERSION = ${FCAE_VERSION}")

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

# Resolve libaether_ffi.a from cargo (in-process engine is linked into this staticlib)
function(aether_ffi_lib_path out_var triple)
    set(candidates
        ${CMAKE_SOURCE_DIR}/target/${triple}/release/libaether_ffi.a
        ${CMAKE_SOURCE_DIR}/core/aether-ffi/target/${triple}/release/libaether_ffi.a
        ${CMAKE_SOURCE_DIR}/core/target/${triple}/release/libaether_ffi.a
    )
    foreach(c ${candidates})
        if(EXISTS "${c}")
            set(${out_var} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${out_var} "${CMAKE_SOURCE_DIR}/target/${triple}/release/libaether_ffi.a" PARENT_SCOPE)
endfunction()

# Link Rust staticlib once as a full path.
# Do NOT use --whole-archive: cargo packs C objects (BoringSSL bcm.o, etc.) that can
# appear more than once in the archive; whole-archive then causes thousands of
# "multiple definition" errors. Normal archive linking is enough because the C++
# frontend references aether_init/start/stop/... which pull the rest of the graph.
function(aether_link_ffi target_name lib_path)
    if(NOT EXISTS "${lib_path}")
        message(WARNING "libaether_ffi.a not found at ${lib_path} (build rust first)")
    endif()
    # IMPORTED static library so CMake does not re-scan/duplicate the archive
    get_filename_component(_aether_ffi_name "${lib_path}" NAME_WE)
    if(NOT TARGET aether_ffi_imported)
        add_library(aether_ffi_imported STATIC IMPORTED GLOBAL)
        set_target_properties(aether_ffi_imported PROPERTIES
            IMPORTED_LOCATION "${lib_path}"
        )
    endif()
    target_link_libraries(${target_name} PRIVATE aether_ffi_imported)
endfunction()

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

    aether_ffi_lib_path(AETHER_FFI_A aarch64-linux-android)
    aether_link_ffi(fcaevpn_native "${AETHER_FFI_A}")

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)

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

    aether_ffi_lib_path(AETHER_FFI_A armv7-linux-androideabi)
    aether_link_ffi(fcaevpn_native "${AETHER_FFI_A}")

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)

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

    aether_ffi_lib_path(AETHER_FFI_A x86_64-linux-android)
    aether_link_ffi(fcaevpn_native "${AETHER_FFI_A}")

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} m
    )
    target_link_options(fcaevpn_native PRIVATE -Wl,--export-dynamic)

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
    )

    target_compile_definitions(fcaevpn PRIVATE
        UNICODE _UNICODE
        IMGUI_IMPL_WIN32_DISABLE_GAMEPAD
        AETHER_TARGET_WIN_X64
        FCAE_VERSION="${FCAE_VERSION}"
    )

    target_compile_options(fcaevpn PRIVATE -municode)

    aether_ffi_lib_path(AETHER_FFI_A x86_64-pc-windows-gnu)
    aether_link_ffi(fcaevpn "${AETHER_FFI_A}")

    # System libs only — crypto is inside the Rust staticlib (BoringSSL), not OpenSSL.
    # pthread MUST come after libaether_ffi.a (BoringSSL thread_pthread needs it).
    target_link_libraries(fcaevpn PRIVATE
        d3d11 dxgi d3dcompiler dwmapi ntdll
        ws2_32 userenv bcrypt shell32 ole32 uuid crypt32 secur32 ncrypt
        iphlpapi
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
    )

    target_compile_definitions(fcaevpn PRIVATE
        IMGUI_IMPL_OPENGL_LOADER_GL3W
        AETHER_TARGET_MACOS
        FCAE_VERSION="${FCAE_VERSION}"
    )

    if(AETHER_TARGET STREQUAL "MACOS_ARM64")
        aether_ffi_lib_path(AETHER_FFI_A aarch64-apple-darwin)
    elseif(AETHER_TARGET STREQUAL "MACOS_X64")
        aether_ffi_lib_path(AETHER_FFI_A x86_64-apple-darwin)
    else()
        # Native build on macOS host — detect arch
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
            aether_ffi_lib_path(AETHER_FFI_A aarch64-apple-darwin)
        else()
            aether_ffi_lib_path(AETHER_FFI_A x86_64-apple-darwin)
        endif()
    endif()
    aether_link_ffi(fcaevpn "${AETHER_FFI_A}")

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
    )

    target_compile_definitions(fcaevpn PRIVATE
        IMGUI_IMPL_OPENGL_LOADER_GL3W
        AETHER_TARGET_LINUX_X64
        FCAE_VERSION="${FCAE_VERSION}"
    )

    aether_ffi_lib_path(AETHER_FFI_A x86_64-unknown-linux-gnu)
    aether_link_ffi(fcaevpn "${AETHER_FFI_A}")

    # Link GLFW: use imported target if available, otherwise raw lib name
    if(TARGET glfw)
        target_link_libraries(fcaevpn PRIVATE glfw)
    elseif(GLFW_LIBRARIES)
        target_link_libraries(fcaevpn PRIVATE ${GLFW_LIBRARIES})
    else()
        target_link_libraries(fcaevpn PRIVATE glfw)
    endif()

    # Do not link system OpenSSL (ssl/crypto) — BoringSSL is already in libaether_ffi.a
    target_link_libraries(fcaevpn PRIVATE
        OpenGL::GL X11::X11 X11::Xi pthread dl m
        z bz2 lzma
    )

endif()

# ── Common compile flags ─────────────────────────────────────────────────
if(AETHER_TARGET STREQUAL "ANDROID_ARM64" OR AETHER_TARGET STREQUAL "ANDROID_ARM32" OR AETHER_TARGET STREQUAL "ANDROID_X86_64")
    set(AETHER_COMPILE_TARGET fcaevpn_native)
else()
    set(AETHER_COMPILE_TARGET fcaevpn)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${AETHER_COMPILE_TARGET} PRIVATE -O2 -Wall -Wextra -Wpedantic)
endif()
