cmake_minimum_required(VERSION 3.22)
project(fcaevpn LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Options ───────────────────────────────────────────────────────────────
option(AETHER_TARGET "Build target" "LINUX_X64")

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

# ── Target-specific configuration ────────────────────────────────────────
if(AETHER_TARGET STREQUAL "ANDROID_ARM64")

    add_library(fcaevpn_native SHARED
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_android.cpp
        ${IMGUI_BACKEND_DIR}/imgui_impl_opengl3.cpp
        ${CMAKE_SOURCE_DIR}/src_cpp/main_android_gles3.cpp
        ${UI_SOURCES}
    )

    target_include_directories(fcaevpn_native PRIVATE
        ${IMGUI_DIR}
        ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
    )

    target_compile_definitions(fcaevpn_native PRIVATE
        IMGUI_IMPL_OPENGL_ES3
        ANDROID
        AETHER_TARGET_ANDROID_ARM64
    )

    find_library(log-lib log)
    find_library(android-lib android)
    find_library(gles-lib GLESv3)
    find_library(egl-lib EGL)
    find_library(app-glue-lib android_native_app_glue)

    target_link_libraries(fcaevpn_native
        ${log-lib} ${android-lib} ${gles-lib} ${egl-lib} ${app-glue-lib} m
    )

    set(RUST_LIB_DIR ${CMAKE_SOURCE_DIR}/target/aarch64-linux-android/release)
    target_link_directories(fcaevpn_native PRIVATE ${RUST_LIB_DIR})
    target_link_libraries(fcaevpn_native libaether_ffi.a)

elseif(WIN32 OR AETHER_TARGET STREQUAL "WIN_X64")

    add_executable(fcaevpn
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_win32.cpp
        ${IMGUI_BACKEND_DIR}/imgui_impl_dx11.cpp
        ${CMAKE_SOURCE_DIR}/src_cpp/main_win32_dx11.cpp
        ${UI_SOURCES}
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
    )

    target_compile_options(fcaevpn PRIVATE -municode)

    target_link_libraries(fcaevpn PRIVATE d3d11 dxgi d3dcompiler dwmapi ntdll)

    set(RUST_LIB_DIR ${CMAKE_SOURCE_DIR}/target/x86_64-pc-windows-gnu/release)
    target_link_directories(fcaevpn PRIVATE ${RUST_LIB_DIR})
    target_link_libraries(fcaevpn PRIVATE libaether_ffi.a)
    target_link_libraries(fcaevpn PRIVATE ws2_32 userenv bcrypt shell32 ole32 uuid mingwthrd ntdll dwmapi)

    if(MINGW)
        target_link_options(fcaevpn PRIVATE -static -mwindows)
        target_link_libraries(fcaevpn PRIVATE stdc++ pthread)
    endif()

elseif(UNIX)

    find_package(glfw3 3.3 REQUIRED)
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
    )

    target_link_libraries(fcaevpn PRIVATE
        glfw OpenGL::GL X11::X11 X11::Xi pthread dl m
    )

    set(RUST_LIB_DIR ${CMAKE_SOURCE_DIR}/target/x86_64-unknown-linux-gnu/release)
    target_link_directories(fcaevpn PRIVATE ${RUST_LIB_DIR})
    target_link_libraries(fcaevpn PRIVATE libaether_ffi.a)
    target_link_libraries(fcaevpn PRIVATE ssl crypto z bz2 lzma curl)

endif()

# ── Common compile flags ─────────────────────────────────────────────────
if(AETHER_TARGET STREQUAL "ANDROID_ARM64")
    set(AETHER_COMPILE_TARGET fcaevpn_native)
else()
    set(AETHER_COMPILE_TARGET fcaevpn)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${AETHER_COMPILE_TARGET} PRIVATE -O2 -Wall -Wextra -Wpedantic)
endif()
