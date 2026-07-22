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

# Resolve libaether_ffi.a from cargo (in-process engine is linked into this staticlib)
function(aether_ffi_lib_path out_var triple)
    set(candidates
        ${CMAKE_SOURCE_DIR}/target/${triple}/release/libaether_ffi.a
        ${CMAKE_SOURCE_DIR}/crates/aether-ffi/target/${triple}/release/libaether_ffi.a
        ${CMAKE_SOURCE_DIR}/crates/target/${triple}/release/libaether_ffi.a
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

    set(APP_GLUE_DIR ${ANDROID_NDK}/sources/android/native_app_glue)
    add_library(app-glue STATIC ${APP_GLUE_DIR}/android_native_app_glue.c)
    target_include_directories(app-glue PUBLIC ${APP_GLUE_DIR})

    aether_ffi_lib_path(AETHER_FFI_A aarch64-linux-android)
    aether_link_ffi(fcaevpn_native "${AETHER_FFI_A}")

    target_link_libraries(fcaevpn_native PRIVATE
        ${log-lib} ${android-lib} ${gles-lib} ${egl-lib} app-glue m
    )
    # Android shared libs: keep Rust #[no_mangle] exports
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
    )

    target_compile_options(fcaevpn PRIVATE -municode)

    aether_ffi_lib_path(AETHER_FFI_A x86_64-pc-windows-gnu)
    aether_link_ffi(fcaevpn "${AETHER_FFI_A}")

    # System libs only — crypto is inside the Rust staticlib (BoringSSL), not OpenSSL
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
            -Wl,-Bstatic -lstdc++ -lpthread -lwinpthread -Wl,-Bdynamic
            -s -mwindows -municode
        )
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

    aether_ffi_lib_path(AETHER_FFI_A x86_64-unknown-linux-gnu)
    aether_link_ffi(fcaevpn "${AETHER_FFI_A}")

    # Do not link system OpenSSL (ssl/crypto) — BoringSSL is already in libaether_ffi.a
    target_link_libraries(fcaevpn PRIVATE
        glfw OpenGL::GL X11::X11 X11::Xi pthread dl m
        z bz2 lzma
    )

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
