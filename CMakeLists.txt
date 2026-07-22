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

# Resolve aether engine binary produced by cargo (bundled next to GUI).
function(aether_engine_bin out_var triple name)
    set(candidates
        ${CMAKE_SOURCE_DIR}/aether/aether/target/${triple}/release/${name}
        ${CMAKE_SOURCE_DIR}/aether/target/${triple}/release/${name}
        ${CMAKE_SOURCE_DIR}/target/${triple}/release/${name}
    )
    foreach(c ${candidates})
        if(EXISTS "${c}")
            set(${out_var} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${out_var} "${CMAKE_SOURCE_DIR}/aether/aether/target/${triple}/release/${name}" PARENT_SCOPE)
endfunction()

# Resolve libaether_ffi.a from cargo
function(aether_ffi_lib_dir out_var triple)
    set(candidates
        ${CMAKE_SOURCE_DIR}/target/${triple}/release
        ${CMAKE_SOURCE_DIR}/crates/aether-ffi/target/${triple}/release
        ${CMAKE_SOURCE_DIR}/crates/aether-ffi/target/release
    )
    foreach(c ${candidates})
        if(EXISTS "${c}/libaether_ffi.a")
            set(${out_var} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${out_var} "${CMAKE_SOURCE_DIR}/target/${triple}/release" PARENT_SCOPE)
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

    target_link_libraries(fcaevpn_native
        ${log-lib} ${android-lib} ${gles-lib} ${egl-lib} app-glue m
    )

    aether_ffi_lib_dir(RUST_LIB_DIR aarch64-linux-android)
    target_link_directories(fcaevpn_native PRIVATE ${RUST_LIB_DIR})
    target_link_libraries(fcaevpn_native libaether_ffi.a)

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

    aether_ffi_lib_dir(RUST_LIB_DIR x86_64-pc-windows-gnu)
    target_link_directories(fcaevpn PRIVATE ${RUST_LIB_DIR})

    target_link_libraries(fcaevpn PRIVATE
        libaether_ffi.a
        d3d11 dxgi d3dcompiler dwmapi ntdll
        ws2_32 userenv bcrypt shell32 ole32 uuid
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

    aether_engine_bin(AETHER_ENGINE_SRC x86_64-pc-windows-gnu aether.exe)
    add_custom_command(TARGET fcaevpn POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DSRC=${AETHER_ENGINE_SRC}
            -DDST=$<TARGET_FILE_DIR:fcaevpn>/aether.exe
            -P ${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake
        COMMENT "Bundle aether.exe next to fcaevpn"
        VERBATIM
    )

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

    aether_ffi_lib_dir(RUST_LIB_DIR x86_64-unknown-linux-gnu)
    target_link_directories(fcaevpn PRIVATE ${RUST_LIB_DIR})
    target_link_libraries(fcaevpn PRIVATE libaether_ffi.a)
    target_link_libraries(fcaevpn PRIVATE ssl crypto z bz2 lzma curl)

    aether_engine_bin(AETHER_ENGINE_SRC x86_64-unknown-linux-gnu aether)
    add_custom_command(TARGET fcaevpn POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DSRC=${AETHER_ENGINE_SRC}
            -DDST=$<TARGET_FILE_DIR:fcaevpn>/aether
            -DMAKE_EXECUTABLE=1
            -P ${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake
        COMMENT "Bundle aether next to fcaevpn"
        VERBATIM
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
