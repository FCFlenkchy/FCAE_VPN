cmake_minimum_required(VERSION 3.22)
project(fcaevpn LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
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

# Parse version into MAJOR.MINOR.PATCH.BUILD for the Windows RC
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

# Source files
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

# ---------------------------------------------------------------------------
# FreeType (optional text rasteriser)
#
# ImGui's default rasteriser is stb_truetype; misc/freetype/imgui_freetype.cpp
# swaps in FreeType, which hints glyph stems so small UI text stays crisp and
# renders each size on demand instead of baking a fixed atlas.
#
# Deliberately a soft dependency:
#   * nothing defines IMGUI_ENABLE_FREETYPE globally. That define makes
#     imgui.cpp require the FreeType symbol, so a machine without the library
#     would fail to link instead of falling back. The UI selects the loader at
#     runtime with io.Fonts->SetFontLoader(), which is in imgui.h's public API.
#   * the Windows build here is cross-compiled on Linux. A host libfreetype
#     found by find_package() would be x86-64 ELF, and linking it into a PE
#     binary fails at the link step -- the late, all-platform-broken kind of
#     failure this project keeps paying for. So a cross build never looks for
#     it: -DFCAE_FREETYPE=system is the explicit opt-in, -DFCAE_FREETYPE=OFF
#     the explicit opt-out, and AUTO skips the Windows cross build.
#
# FCAE_FREETYPE_ENABLED is what the UI sees, via a generated define, so the
# runtime call and the compiled-in loader can never disagree.
# ---------------------------------------------------------------------------
set(FCAE_FREETYPE "AUTO" CACHE STRING
    "FreeType text rasteriser: AUTO, ON, system, or OFF")

set(FCAE_FREETYPE_ENABLED FALSE)
set(FCAE_FREETYPE_SOURCE "")
set(FCAE_FREETYPE_SHARED FALSE)

if(NOT FCAE_FREETYPE STREQUAL "OFF")
    set(_ft_may_look TRUE)
    # A cross build cannot use libraries from the build machine's sysroot.
    if(CMAKE_CROSSCOMPILING AND NOT FCAE_FREETYPE STREQUAL "system"
            AND NOT FCAE_FREETYPE STREQUAL "ON")
        message(STATUS "FreeType: skipped (cross-compiling; pass -DFCAE_FREETYPE=system to force)")
        set(_ft_may_look FALSE)
    endif()

    if(_ft_may_look)
        find_package(Freetype QUIET)
        if(FREETYPE_FOUND AND FREETYPE_INCLUDE_DIRS)
            set(FCAE_FREETYPE_ENABLED TRUE)
            set(FCAE_FREETYPE_SOURCE "${FREETYPE_LIBRARY}")
            # Package managers very often install both a .so/.dylib and a
            # static archive under the same base name. Prefer the archive: a
            # dynamically linked FreeType inside a shipped app is a load-time
            # dependency on a path the user's machine may not have, and the
            # macOS packaging check rejects it outright.
            get_filename_component(_ft_dir "${FREETYPE_LIBRARY}" DIRECTORY)
            get_filename_component(_ft_file "${FREETYPE_LIBRARY}" NAME)
            # Strip the shared-library tail properly. NAME_WE is not enough: it
            # removes only the last extension, so "libfreetype.so" stays
            # "libfreetype.so" and the candidate became "libfreetype.so.a".
            string(REGEX REPLACE "\\.[^.]*$" "" _ft_stem "${_ft_file}")
            string(REGEX REPLACE "\\.(so|dylib)$" "" _ft_stem "${_ft_stem}")
            foreach(_ft_ext a lib)
                set(_ft_candidate "${_ft_dir}/${_ft_stem}.${_ft_ext}")
                if(EXISTS "${_ft_candidate}")
                    set(FCAE_FREETYPE_SOURCE "${_ft_candidate}")
                    break()
                endif()
            endforeach()
            # Still shared? Then packaging has to put it inside the bundle.
            if(FCAE_FREETYPE_SOURCE MATCHES "\\.(so|dylib)(\\.[0-9.]+)?$")
                set(FCAE_FREETYPE_SHARED TRUE)
                message(STATUS "FreeType: ${FREETYPE_VERSION_STRING} (shared, ${FCAE_FREETYPE_SOURCE}) -- the bundle must embed it")
            else()
                message(STATUS "FreeType: ${FREETYPE_VERSION_STRING} (static, ${FCAE_FREETYPE_SOURCE})")
            endif()
        elseif(FCAE_FREETYPE STREQUAL "ON" OR FCAE_FREETYPE STREQUAL "system")
            message(FATAL_ERROR
                "FCAE_FREETYPE=${FCAE_FREETYPE} but no FreeType was found. "
                "Install libfreetype6-dev / freetype2, or set -DFCAE_FREETYPE=OFF.")
        else()
            message(STATUS "FreeType: not found, using ImGui's built-in rasteriser")
        endif()
    endif()
endif()

if(FCAE_FREETYPE_ENABLED)
    list(APPEND IMGUI_SOURCES ${IMGUI_DIR}/misc/freetype/imgui_freetype.cpp)
endif()

# Resolve one of FreeType's own dependencies as a static archive and link it
# into `target_name`. Missing dependencies are skipped, not fatal: the point is
# to supply what the FreeType build actually calls out to.
#
# Two details in here are load-bearing, and both cost a debugging round:
#
#  * find_library() prefers the shared object. A directory holding both libz.so
#    and libz.a resolves to libz.so every time, so the result is accepted only
#    if it really ends in .a, and a static sibling is looked for by hand
#    otherwise. (find_library(... SUFFIXES ".a") does not do this job: on CMake
#    3.31 it still returned libz.so.)
#  * find_library() caches under its result variable. Without clearing it, the
#    second call silently reuses the first one's path -- every dependency
#    resolved to libz.so, which is exactly what happened before the unset().
#
# Defined at file scope on purpose -- defining a function inside an if()/else()
# block is a CMake flow-control error, not a nested definition.
function(_fcae_link_static_dep target_name dep_names)
    unset(_fcae_dep_lib CACHE)
    find_library(_fcae_dep_lib NAMES ${dep_names})
    if(_fcae_dep_lib AND _fcae_dep_lib MATCHES "\\.a$")
        target_link_libraries(${target_name} PRIVATE ${_fcae_dep_lib})
    else()
        get_filename_component(_fcae_dep_dir "${_fcae_dep_lib}" DIRECTORY)
        if(_fcae_dep_lib)
            foreach(_fcae_stem IN LISTS dep_names)
                if(EXISTS "${_fcae_dep_dir}/lib${_fcae_stem}.a")
                    target_link_libraries(${target_name} PRIVATE "${_fcae_dep_dir}/lib${_fcae_stem}.a")
                    break()
                endif()
            endforeach()
        endif()
    endif()
endfunction()

# One helper, so the three platform targets cannot drift apart on this: adds
# the include paths, the define ui_render.cpp tests, and the library.
function(fcae_apply_freetype target_name)
    if(NOT FCAE_FREETYPE_ENABLED)
        return()
    endif()
    target_include_directories(${target_name} PRIVATE
        ${FREETYPE_INCLUDE_DIRS}
        ${IMGUI_DIR}/misc/freetype
    )
    target_compile_definitions(${target_name} PRIVATE FCAE_HAVE_FREETYPE=1)
    if(FCAE_FREETYPE_SOURCE)
        # A static FreeType is not self-contained, and FindFreetype does not
        # say so: its FREETYPE_LIBRARIES is just the one library path, with the
        # dependencies already baked into the shared object it normally points
        # at. Linking the bare archive therefore fails at the very end of the
        # build with "symbol(s) not found" for inflate, BZ2_*, png_* and
        # HVF_* -- after everything has compiled, the most expensive place to
        # find out.
        #
        # So the dependencies are resolved here by name. Everything is optional
        # except zlib and bzip2, which a normal FreeType build always has;
        # each is linked on whichever platform names it, and simply skipped
        # where it does not exist.
        target_link_libraries(${target_name} PRIVATE ${FCAE_FREETYPE_SOURCE})

        if(WIN32)
            # MinGW/MSYS2 name the same libraries this way; they resolve to the
            # import libraries of whatever the toolchain ships.
            target_link_libraries(${target_name} PRIVATE z bz2)
        else()
            # Each dependency is resolved archive-first. Linking FreeType
            # statically and then dragging in libpng/libbrotli as shared
            # libraries would leave the shipped app depending on Homebrew paths
            # anyway -- it would just move the problem one library over.
            #
            # Two names are tried per dependency because packagers differ:
            # a normal install has libpng16/libbrotlidec, Homebrew additionally
            # suffixes its static ones "-static".
            # Order matters for static archives: the linker makes a single
            # left-to-right pass, so a library has to come after everything
            # that references it. libpng needs zlib's deflate, brotlidec needs
            # brotlicommon, harfbuzz needs zlib and ICU -- so the leaf
            # libraries go last. Getting this backwards shows up as
            # "undefined reference to deflate" with every file already
            # compiled.
            #
            # Newer FreeType releases compile HarfBuzz' hvf shaper in and call
            # out to it: that is the HVF_* symbols in the macOS link error.
            _fcae_link_static_dep(${target_name} "harfbuzz;harfbuzz-static")
            _fcae_link_static_dep(${target_name} "png16;png")
            _fcae_link_static_dep(${target_name} "brotlidec;brotlidec-static")
            _fcae_link_static_dep(${target_name} "bz2")
            _fcae_link_static_dep(${target_name} "brotlicommon;brotlicommon-static")
            _fcae_link_static_dep(${target_name} "z;zlib")
        endif()
        if(FREETYPE_LIBRARIES)
            foreach(_ft_dep IN LISTS FREETYPE_LIBRARIES)
                if(NOT _ft_dep STREQUAL FCAE_FREETYPE_SOURCE)
                    target_link_libraries(${target_name} PRIVATE ${_ft_dep})
                endif()
            endforeach()
        endif()
    elseif(FREETYPE_LIBRARIES)
        target_link_libraries(${target_name} PRIVATE ${FREETYPE_LIBRARIES})
    endif()
endfunction()

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

# sing-box's naive outbound drives Chromium's network stack, cronet, and where
# that library ends up differs per platform, because what a platform can carry
# differs:
#
#   Linux    one file, cronet linked in. Its objects go through the isolation
#            pass below (binutils cannot read them, and their BoringSSL collides
#            with ours), and the executable carries ~10 MB of it.
#   macOS    a dylib next to the app, linked from cronet-go's archive here. Not
#            a preference: cronet contributes a fourth exception personality
#            routine (base::apple's), and Mach-O encodes at most three in
#            compact unwind, so the image does not link with it inside.
#   Windows  inside the executable, as `libcronet.dll` unpacked at run time.
#            cronet-go publishes no Windows static archive (Chromium is MSVC-
#            only, and a cgo link is MinGW), so the DLL is embedded by
#            `fcae-runtime`'s build script and staged beside `deps/` by
#            `fcae_runtime::cronet` — see those modules.
#   Android  cgo inside the c-shared Go library, i.e. part of the .so Android
#            loads.
#
# The Rust side decides which of those apply: `with_purego` is set for Windows
# and Apple, and its absence is what leaves cronet in the Linux link.

# Locate one published cronet-go artifact (`lib/${goos}_${goarch}`) in the
# module cache the Rust build just populated.
function(fcae_cronet_artifact out_var goos goarch name)
    set(${out_var} "" PARENT_SCOPE)

    set(mod_cache "")
    find_program(FCAE_GO_EXECUTABLE NAMES go)
    if(FCAE_GO_EXECUTABLE)
        execute_process(
            COMMAND "${FCAE_GO_EXECUTABLE}" env GOMODCACHE
            OUTPUT_VARIABLE mod_cache
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(NOT mod_cache)
        set(mod_cache "$ENV{GOMODCACHE}")
    endif()
    if(NOT mod_cache)
        set(mod_cache "$ENV{HOME}/go/pkg/mod")
    endif()

    # Glob, so a version bump of cronet-go needs no edit here.
    file(GLOB cronet_libs
        "${mod_cache}/github.com/sagernet/cronet-go/lib/${goos}_${goarch}@*/${name}")
    if(NOT cronet_libs)
        message(WARNING
            "cronet-go's ${name} for ${goos}_${goarch} not found under ${mod_cache} "
            "(build the Rust side first); sing-box's naive outbound will not load")
        return()
    endif()
    list(SORT cronet_libs COMPARE NATURAL ORDER DESCENDING)
    list(GET cronet_libs 0 cronet_lib)
    set(${out_var} "${cronet_lib}" PARENT_SCOPE)
endfunction()

# The archives cronet-go ships are LLVM-built, and that shows in two ways the
# ELF frontend link has to answer before it sees them.
#
# Their relocation sections are CREL (SHT_CREL): a compact encoding LLVM 19
# introduced and GNU binutils has never read, so `ld` rejects every member with
# "unknown architecture of input file ... is incompatible with i386:x86-64" --
# no binutils release can change that (binutils PR 31475, still open).
#
# They also carry a complete second BoringSSL next to the one boring-sys builds
# for the Rust side. Cronet pulls the members it needs, those define the same
# bssl:: symbols with a different version behind them, and the link stops at
# "multiple definition of bssl::SSL_HANDSHAKE::~SSL_HANDSHAKE()".
#
# Both are fixed on the archive instead of at the link line: one LLVM pass folds
# it into a single relocatable object rooted at its C API, and everything that is
# not that API gets local binding. Cronet's internals then resolve inside cronet
# -- the only sound outcome for a library that vendored its own copies of
# BoringSSL, brotli, protobuf and absl -- while the frontend keeps exactly one
# global definition per symbol. Nothing is suppressed and no code is dropped: the
# objects are the same, only their visibility in this link changes.
#
# The toolchain is the Rust one the project already builds with; rust-lld reads
# CREL and llvm-objcopy is the component that can rewrite the symbol table of an
# object that carries it.
function(fcae_llvm_binaries out_lld out_nm out_objcopy)
    find_program(FCAE_RUSTC NAMES rustc)
    if(NOT FCAE_RUSTC)
        message(FATAL_ERROR
            "rustc was not found. The ELF frontend link needs the LLVM linker and "
            "binutils that ship with the Rust toolchain, because cronet-go's prebuilt "
            "objects use CREL relocations that GNU binutils cannot read.")
    endif()
    execute_process(COMMAND "${FCAE_RUSTC}" --print sysroot
        OUTPUT_VARIABLE _sysroot OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    execute_process(COMMAND "${FCAE_RUSTC}" -vV
        OUTPUT_VARIABLE _version COMMAND_ERROR_IS_FATAL ANY)
    if(NOT _version MATCHES "host: ([A-Za-z0-9_.-]+)")
        message(FATAL_ERROR "cannot read the host triple from `rustc -vV`")
    endif()
    set(_bin "${_sysroot}/lib/rustlib/${CMAKE_MATCH_1}/bin")
    foreach(_tool rust-lld llvm-nm llvm-objcopy)
        if(NOT EXISTS "${_bin}/${_tool}")
            message(FATAL_ERROR
                "${_tool} is missing from the Rust toolchain at ${_bin}. Install it with "
                "`rustup component add llvm-tools-preview`; the ELF frontend link needs "
                "rust-lld and llvm-objcopy to read cronet-go's CREL objects.")
        endif()
    endforeach()
    set(${out_lld} "${_bin}/rust-lld" PARENT_SCOPE)
    set(${out_nm} "${_bin}/llvm-nm" PARENT_SCOPE)
    set(${out_objcopy} "${_bin}/llvm-objcopy" PARENT_SCOPE)
endfunction()

# Rewrite `archive` into `out_obj`: one relocatable object reachable from the
# archive's C API, with every other definition local to it.
function(fcae_cronet_isolate archive out_obj lld nm objcopy)
    if(EXISTS "${out_obj}")
        if(NOT "${archive}" IS_NEWER_THAN "${out_obj}")
            return()
        endif()
    endif()

    # The roots are the archive's own C API. Nothing else is called across the
    # boundary: cronet-go's cgo wrappers name Cronet_* and bidirectional_stream_*
    # and no other symbol of the archive.
    # stderr carries a "no symbols" line for every foreign-architecture member
    # the archive holds; they are neither errors nor ours to print.
    execute_process(COMMAND "${nm}" -j --defined-only --extern-only "${archive}"
        OUTPUT_VARIABLE _symbols RESULT_VARIABLE _rc
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "cannot read the symbol table of ${archive}")
    endif()
    string(REPLACE "\n" ";" _lines "${_symbols}")
    # Anchored on a whole symbol name: llvm-nm prints a member header per archive
    # member and those names end in `.o:`, which is not a symbol.
    list(FILTER _lines INCLUDE REGEX "^(Cronet_|bidirectional_stream_)[A-Za-z0-9_]*$")
    list(REMOVE_DUPLICATES _lines)
    list(LENGTH _lines _count)
    if(_count LESS 100)
        message(FATAL_ERROR
            "${archive} exposes only ${_count} C API symbols; the archive layout changed")
    endif()

    get_filename_component(_dir "${out_obj}" DIRECTORY)
    file(MAKE_DIRECTORY "${_dir}")
    set(_api "${_dir}/cronet-api.txt")
    string(REPLACE ";" "\n" _api_text "${_lines}")
    file(WRITE "${_api}" "${_api_text}\n")

    set(_roots "")
    foreach(_symbol IN LISTS _lines)
        list(APPEND _roots "-u${_symbol}")
    endforeach()

    set(_merged "${_dir}/cronet-merged.o")
    execute_process(COMMAND "${lld}" -r -o "${_merged}" ${_roots} "${archive}"
        COMMAND_ERROR_IS_FATAL ANY)
    execute_process(COMMAND "${objcopy}" "--keep-global-symbols=${_api}" "${_merged}" "${out_obj}"
        COMMAND_ERROR_IS_FATAL ANY)
    file(REMOVE "${_merged}")
    message(STATUS "cronet isolated: ${_count} API symbols global, ${archive}")
endfunction()

# Put the isolated cronet object in `target`'s link and switch that link to LLVM.
function(fcae_link_cronet_elf target archive)
    fcae_llvm_binaries(FCAE_LLVM_LLD FCAE_LLVM_NM FCAE_LLVM_OBJCOPY)

    # rust-lld takes its dialect from the name it was invoked under, and gcc
    # looks its linker up by name too, so one `ld.lld` symlink serves both the
    # isolation pass here and the frontend link below. rustup ships the same
    # link as rustlib/<host>/bin/gcc-ld/ld.lld.
    set(_lld_dir "${CMAKE_BINARY_DIR}/lld")
    file(MAKE_DIRECTORY "${_lld_dir}")
    file(REMOVE "${_lld_dir}/ld.lld")
    file(CREATE_LINK "${FCAE_LLVM_LLD}" "${_lld_dir}/ld.lld" SYMBOLIC)
    set(_lld "${_lld_dir}/ld.lld")

    set(_isolated "${CMAKE_BINARY_DIR}/cronet/libcronet-isolated.o")
    fcae_cronet_isolate("${archive}" "${_isolated}"
        "${_lld}" "${FCAE_LLVM_NM}" "${FCAE_LLVM_OBJCOPY}")
    target_link_libraries(${target} PRIVATE "${_isolated}")

    # The isolated object still carries CREL relocations, and anything else LLVM
    # built will too, so the ELF frontend links with LLVM's linker instead of one
    # that cannot read its input.
    target_link_options(${target} PRIVATE
        "-B${_lld_dir}"
        "-fuse-ld=lld"
    )
    message(STATUS "ELF frontend link uses rust-lld: ${FCAE_LLVM_LLD}")
endfunction()

# cronet-go publishes macOS cronet only as a static archive, so the dylib the
# app loads is linked from it here.
#
# The image is rooted at the archive's C API -- the only symbols cronet-go's
# binding resolves -- so the closure those entry points pull is the whole
# library, and its dependencies are the ones cronet-go's own darwin cgo line
# names. Sharing code with the frontend is a non-issue in a dylib: a two-level
# namespace keeps cronet's copy of BoringSSL and libc++ private to it even when
# the frontend carries its own, and the binding resolves symbols in this image
# only.
function(fcae_cronet_stage_darwin target archive arch)
    set(_out "${CMAKE_BINARY_DIR}/libcronet.dylib")

    # Whole symbol names in Mach-O spelling: the leading underscore is also what
    # the linker's -u takes.
    find_program(FCAE_NM NAMES nm REQUIRED)
    execute_process(COMMAND "${FCAE_NM}" -g "${archive}"
        OUTPUT_VARIABLE _symbols RESULT_VARIABLE _rc ERROR_QUIET)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "cannot read the symbol table of ${archive}")
    endif()
    string(REPLACE "\n" ";" _lines "${_symbols}")
    # Only a defined symbol carries an address and a type letter in front of its
    # name; an undefined reference carries neither, so this keeps the archive's
    # defined Cronet_*/bidirectional_stream_* entry points and nothing else.
    list(FILTER _lines INCLUDE REGEX
        "^[0-9a-fA-F]+ +[A-Za-z] +_(Cronet_|bidirectional_stream_)[A-Za-z0-9_]*$")
    set(_roots)
    foreach(_line IN LISTS _lines)
        string(REGEX REPLACE "^[0-9a-fA-F]+ +[A-Za-z] +" "" _symbol "${_line}")
        list(APPEND _roots "-Wl,-u,${_symbol}")
    endforeach()
    list(REMOVE_DUPLICATES _roots)
    list(LENGTH _roots _count)
    if(_count LESS 100)
        message(FATAL_ERROR
            "${archive} exposes only ${_count} C API symbols; the archive layout changed")
    endif()

    set(_deploy "${CMAKE_OSX_DEPLOYMENT_TARGET}")
    if(NOT _deploy)
        set(_deploy 13.0)
    endif()
    # Only a resolved path is an -isysroot argument; a bare name ("macosx") is
    # what the compiler resolves on its own.
    set(_sysroot)
    if(IS_ABSOLUTE "${CMAKE_OSX_SYSROOT}")
        set(_sysroot "-isysroot" "${CMAKE_OSX_SYSROOT}")
    endif()

    add_custom_command(OUTPUT "${_out}"
        COMMAND "${CMAKE_C_COMPILER}" -dynamiclib -o "${_out}"
            -arch "${arch}" ${_sysroot}
            -mmacosx-version-min=${_deploy}
            -install_name "@executable_path/libcronet.dylib"
            ${_roots}
            "${archive}"
            -lbsm -lpmenergy -lpmsample -lresolv
            -framework CoreFoundation -framework CoreGraphics -framework CoreText
            -framework Foundation -framework Security
            -framework ApplicationServices -framework AppKit
            -framework IOKit -framework OpenDirectory -framework CFNetwork
            -framework CoreServices -framework Network
            -framework SystemConfiguration -framework UniformTypeIdentifiers
            -framework CryptoTokenKit -framework LocalAuthentication
        DEPENDS "${archive}"
        COMMENT "Linking libcronet.dylib (${_count} C API roots) from cronet-go's archive"
        VERBATIM)
    add_custom_target(fcae_cronet_runtime ALL DEPENDS "${_out}")
    add_dependencies(${target} fcae_cronet_runtime)
    message(STATUS "cronet runtime library: ${_out} (from ${archive})")
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
# Psiphon and tun2socks use the same Go runtime.
function(fcae_link_audio_backend target_name)
    # Cargo's native-link metadata is not propagated through the later CMake
    # link of the Rust static library. Add each rodio/cpal platform backend to
    # the final executable/shared-library link explicitly.
    if(AETHER_TARGET MATCHES "^ANDROID_" OR ANDROID)
        find_library(FCAE_AAUDIO_LIB aaudio)
        if(NOT FCAE_AAUDIO_LIB)
            message(FATAL_ERROR "Android AAudio library not found in the NDK sysroot")
        endif()
        target_link_libraries(${target_name} PRIVATE ${FCAE_AAUDIO_LIB})
    elseif(APPLE OR AETHER_TARGET STREQUAL "MACOS_ARM64" OR AETHER_TARGET STREQUAL "MACOS_X64")
        target_link_libraries(${target_name} PRIVATE
            "-framework CoreAudio"
            "-framework AudioToolbox"
        )
    elseif(WIN32 OR AETHER_TARGET STREQUAL "WIN_X64")
        # WASAPI's COM and UUID imports are already covered by the existing
        # ole32/uuid entries below. CPAL also calls the Kernel32 wait/event
        # APIs, whose native-link metadata is not propagated from the Rust
        # static library.
        target_link_libraries(${target_name} PRIVATE kernel32)
    elseif(UNIX)
        find_library(FCAE_ALSA_LIB asound)
        if(NOT FCAE_ALSA_LIB)
            message(FATAL_ERROR "ALSA library not found; install libasound2-dev")
        endif()
        target_link_libraries(${target_name} PRIVATE ${FCAE_ALSA_LIB})
    endif()
endfunction()

function(fcae_link_go_bridges target_name abi)
    set(jni_dir ${CMAKE_SOURCE_DIR}/android/app/src/main/jniLibs/${abi})
    # TUN mode always needs it: a hard dependency.
    set(t2s ${jni_dir}/libfcae_go_bridge.so)
    if(NOT EXISTS "${t2s}")
        message(FATAL_ERROR
            "Missing required Android Go bridge: ${t2s}. Build the fcae-ffi tun2socks bridge "
            "for ${abi} before configuring CMake so Gradle can package it.")
    endif()
    target_link_libraries(${target_name} PRIVATE "${t2s}")
    message(STATUS "linking Go bridge: ${t2s}")

    # The .so sits next to our library in the APK's native lib dir.
    target_link_options(${target_name} PRIVATE "-Wl,-rpath,\\$ORIGIN")
endfunction()

# Target-specific configuration
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
    fcae_link_audio_backend(fcaevpn_native)
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
    fcae_link_audio_backend(fcaevpn_native)
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
    fcae_link_audio_backend(fcaevpn_native)
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
    fcae_link_audio_backend(fcaevpn_native)
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
    fcae_apply_freetype(fcaevpn)

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
    fcae_link_audio_backend(fcaevpn)
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
    # Cargo's native-link metadata is not forwarded to this CMake link.
    # Keep the HEV archives after the Rust staticlib and group them because
    # the engine and its task/lwIP dependencies refer to one another.
    set(FCAE_HEV_ARCHIVE_DIR "$ENV{FCAE_HEV_LIBDIR}")
    if(FCAE_HEV_ARCHIVE_DIR STREQUAL "")
        set(FCAE_HEV_ARCHIVE_DIR "${CMAKE_SOURCE_DIR}/core/hev-socks5-tunnel/bin/fcae-windows")
    endif()
    set(FCAE_HEV_ARCHIVES)
    foreach(name hev-socks5-tunnel yaml lwip hev-task-system)
        set(archive "${FCAE_HEV_ARCHIVE_DIR}/lib${name}.a")
        if(NOT EXISTS "${archive}")
            message(FATAL_ERROR "static HEV archive missing: ${archive}")
        endif()
        list(APPEND FCAE_HEV_ARCHIVES "${archive}")
    endforeach()
    target_link_libraries(fcaevpn PRIVATE -Wl,--start-group ${FCAE_HEV_ARCHIVES} -Wl,--end-group)

    # System libs only — crypto lives in the Rust staticlib (BoringSSL).
    # pthread MUST come after libfcae_ffi.a (BoringSSL thread_pthread needs it).
    target_link_libraries(fcaevpn PRIVATE
        d3d11 dxgi d3dcompiler dwmapi ntdll
        ws2_32 userenv bcrypt shell32 ole32 uuid crypt32 secur32 ncrypt
        iphlpapi advapi32 psapi mswsock user32 dnsapi wintrust version
        netapi32 wtsapi32 setupapi cfgmgr32 oleaut32 pdh
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

    # No windowing library and no OpenGL: macOS renders through AppKit and
    # Metal, both of which are in the OS. Metal is the only graphics API Apple
    # still develops, and the one the iOS front end would use too.
    # Objective-C++ for the two ImGui Apple backends and this host. ARC stays
    # off, which is both clang's default and what the backends assume: they hand
    # raw pointers to ImGui and pair their own retains with releases.
    #
    # Only enabled when the host is Apple: CMake probes the language with a real
    # trial compile, so enabling it on a host without an Objective-C++ front end
    # would fail during configure. A cross build that reaches this branch with
    # AETHER_TARGET set to a macOS target has to bring its own toolchain file and
    # enable OBJCXX there, because compiling a macOS app at all needs the SDK.
    if(APPLE)
        enable_language(OBJCXX)
    endif()

    add_executable(fcaevpn
        ${IMGUI_SOURCES}
        ${IMGUI_BACKEND_DIR}/imgui_impl_metal.mm
        ${IMGUI_BACKEND_DIR}/imgui_impl_osx.mm
        ${CMAKE_SOURCE_DIR}/src_cpp/main_macos_metal.mm
        ${UI_SOURCES}
    )
    fcae_apply_freetype(fcaevpn)

    target_include_directories(fcaevpn PRIVATE
        ${IMGUI_DIR} ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
        ${CMAKE_BINARY_DIR}
    )

    target_compile_definitions(fcaevpn PRIVATE
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
    fcae_link_audio_backend(fcaevpn)

    # cronet is not linked here: cronet-go's purego binding loads the dylib
    # from beside the executable (see the cronet notes above).
    if(FCAE_FFI_A MATCHES "aarch64-apple-darwin")
        set(FCAE_CRONET_GOARCH arm64)
        set(FCAE_CRONET_ARCH arm64)
    else()
        set(FCAE_CRONET_GOARCH amd64)
        set(FCAE_CRONET_ARCH x86_64)
    endif()
    fcae_cronet_artifact(FCAE_CRONET_A darwin ${FCAE_CRONET_GOARCH} libcronet.a)
    if(FCAE_CRONET_A)
        fcae_cronet_stage_darwin(fcaevpn "${FCAE_CRONET_A}" "${FCAE_CRONET_ARCH}")
    endif()

    target_link_libraries(fcaevpn PRIVATE
        # AppKit draws the window, Metal draws the UI, QuartzCore supplies the
        # CAMetalLayer the view presents through. The ImGui OSX backend also
        # needs GameController for its gamepad path.
        "-framework Cocoa"
        "-framework Metal"
        "-framework MetalKit"
        "-framework QuartzCore"
        "-framework GameController"
        "-framework IOKit"
        "-framework CoreFoundation"
        "-framework CoreVideo"
        # Go runtime in libfcae_ffi.a: Security for the system trust store,
        # resolv for DNS — cargo's directives never reach this CMake link.
        "-framework Security"
        resolv
        pthread dl m
        z bz2 lzma
        # What the Go dependencies' own cgo link lines ask for and a c-archive
        # cannot carry: sing-box's usbip service, whose usbhost_darwin is cgo
        # with "-framework Foundation -framework IOKit -framework IOUSBHost",
        # and only the last one was missing. CoreFoundation, IOKit, Foundation,
        # Security and Network are above. cronet's darwin libraries (bsm,
        # pmenergy, pmsample) were on this list only while cronet was linked in;
        # they belong to the dylib now.
        "-framework CoreGraphics"
        "-framework CoreText"
        "-framework Foundation"
        "-framework ApplicationServices"
        "-framework AppKit"
        "-framework IOKit"
        "-framework OpenDirectory"
        "-framework CFNetwork"
        "-framework CoreServices"
        "-framework Network"
        "-framework SystemConfiguration"
        "-framework UniformTypeIdentifiers"
        "-framework CryptoTokenKit"
        "-framework LocalAuthentication"
        "-framework IOUSBHost"
    )

    # macOS-specific linker flags
    # -S/-x drop the debug map (STABS) and local symbols ld64 keeps by default.
    #
    # No -no_compact_unwind: this image carries exactly three exception
    # personality routines -- Rust's for libfcae_ffi.a, libc++'s for the C++
    # frontend, and the audio backend's Objective-C one -- and three is what
    # compact unwind encodes. The fourth, base::apple's, came from cronet's
    # ObjC++ exception shim and left with the dylib (see the cronet notes above).
    target_link_options(fcaevpn PRIVATE
        -Wl,-dead_strip
        -Wl,-S
        -Wl,-x
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
    fcae_apply_freetype(fcaevpn)

    target_include_directories(fcaevpn PRIVATE
        ${IMGUI_DIR} ${IMGUI_BACKEND_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src_cpp
        ${CMAKE_BINARY_DIR}
    )

    # ui_render.cpp calls glfwPostEmptyEvent() so a change reported from a
    # worker thread ends the host's wait immediately. The glfw CMake target
    # carries its include directory, but the pkg-config fallback below exports
    # only library paths, so add the headers explicitly.
    if(GLFW_INCLUDE_DIRS)
        target_include_directories(fcaevpn PRIVATE ${GLFW_INCLUDE_DIRS})
    endif()

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
    fcae_link_audio_backend(fcaevpn)

    fcae_cronet_artifact(FCAE_CRONET_A linux amd64 libcronet.a)
    if(FCAE_CRONET_A)
        fcae_link_cronet_elf(fcaevpn "${FCAE_CRONET_A}")
    endif()

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
    # -s as on Windows: BoringSSL builds itself with -ggdb, and its DWARF alone
    # is ~23 MB of the shipped binary.
    target_link_options(fcaevpn PRIVATE
        -static-libgcc -static-libstdc++
        -s
    )

endif()

# Common compile flags
if(AETHER_TARGET STREQUAL "ANDROID_ARM64" OR AETHER_TARGET STREQUAL "ANDROID_ARM32" OR AETHER_TARGET STREQUAL "ANDROID_X86_64" OR AETHER_TARGET STREQUAL "ANDROID_UNIVERSAL")
    set(AETHER_COMPILE_TARGET fcaevpn_native)
else()
    set(AETHER_COMPILE_TARGET fcaevpn)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${AETHER_COMPILE_TARGET} PRIVATE -O3 -Wall -Wextra -Wpedantic)
endif()
