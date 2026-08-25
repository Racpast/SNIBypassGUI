# Copyright © 2026 Racpast. All Rights Reserved.
#
# This file is part of SNIBypassGUI, a proprietary software project.
#
# NOTICE: All information contained herein is, and remains the property of
# Racpast. The intellectual and technical concepts contained herein are
# proprietary to Racpast and are protected by copyright law and international
# treaties. Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained from Racpast.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited.
#
# For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
#
# See the LICENSE file in the project root for full terms and conditions.

cmake_minimum_required(VERSION 3.21)

# ---------------------------------------------------------------------------
# Version — single source of truth is APP_VERSION_NUM in src/app/version.h.
#
# Read before project(), so that even CMake's own PROJECT_VERSION comes from
# there. Every other copy of the version in this build — the native FILEVERSION
# resource, the assembly manifest — is generated from these variables, so a bump
# is one edit in one file and nothing can be left behind at the old number.
# ---------------------------------------------------------------------------
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/src/app/version.h" _ver_line
     REGEX "^[ \t]*#define[ \t]+APP_VERSION_NUM[ \t]+L\"")
if(NOT _ver_line)
    message(FATAL_ERROR "APP_VERSION_NUM not found in src/app/version.h")
endif()
string(REGEX REPLACE ".*L\"([^\"]*)\".*" "\\1" SNIB_VERSION "${_ver_line}")

string(REPLACE "." ";" _ver_parts "${SNIB_VERSION}")
list(LENGTH _ver_parts _ver_len)
set(_ver_names A B C D)
foreach(_i RANGE 3)
    if(_i LESS _ver_len)
        list(GET _ver_parts ${_i} _part)
        string(REGEX REPLACE "[^0-9]" "" _part "${_part}")
        if(_part STREQUAL "")
            set(_part 0)
        endif()
    else()
        set(_part 0)
    endif()
    list(GET _ver_names ${_i} _name)
    set(SNIB_VER_${_name} ${_part})
endforeach()
set(SNIB_VER_NUMERIC "${SNIB_VER_A}.${SNIB_VER_B}.${SNIB_VER_C}.${SNIB_VER_D}")

project(SNIBypassGUI VERSION ${SNIB_VER_NUMERIC} LANGUAGES C CXX)
message(STATUS "SNIBypassGUI version: ${SNIB_VERSION} (numeric ${SNIB_VER_NUMERIC})")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

option(SNIB_BUILD_TESTS "Build the unit test suite" OFF)

# What clangd and clang-tidy read to learn each translation unit's flags. Without
# it an editor falls back to guessing them, and every Windows header resolves to
# nothing — the diagnostics that follow are about the guess, not the code.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Windows only.
# ---------------------------------------------------------------------------
if(NOT WIN32)
    message(FATAL_ERROR "SNIBypassGUI targets Windows. Configure with a MinGW-w64 toolchain.")
endif()

# ---------------------------------------------------------------------------
# Compile definitions applied to every target.
# ---------------------------------------------------------------------------
add_compile_definitions(
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601)

set(SNIB_WARNING_FLAGS -Wall -Wextra)

set(SNIB_CHARSET_FLAGS
    -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE)

set(SNIB_PRIVACY_FLAGS
    -fno-ident
    "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
    "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=.")

# ---------------------------------------------------------------------------
# Resource script — generated into the build tree so src/ stays clean.
# ---------------------------------------------------------------------------
set(SNIB_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${SNIB_GENERATED_DIR}")

set(SNIB_APP_RC "${SNIB_GENERATED_DIR}/app.rc")
configure_file("${CMAKE_SOURCE_DIR}/src/app.rc.in" "${SNIB_APP_RC}" @ONLY)

# The assembly manifest carries the version too, so it is generated from the same
# variables rather than kept in step by hand. It lands beside the generated app.rc,
# which is where that script's reference to it resolves from.
configure_file("${CMAKE_SOURCE_DIR}/src/app.manifest.in"
               "${SNIB_GENERATED_DIR}/app.manifest" @ONLY)

enable_language(RC)
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -I${SNIB_GENERATED_DIR} -I${CMAKE_SOURCE_DIR}/resources/branding -I${CMAKE_SOURCE_DIR}/src -I${CMAKE_SOURCE_DIR}/resources/embedded")

# ---------------------------------------------------------------------------
# Shared object library: every translation unit except the entry point.
# ---------------------------------------------------------------------------
add_library(snib_core OBJECT
    src/app/bootstrap.cpp
    src/app/filesystem.cpp
    src/app/i18n.cpp
    src/app/logging.cpp
    src/app/paths.cpp
    src/app/services.cpp
    src/app/settings.cpp
    src/app/text.cpp
    src/app/version.cpp
    src/dns/file_watcher.cpp
    src/dns/message.cpp
    src/dns/nrpt.cpp
    src/dns/redirector.cpp
    src/dns/resolver.cpp
    src/dns/rules.cpp
    src/platform/autostart.cpp
    src/platform/command.cpp
    src/platform/elevation.cpp
    src/platform/embedded_text.cpp
    src/platform/ports.cpp
    src/platform/process.cpp
    src/platform/shell.cpp
    src/platform/shortcut.cpp
    src/update/client.cpp
    src/update/crypto.cpp
    src/update/http.cpp
    src/update/json.cpp)

target_include_directories(snib_core PUBLIC
    "${CMAKE_SOURCE_DIR}/src"
    "${SNIB_GENERATED_DIR}")

target_compile_options(snib_core PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O2>
    -municode
    ${SNIB_WARNING_FLAGS}
    ${SNIB_CHARSET_FLAGS}
    ${SNIB_PRIVACY_FLAGS})

# ---------------------------------------------------------------------------
# UI objects (only needed in the executable, not in the test runner).
# ---------------------------------------------------------------------------
add_library(snib_ui OBJECT
    src/ui/eula.cpp
    src/ui/supported_sites.cpp
    src/ui/tray.cpp)

target_include_directories(snib_ui PUBLIC "${CMAKE_SOURCE_DIR}/src")
target_compile_options(snib_ui PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O2>
    -municode
    ${SNIB_WARNING_FLAGS}
    ${SNIB_CHARSET_FLAGS}
    ${SNIB_PRIVACY_FLAGS})

# ---------------------------------------------------------------------------
# Main executable.
# ---------------------------------------------------------------------------
add_executable(SNIBypassGUI WIN32
    src/main.cpp
    $<TARGET_OBJECTS:snib_core>
    $<TARGET_OBJECTS:snib_ui>
    "${SNIB_APP_RC}")

target_include_directories(SNIBypassGUI PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${SNIB_GENERATED_DIR}")

target_compile_options(SNIBypassGUI PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-O2>
    -municode
    ${SNIB_WARNING_FLAGS}
    ${SNIB_CHARSET_FLAGS}
    ${SNIB_PRIVACY_FLAGS})

# Suppress GCC's automatic default-manifest.o so ours (from app.rc) is the only one.
include("${CMAKE_SOURCE_DIR}/cmake/NoDefaultManifest.cmake")
snib_generate_no_default_manifest_spec(SNIB_NO_DEFAULT_MANIFEST_SPEC)

target_link_options(SNIBypassGUI PRIVATE
    -municode -mwindows
    -static -static-libgcc -static-libstdc++
    -s
    "-specs=${SNIB_NO_DEFAULT_MANIFEST_SPEC}"
    -Wl,--gc-sections)

add_custom_command(TARGET SNIBypassGUI POST_BUILD
    COMMAND ${CMAKE_COMMAND}
            "-DEXE=$<TARGET_FILE:SNIBypassGUI>"
            -P "${CMAKE_SOURCE_DIR}/cmake/VerifyManifest.cmake"
    VERBATIM)

# taskschd/oleaut32: start-at-logon is registered through the Task Scheduler API,
# so a non-ASCII install path never has to survive a console code page.
target_link_libraries(SNIBypassGUI PRIVATE
    iphlpapi ws2_32 wininet bcrypt crypt32 shell32 ole32 oleaut32 taskschd advapi32 user32
    gdi32 comctl32)

# ---------------------------------------------------------------------------
# Tests (opt-in).
# ---------------------------------------------------------------------------
if(SNIB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install + dist.
# ---------------------------------------------------------------------------
install(TARGETS SNIBypassGUI RUNTIME DESTINATION .)
install(DIRECTORY "${CMAKE_SOURCE_DIR}/resources/payload/"
        DESTINATION .
        USE_SOURCE_PERMISSIONS)

add_custom_target(dist
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${CMAKE_SOURCE_DIR}/dist"
    COMMAND ${CMAKE_COMMAND} --install "${CMAKE_BINARY_DIR}" --prefix "${CMAKE_SOURCE_DIR}/dist"
    DEPENDS SNIBypassGUI
    COMMENT "Staging exe + payload into dist/")
