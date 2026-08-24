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

# Derive a GCC spec override that suppresses the automatic default-manifest.o.
#
# app.rc embeds our own RT_MANIFEST requesting administrator rights. GCC links its
# own default-manifest.o (asInvoker) into every non-DLL, causing a linker failure
# with ".rsrc merge failure: multiple non-default manifests".
#
# The override is generated from the compiler's `-dumpspecs` output by deleting the
# default-manifest.o entry from the *endfile block. This ensures it stays correct
# across compiler updates.
#
# Sets SNIB_NO_DEFAULT_MANIFEST_SPEC to the generated file's path.

function(snib_generate_no_default_manifest_spec out_var)
    set(_generated_dir "${CMAKE_BINARY_DIR}/generated")
    set(_generated "${_generated_dir}/no-default-manifest.spec")
    file(MAKE_DIRECTORY "${_generated_dir}")

    execute_process(
        COMMAND "${CMAKE_CXX_COMPILER}" -dumpspecs
        OUTPUT_VARIABLE _specs
        ERROR_VARIABLE _specs_err
        RESULT_VARIABLE _specs_rc)
    if(NOT _specs_rc EQUAL 0)
        message(FATAL_ERROR
            "Could not read the compiler's spec strings.\n"
            "`${CMAKE_CXX_COMPILER} -dumpspecs` exited ${_specs_rc}: ${_specs_err}")
    endif()

    # Normalize line endings (some MinGW builds may output CRLF).
    string(REPLACE "\r\n" "\n" _specs "${_specs}")
    string(REPLACE "\r" "\n" _specs "${_specs}")

    # Spec text is full of semicolons, which CMake would otherwise treat as list
    # separators; escape them for the whole round trip and unescape on write.
    string(REPLACE ";" "\;" _specs "${_specs}")

    # The *endfile block is a single line listing the object files GCC appends at
    # link time. default-manifest.o is one entry inside it.
    string(REGEX MATCH "[*]endfile:\n([^\n]*)\n" _matched "${_specs}")
    if(NOT _matched)
        message(FATAL_ERROR
            "Could not find the *endfile block in `${CMAKE_CXX_COMPILER} -dumpspecs`.\n"
            "This GCC lays its specs out differently than expected, so the "
            "default-manifest override cannot be derived.")
    endif()
    set(_endfile "${CMAKE_MATCH_1}")

    string(FIND "${_endfile}" "default-manifest.o" _found_at)
    if(_found_at EQUAL -1)
        message(FATAL_ERROR
            "The *endfile spec does not mention default-manifest.o, so this GCC does "
            "not link one automatically.\n"
            "That is good news, but it means the override in cmake/"
            "NoDefaultManifest.cmake is now obsolete and should be removed rather "
            "than left silently doing nothing.")
    endif()

    # Drop the conditional that pulls in default-manifest.o, leaving the rest of the
    # block (crtfastmath, vtable-verify, crtend) exactly as this compiler wrote it.
    # Use a regex that tolerates whitespace and minor format changes.
    string(REGEX REPLACE "%\\{[^}]*default-manifest\\.o[^}]*\\}" ""
           _stripped "${_endfile}")
    if(_stripped STREQUAL _endfile)
        message(FATAL_ERROR
            "Found default-manifest.o in the *endfile spec but could not remove it.\n"
            "The regex pattern did not match, which means this GCC formats the entry "
            "differently than expected.\n"
            "Spec text was:\n${_endfile}")
    endif()

    string(FIND "${_stripped}" "default-manifest.o" _still_at)
    if(NOT _still_at EQUAL -1)
        message(FATAL_ERROR
            "default-manifest.o still present after stripping the *endfile spec.\n"
            "Result was:\n${_stripped}")
    endif()

    string(REPLACE "\;" ";" _stripped "${_stripped}")
    file(WRITE "${_generated}" "*endfile:\n${_stripped}\n\n")

    set(${out_var} "${_generated}" PARENT_SCOPE)
endfunction()
