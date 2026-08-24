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

# Post-build check: the linked executable must carry exactly one application
# manifest requesting administrator rights.
#
# This verifies that the -specs mechanism successfully suppressed GCC's
# default-manifest.o, catching build issues before deployment.
#
# Invoked as: cmake -DEXE=<path> -P VerifyManifest.cmake

if(NOT DEFINED EXE)
    message(FATAL_ERROR "VerifyManifest: EXE was not provided")
endif()
if(NOT EXISTS "${EXE}")
    message(FATAL_ERROR "VerifyManifest: ${EXE} does not exist")
endif()

# Manifests are plain UTF-8 XML inside the resource section, so scanning the strings
# in the binary needs no external tool.
file(STRINGS "${EXE}" _elevation REGEX "requestedExecutionLevel")
file(STRINGS "${EXE}" _asis REGEX "level=\"asInvoker\"")

list(LENGTH _elevation _n_elevation)
if(_n_elevation EQUAL 0)
    message(FATAL_ERROR
        "VerifyManifest: no application manifest found in ${EXE}.\n"
        "app.rc should have embedded one requesting administrator rights.")
endif()

string(FIND "${_elevation}" "requireAdministrator" _admin_at)
if(_admin_at EQUAL -1)
    message(FATAL_ERROR
        "VerifyManifest: the embedded manifest does not request administrator "
        "rights.\nFound: ${_elevation}")
endif()

if(_asis)
    message(FATAL_ERROR
        "VerifyManifest: ${EXE} also carries an asInvoker manifest, which means "
        "GCC's default-manifest.o was linked in alongside ours.\n"
        "src/no-default-manifest.spec no longer matches this GCC's *endfile spec. "
        "Regenerate it: run `gcc -dumpspecs`, copy the *endfile block, and delete the "
        "default-manifest.o entry from it.")
endif()

message(STATUS "Manifest check: ${EXE} requests administrator rights.")
