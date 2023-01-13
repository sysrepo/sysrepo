# Find Sysrepo
#  Once done, it will define
#
#  SYSREPO_FOUND - System has sysrepo
#  SYSREPO_INCLUDE_DIRS - The sysrepo include directories
#  SYSREPO_LIBRARIES - The libraries needed to use sysrepo
#  SYSREPO_VERSION - SO version of the found sysrepo library
#
#  Author Michal Vasko <mvasko@cesnet.cz>
#  Copyright (c) 2021 CESNET, z.s.p.o.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
include(FindPackageHandleStandardArgs)

if(SYSREPO_LIBRARIES AND SYSREPO_INCLUDE_DIRS)
    # in cache already
    set(SYSREPO_FOUND TRUE)
else()
    find_path(SYSREPO_INCLUDE_DIR
        NAMES sysrepo.h
        PATHS /usr/include /usr/local/include /opt/local/include /sw/include
        ${CMAKE_INCLUDE_PATH} ${CMAKE_INSTALL_PREFIX}/include
    )

    find_library(SYSREPO_LIBRARY
        NAMES sysrepo libsysrepo
        PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /opt/local/lib /sw/lib
        ${CMAKE_LIBRARY_PATH} ${CMAKE_INSTALL_PREFIX}/lib
    )

    if(SYSREPO_INCLUDE_DIR)
        find_path(SR_VERSION_PATH "sysrepo/version.h" HINTS ${SYSREPO_INCLUDE_DIR})
        file(READ "${SR_VERSION_PATH}/sysrepo/version.h" SR_VERSION_FILE)
        string(REGEX MATCH "#define SR_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\"" SR_VERSION_MACRO "${SR_VERSION_FILE}")
        string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" SYSREPO_VERSION "${SR_VERSION_MACRO}")
    endif()

    set(SYSREPO_INCLUDE_DIRS ${SYSREPO_INCLUDE_DIR})
    set(SYSREPO_LIBRARIES ${SYSREPO_LIBRARY})
    mark_as_advanced(SYSREPO_INCLUDE_DIRS SYSREPO_LIBRARIES)

    # handle the QUIETLY and REQUIRED arguments and set SYSREPO_FOUND to TRUE
    # if all listed variables are TRUE
    find_package_handle_standard_args(Sysrepo FOUND_VAR SYSREPO_FOUND
        REQUIRED_VARS SYSREPO_LIBRARY SYSREPO_INCLUDE_DIR
        VERSION_VAR SYSREPO_VERSION)
endif()
