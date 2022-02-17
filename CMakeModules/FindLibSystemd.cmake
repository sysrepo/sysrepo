# - Try to find LibSystemd, it is expected find_package(PkgConfig) was called before
#
# Once done this will define
#
#  LIBSYSTEMD_FOUND - system has LibSystemd
#  LIBSYSTEMD_INCLUDE_DIRS - the LibSystemd include directory
#  LIBSYSTEMD_LIBRARIES - link these to use LibSystemd
#  SYSTEMD_UNIT_DIR - directory with systemd system unit files
#
#  Author Michal Vasko <mvasko@cesnet.cz>
#  Copyright (c) 2022 CESNET, z.s.p.o.
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

if(LIBSYSTEMD_LIBRARIES AND LIBSYSTEMD_INCLUDE_DIRS AND SYSTEMD_UNIT_DIR)
    # in cache already
    set(LIBSYSTEMD_FOUND TRUE)
else()
    find_path(LIBSYSTEMD_INCLUDE_DIR
        NAMES
        systemd/sd-daemon.h
        PATHS
        /usr/include
        /usr/local/include
        /opt/local/include
        /sw/include
        ${CMAKE_INCLUDE_PATH}
        ${CMAKE_INSTALL_PREFIX}/include
    )

    find_library(LIBSYSTEMD_LIBRARY
        NAMES
        systemd
        libsystemd
        PATHS
        /usr/lib
        /usr/lib64
        /usr/local/lib
        /usr/local/lib64
        /opt/local/lib
        /sw/lib
        ${CMAKE_LIBRARY_PATH}
        ${CMAKE_INSTALL_PREFIX}/lib
    )

    if(NOT SYSTEMD_UNIT_DIR)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --define-variable=rootprefix=${CMAKE_INSTALL_PREFIX} --variable=systemdsystemunitdir systemd
                OUTPUT_VARIABLE SYSTEMD_UNIT_DIR)
        string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_DIR "${SYSTEMD_UNIT_DIR}")
    endif()

    set(LIBSYSTEMD_INCLUDE_DIRS ${LIBSYSTEMD_INCLUDE_DIR})
    set(LIBSYSTEMD_LIBRARIES ${LIBSYSTEMD_LIBRARY})
    mark_as_advanced(LIBSYSTEMD_INCLUDE_DIRS LIBSYSTEMD_LIBRARIES)

    # handle the QUIETLY and REQUIRED arguments and set LIBSYSTEMD_FOUND to TRUE
    # if all listed variables are TRUE
    find_package_handle_standard_args(LibSystemd FOUND_VAR LIBSYSTEMD_FOUND
        REQUIRED_VARS LIBSYSTEMD_LIBRARY LIBSYSTEMD_INCLUDE_DIR SYSTEMD_UNIT_DIR)
endif()
