cmake_minimum_required(VERSION 2.8.12)

project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository for all-around configuration management.")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(UseCompat)
include(ABICheck)
include(SourceFormat)
include(GenDoc)
include(GenCoverage)
if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# set default build type if not specified by user and normalize it
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
# see https://github.com/CESNET/libyang/pull/1692 for why CMAKE_C_FLAGS_<type> are not used directly
if("${BUILD_TYPE_UPPER}" STREQUAL "RELEASE")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-DNDEBUG -O2 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -O0 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBUG")
    set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    set(CMAKE_BUILD_TYPE "ABICheck" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -Og ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    set(CMAKE_BUILD_TYPE "DocOnly" CACHE STRING "Build Type" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

if(NOT FORCE_WSL AND EXISTS "/proc/sys/kernel/osrelease")
    file(READ "/proc/sys/kernel/osrelease" OS_RELEASE)
    string(FIND ${OS_RELEASE} "Microsoft" POS)
    if(POS GREATER -1)
        message(FATAL_ERROR "Windows Subsystem for Linux is not supported. Set FORCE_WSL var to bypass at your own risk.")
    endif()
endif()

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(SYSREPO_MAJOR_VERSION 2)
set(SYSREPO_MINOR_VERSION 2)
set(SYSREPO_MICRO_VERSION 73)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(SYSREPO_MAJOR_SOVERSION 7)
set(SYSREPO_MINOR_SOVERSION 14)
set(SYSREPO_MICRO_SOVERSION 32)
set(SYSREPO_SOVERSION_FULL ${SYSREPO_MAJOR_SOVERSION}.${SYSREPO_MINOR_SOVERSION}.${SYSREPO_MICRO_SOVERSION})
set(SYSREPO_SOVERSION ${SYSREPO_MAJOR_SOVERSION})

# Version of libyang library that this sysrepo depends on
set(LIBYANG_DEP_VERSION 2.1.77)
set(LIBYANG_DEP_SOVERSION 2.35.7)
set(LIBYANG_DEP_SOVERSION_MAJOR 2)

# generate only version header, it is needed for docs
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_BINARY_DIR}/version.h" ESCAPE_QUOTES @ONLY)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -std=c11")

#
# options
#
if(("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG") OR ("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO"))
    option(ENABLE_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_EXAMPLES "Build examples." ON)
option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)
option(INSTALL_SYSCTL_CONF "Install sysctl conf file to allow shared access to SHM files." OFF)
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/sysrepo" CACHE STRING "Directory where to copy the YANG modules to")

# ietf-yang-library revision
set(YANGLIB_REVISION "2019-01-04" CACHE STRING
    "YANG module ietf-yang-library revision to implement. Only 2019-01-04 and 2016-06-21 are supported.")
if(NOT ${YANGLIB_REVISION} STREQUAL "2019-01-04" AND NOT ${YANGLIB_REVISION} STREQUAL "2016-06-21")
    message(FATAL_ERROR "Unsupported ietf-yang-library revision ${YANGLIB_REVISION} specified!")
endif()
message(STATUS "ietf-yang-library revision: ${YANGLIB_REVISION}")

# security
set(SYSREPO_UMASK "000" CACHE STRING "Umask used for any files created by sysrepo.")
set(SYSREPO_GROUP "" CACHE STRING "System group that will own all sysrepo-related files. If empty, the specific process group will be kept.")
set(SYSREPO_SUPERUSER_UID "0" CACHE STRING "UID of the system user that can execute sensitive functions.")
if(NOT SYSREPO_SUPERUSER_UID MATCHES "^[0-9]+$")
    message(FATAL_ERROR "Invalid superuser UID \"${SYSREPO_SUPERUSER_UID}\"!")
endif()
set(NACM_RECOVERY_USER "root" CACHE STRING "NACM recovery session user that has unrestricted access.")
set(NACM_SRMON_DATA_PERM "600" CACHE STRING "NACM modules ietf-netconf-acm and sysrepo-monitoring default data permissions.")

# sr_cond implementation
if(NOT SR_COND_IMPL)
    check_include_file("linux/futex.h" HAS_FUTEX)
    if(HAS_FUTEX)
        set(SR_COND_IMPL "sr_cond_futex")
    else()
        set(SR_COND_IMPL "sr_cond_pthread")
    endif()
endif()
message(STATUS "Conditional variable implementation: ${SR_COND_IMPL}")

# paths
if(NOT SHM_DIR)
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
        set(SHM_DIR "/tmp/shm")
    else()
        set(SHM_DIR "/dev/shm")
    endif()
endif()
set(SHM_DIR "${SHM_DIR}" CACHE PATH "SHM file directory, contains all shared memory files.")

if(NOT REPO_PATH)
    if("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
        set(REPO_PATH "${CMAKE_BINARY_DIR}/repository")
    else()
        set(REPO_PATH "/etc/sysrepo")
    endif()
endif()
set(REPO_PATH "${REPO_PATH}" CACHE PATH "Repository path, contains configuration schema and data files.")
message(STATUS "Sysrepo repository: ${REPO_PATH}")

set(STARTUP_DATA_PATH "${STARTUP_DATA_PATH}" CACHE PATH "Startup data path, contains startup datastore module files.")
if(STARTUP_DATA_PATH)
    message(STATUS "Startup data path:  ${STARTUP_DATA_PATH}")
else()
    message(STATUS "Startup data path:  ${REPO_PATH}/data")
endif()

set(FACTORY_DEFAULT_DATA_PATH "${FACTORY_DEFAULT_DATA_PATH}" CACHE PATH "Factory-default data path, contains factory-default datastore module files.")
if(FACTORY_DEFAULT_DATA_PATH)
    message(STATUS "Factory-default data path: ${FACTORY_DEFAULT_DATA_PATH}")
else()
    message(STATUS "Factory-default data path: ${REPO_PATH}/data")
endif()

set(NOTIFICATION_PATH "${NOTIFICATION_PATH}" CACHE PATH "Notification path, contains stored notifications.")
if(NOTIFICATION_PATH)
    message(STATUS "Notification path:  ${NOTIFICATION_PATH}")
else()
    message(STATUS "Notification path:  ${REPO_PATH}/data/notif")
endif()

set(YANG_MODULE_PATH "${YANG_MODULE_PATH}" CACHE PATH "YANG module path, contains all used YANG module files.")
if(YANG_MODULE_PATH)
    message(STATUS "YANG module path:   ${YANG_MODULE_PATH}")
else()
    message(STATUS "YANG module path:   ${REPO_PATH}/yang")
endif()

if(NOT SR_PLUGINS_PATH)
    set(SR_PLUGINS_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/sysrepo/plugins/" CACHE PATH
        "Sysrepo datastore and/or notification plugins path.")
endif()
message(STATUS "SR plugins path:    ${SR_PLUGINS_PATH}")

if(NOT SRPD_PLUGINS_PATH)
    set(SRPD_PLUGINS_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/sysrepo-plugind/plugins/" CACHE PATH
        "Sysrepo plugin daemon plugins path.")
endif()
message(STATUS "SRPD plugins path:  ${SRPD_PLUGINS_PATH}")

#
# sources
#
set(LIB_SRC
    src/sysrepo.c
    src/common.c
    src/subscr.c
    src/log.c
    src/replay.c
    src/modinfo.c
    src/edit_diff.c
    src/lyd_mods.c
    src/context_change.c
    src/shm_main.c
    src/shm_ext.c
    src/shm_mod.c
    src/shm_sub.c
    src/sr_cond/${SR_COND_IMPL}.c
    src/plugins/ds_json.c
    src/plugins/ntf_json.c
    src/plugins/common_json.c
    src/utils/values.c
    src/utils/xpath.c
    src/utils/error_format.c
    src/utils/nacm.c)

set (SYSREPOCTL_SRC
    src/executables/sysrepoctl.c)

set (SYSREPOCFG_SRC
    src/executables/sysrepocfg.c)

set (SYSREPOPLUGIND_SRC
    src/executables/srpd_rotation.c
    src/executables/srpd_oper_poll_diff.c
    src/executables/srpd_common.c
    src/executables/sysrepo-plugind.c)

# public headers to check API/ABI on
set(LIB_HEADERS
    src/sysrepo.h
    src/sysrepo_types.h
    src/utils/values.h
    src/utils/xpath.h
    src/utils/error_format.h
    src/utils/netconf_acm.h)

# files to generate doxygen from
set(DOXY_FILES
    doc/
    ${LIB_HEADERS}
    src/plugins_datastore.h
    src/plugins_notification.h
    ${PROJECT_BINARY_DIR}/version.h)

# project (doxygen) logo
set(PROJECT_LOGO
    doc/logo.png)

# source files to be covered by the 'format' target
set(FORMAT_SOURCES
    compat/*.c
    compat/*.h*
    examples/*.c
    examples/plugin/*.c
    src/*.c
    src/*.h
    src/executables/*.c
    src/executables/*.h*
    src/utils/*)

#
# checks
#
if(ENABLE_VALGRIND_TESTS)
    if(NOT ENABLE_TESTS)
        message(WARNING "Tests are disabled! Disabling memory leak tests.")
        set(ENABLE_VALGRIND_TESTS OFF)
    else()
        find_program(VALGRIND_FOUND valgrind)
        if(NOT VALGRIND_FOUND)
            message(WARNING "valgrind executable not found! Disabling memory leaks tests.")
            set(ENABLE_VALGRIND_TESTS OFF)
        endif()
    endif()
endif()

if(ENABLE_TESTS)
    find_package(CMocka 1.0.1)
    if(NOT CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka")
        set(ENABLE_TESTS OFF)
    endif()
endif()

if(ENABLE_PERF_TESTS)
    find_path(VALGRIND_INCLUDE_DIR
        NAMES
        valgrind/callgrind.h
        PATHS
        /usr/include
        /usr/local/include
        /opt/local/include
        /sw/include
        ${CMAKE_INCLUDE_PATH}
        ${CMAKE_INSTALL_PREFIX}/include)
    if(VALGRIND_INCLUDE_DIR)
        set(SR_HAVE_CALLGRIND 1)
    else()
        message(STATUS "Disabling callgrind macros in performance tests because of missing valgrind headers")
    endif()
endif()

if(ENABLE_COVERAGE)
    gen_coverage_enable(${ENABLE_TESTS})
endif()

if ("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    source_format_enable(0.77)
endif()

if("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    gen_doc("${DOXY_FILES}" ${SYSREPO_VERSION} ${SYSREPO_DESC} ${PROJECT_LOGO})
    return()
endif()

#
# targets
#

# use compat
use_compat()

# sysrepo
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
add_library(srobj OBJECT ${LIB_SRC} ${compatsrc})
set_target_properties(srobj PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
add_library(sysrepo SHARED $<TARGET_OBJECTS:srobj>)
set_target_properties(sysrepo PROPERTIES VERSION ${SYSREPO_SOVERSION_FULL} SOVERSION ${SYSREPO_SOVERSION})

# sysrepoctl tool
add_executable(sysrepoctl ${SYSREPOCTL_SRC} ${compatsrc})
target_link_libraries(sysrepoctl sysrepo)

# sysrepocfg tool
add_executable(sysrepocfg ${SYSREPOCFG_SRC} ${compatsrc})
target_link_libraries(sysrepocfg sysrepo)

# sysrepo-plugind daemon
add_executable(sysrepo-plugind ${SYSREPOPLUGIND_SRC} ${compatsrc})
target_link_libraries(sysrepo-plugind sysrepo)

# include repository files with highest priority
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories(${PROJECT_BINARY_DIR})

# dependencies
# libatomic
check_library_exists(atomic __atomic_fetch_add_4 "" LIBATOMIC)
if(LIBATOMIC)
    target_link_libraries(sysrepo atomic)
endif()

# librt (shm_open, shm_unlink, not required on QNX or OSX)
find_library(LIBRT_LIBRARIES rt)
if(LIBRT_LIBRARIES)
    target_link_libraries(sysrepo ${LIBRT_LIBRARIES})
endif()

# libdl
target_link_libraries(sysrepo ${CMAKE_DL_LIBS})

# libyang, check version
find_package(LibYANG ${LIBYANG_DEP_SOVERSION} REQUIRED)
target_link_libraries(sysrepo ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# pkg-config
find_package(PkgConfig)
if(NOT PKG_CONFIG_FOUND AND NOT SYSTEMD_UNIT_DIR)
    set(SYSTEMD_UNIT_DIR "/usr/lib/systemd/system")
endif()

# libsystemd
find_package(LibSystemd)
if(LIBSYSTEMD_FOUND)
    set(SR_HAVE_SYSTEMD 1)
    target_link_libraries(sysrepo-plugind ${LIBSYSTEMD_LIBRARIES})
    include_directories(${LIBSYSTEMD_INCLUDE_DIRS})
    message(STATUS "systemd system service unit path: ${SYSTEMD_UNIT_DIR}")
else()
    message(WARNING "Disabling sysrepo-plugind systemd support because libsystemd was not found.")
endif()

# pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(sysrepo ${CMAKE_THREAD_LIBS_INIT})
set(CMAKE_REQUIRED_LIBRARIES pthread)

# required functions
set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE;-D_DEFAULT_SOURCE")
check_symbol_exists(eaccess "unistd.h" SR_HAVE_EACCESS)
if(NOT SR_HAVE_EACCESS)
    message(WARNING "Function eaccess() is not supported, using access() instead which may "
        "change results of access control checks!")
endif()
check_symbol_exists(mkstemps "stdlib.h" SR_HAVE_MKSTEMPS)
unset(CMAKE_REQUIRED_DEFINITIONS)

# tar
find_program(TAR_BINARY "tar")
if(NOT TAR_BINARY)
    message(FATAL_ERROR "tar binary was not found.")
endif()

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/plugins/common_json.h.in" "${PROJECT_BINARY_DIR}/common_json.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/sysrepo.pc.in" "${PROJECT_BINARY_DIR}/sysrepo.pc" @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/executables/bin_common.h.in" "${PROJECT_BINARY_DIR}/bin_common.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/executables/sysrepo-plugind.service.in" "${PROJECT_BINARY_DIR}/sysrepo-plugind.service" @ONLY)

# installation
install(DIRECTORY "${PROJECT_SOURCE_DIR}/modules/" DESTINATION ${YANG_MODULE_DIR} FILES_MATCHING PATTERN "*.yang")

install(TARGETS sysrepo DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/sysrepo.h ${PROJECT_SOURCE_DIR}/src/sysrepo_types.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/plugins_datastore.h ${PROJECT_BINARY_DIR}/version.h
            ${PROJECT_SOURCE_DIR}/src/utils/values.h ${PROJECT_SOURCE_DIR}/src/utils/xpath.h
            ${PROJECT_SOURCE_DIR}/src/utils/error_format.h ${PROJECT_SOURCE_DIR}/src/utils/netconf_acm.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo)
install(FILES ${PROJECT_BINARY_DIR}/sysrepo.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(TARGETS sysrepoctl sysrepocfg sysrepo-plugind DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/executables/sysrepoctl.1 ${PROJECT_SOURCE_DIR}/src/executables/sysrepocfg.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES ${PROJECT_SOURCE_DIR}/src/executables/sysrepo-plugind.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
install(DIRECTORY DESTINATION ${SRPD_PLUGINS_PATH})
if(SR_HAVE_SYSTEMD)
    install(FILES ${PROJECT_BINARY_DIR}/sysrepo-plugind.service DESTINATION ${SYSTEMD_UNIT_DIR})
endif()

if(INSTALL_SYSCTL_CONF)
    install(FILES "${PROJECT_SOURCE_DIR}/zz-sysrepo-disable-fs-protected_regular.conf" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/sysctl.d/")
endif()

# tests
if(ENABLE_TESTS OR ENABLE_PERF_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# create coverage target for generating coverage reports
gen_coverage("test_.*" "test_.*_valgrind")

# examples
if(ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()

# generate doxygen documentation
gen_doc("${DOXY_FILES}" ${SYSREPO_VERSION} ${SYSREPO_DESC} ${PROJECT_LOGO})

# generate API/ABI report
if ("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    lib_abi_check(sysrepo "${LIB_HEADERS}" ${SYSREPO_SOVERSION_FULL} 3b247459f7070f1175370ef5eb6972abd225eda4)
endif()

# source files to be covered by the 'format' target and a test with 'format-check' target
source_format(${FORMAT_SOURCES})

# phony target for clearing sysrepo SHM
add_custom_target(shm_clean
    COMMAND rm -rf ${SHM_DIR}/sr_*
    COMMAND rm -rf ${SHM_DIR}/srsub_*
    COMMENT "Removing all volatile SHM files prefixed with \"sr\""
)

# phony target for clearing all sysrepo data
add_custom_target(sr_clean
    COMMAND rm -rf ${REPO_PATH}
    DEPENDS shm_clean
    COMMENT "Removing the whole persistent repository \"${REPO_PATH}\""
)

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
add_custom_target(uninstall_with_repo "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
    COMMAND rm -rf ${REPO_PATH})
