cmake_minimum_required(VERSION 2.8.12...3.28.1)

project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository for all-around configuration management.")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(UseCompat)
include(ABICheck)
include(SourceFormat)
include(GenDoc)
include(GenCoverage)
include(UsePrintedContext)
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
    set(CMAKE_C_FLAGS "-DNDEBUG -g -O2 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBUG")
    set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    set(CMAKE_BUILD_TYPE "ABICheck" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -Og ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    set(CMAKE_BUILD_TYPE "DocOnly" CACHE STRING "Build Type" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(SYSREPO_MAJOR_VERSION 3)
set(SYSREPO_MINOR_VERSION 7)
set(SYSREPO_MICRO_VERSION 11)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(SYSREPO_MAJOR_SOVERSION 7)
set(SYSREPO_MINOR_SOVERSION 34)
set(SYSREPO_MICRO_SOVERSION 6)
set(SYSREPO_SOVERSION_FULL ${SYSREPO_MAJOR_SOVERSION}.${SYSREPO_MINOR_SOVERSION}.${SYSREPO_MICRO_SOVERSION})
set(SYSREPO_SOVERSION ${SYSREPO_MAJOR_SOVERSION})

# Version of libyang library that this sysrepo depends on
set(LIBYANG_DEP_VERSION 3.13.2)
set(LIBYANG_DEP_SOVERSION 3.9.11)
set(LIBYANG_DEP_SOVERSION_MAJOR 3)

# generate only version header, it is needed for docs
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_BINARY_DIR}/include/sysrepo/version.h" ESCAPE_QUOTES @ONLY)

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
option(ENABLE_COMMON_TARGETS "Define common custom target names such as 'doc' or 'uninstall', may cause conflicts when using add_subdirectory() to build this project" ON)
option(ENABLE_DS_MONGO "Enable MongoDB datastore plugin" OFF)
option(ENABLE_DS_REDIS "Enable Redis datastore plugin" OFF)
option(ENABLE_SYSREPOCTL "Build binary tool 'sysrepoctl'" ON)
option(ENABLE_SYSREPOCFG "Build binary tool 'sysrepocfg'" ON)
option(ENABLE_SYSREPO_PLUGIND "Build binary daemon 'sysrepo-plugind'" ON)
option(BUILD_SHARED_LIBS "By default, shared libs are enabled. Turn off for a static build." ON)
option(INSTALL_SYSCTL_CONF "Install sysctl conf file to allow shared access to SHM files." OFF)
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/sysrepo" CACHE STRING "Directory where to copy the YANG modules to.")
set(INTERNAL_MODULE_DATA_PATH "" CACHE STRING "Path to a file with startup and factory-default data of internal modules. Contents of the file are compiled into the library.")
if(INTERNAL_MODULE_DATA_PATH)
    if(NOT EXISTS "${INTERNAL_MODULE_DATA_PATH}")
        message(FATAL_ERROR "File \"${INTERNAL_MODULE_DATA_PATH}\" does not exist.")
    endif()
    string(REGEX MATCH "[.](xml|json)$" EXT ${INTERNAL_MODULE_DATA_PATH})
    if(NOT EXT)
        message(FATAL_ERROR "File \"${INTERNAL_MODULE_DATA_PATH}\" with an unknown extension.")
    endif()

    file(READ "${INTERNAL_MODULE_DATA_PATH}" INTERNAL_MODULE_DATA_RAW)
    string(REPLACE "\n" "\\\n" INTERNAL_MODULE_DATA ${INTERNAL_MODULE_DATA_RAW})

    if(${EXT} STREQUAL ".xml")
        set(INTERNAL_MODULE_DATA_FORMAT LYD_XML)
    else()
        set(INTERNAL_MODULE_DATA_FORMAT LYD_JSON)
    endif()
else()
    # empty data but the code needs a format
    set(INTERNAL_MODULE_DATA_FORMAT LYD_XML)
endif()
set(INTERNAL_MODULE_DISABLED_RUNNING "" CACHE STRING "List of internal sysrepo or libyang modules that will have their 'running' datastores disabled (always mirroring 'startup'), separated by space. Use '*' for all the modules.")

# default datastore plugins
set(DEFAULT_STARTUP_DS_PLG "JSON DS file" CACHE STRING "Default datastore plugin for storing startup data.")
set(DEFAULT_RUNNING_DS_PLG "JSON DS file" CACHE STRING "Default datastore plugin for storing running data.")
set(DEFAULT_CANDIDATE_DS_PLG "JSON DS file" CACHE STRING "Default datastore plugin for storing candidate data.")
set(DEFAULT_OPERATIONAL_DS_PLG "JSON DS file" CACHE STRING "Default datastore plugin for storing operational data.")
set(DEFAULT_FACTORY_DEFAULT_DS_PLG "JSON DS file" CACHE STRING "Default datastore plugin for storing factory default data.")
set(DEFAULT_NOTIFICATION_DS_PLG "JSON notif" CACHE STRING "Default datastore plugin for storing notifications.")

# MongoDB username, password, host and port for the client
set(MONGO_AUTHSOURCE "admin" CACHE STRING "Database name associated with the user's credentials.")
set(MONGO_USERNAME "" CACHE STRING "Username for MongoDB administrator client, all operations are done via this client in case MongoDB plugin is supported. If not provided, no authentication is done.")
set(MONGO_PASSWORD "" CACHE STRING "Password for all MongoDB clients in case MongoDB plugin is supported.")
set(MONGO_HOST "127.0.0.1" CACHE STRING "Host for the MongoDB client to connect to.")
set(MONGO_PORT 27017 CACHE STRING "Port for the MongoDB client to connect to.")
set(MONGO_SOCKET "" CACHE STRING "Unix socket for the MongoDB client to connect to, this overrides MONGO_HOST and MONGO_PORT variables.")

# Redis username, password, host and port for the client
set(REDIS_USERNAME "" CACHE STRING "Username for Redis user, all operations are done via this client in case Redis plugin is supported. If not provided, no authentication is done.")
set(REDIS_PASSWORD "" CACHE STRING "Password for Redis user in case Redis plugin is supported.")
set(REDIS_HOST "127.0.0.1" CACHE STRING "Host for the Redis client to connect to.")
set(REDIS_PORT 6379 CACHE STRING "Port for the Redis client to connect to.")
set(REDIS_SOCKET "" CACHE STRING "Unix socket for the Redis client to connect to, this overrides REDIS_HOST and REDIS_PORT variables.")

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

if(NOT SYSREPOCFG_DEFAULT_LYD_FORMAT)
    set(SYSREPOCFG_DEFAULT_LYD_FORMAT LYD_XML)
endif()
message(STATUS "sysrepocfg default data format: ${SYSREPOCFG_DEFAULT_LYD_FORMAT}")

#
# sources
#
set(LIB_SRC
    src/sysrepo.c
    src/common.c
    src/ly_wrap.c
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
    src/utils/nacm.c
    src/utils/subscribed_notifications.c
    src/utils/sn_common.c
    src/utils/sn_yang_push.c)

set(SYSREPOCTL_SRC
    src/executables/sysrepoctl.c)

set(SYSREPOCFG_SRC
    src/executables/sysrepocfg.c)

set(SYSREPOPLUGIND_SRC
    src/executables/srpd_rotation.c
    src/executables/srpd_oper_poll_diff.c
    src/executables/srpd_common.c
    src/executables/sysrepo-plugind.c)

# public headers to check API/ABI on
set(LIB_MAIN_HEADERS
    src/sysrepo.h
    src/sysrepo_types.h)
set(LIB_UTIL_HEADERS
    src/plugins_datastore.h
    src/plugins_notification.h
    src/utils/values.h
    src/utils/xpath.h
    src/utils/error_format.h
    src/utils/netconf_acm.h
    src/utils/subscribed_notifications.h)

# files to generate doxygen from
set(DOXY_FILES
    doc/
    ${LIB_MAIN_HEADERS}
    ${LIB_UTIL_HEADERS}
    src/plugins_datastore.h
    src/plugins_notification.h
    ${PROJECT_BINARY_DIR}/include/sysrepo/version.h)

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
    src/plugins/*.c
    src/plugins/*.h*
    src/utils/*
    tests/*.c
    tests/*.c)

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

# required functions
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_DEFAULT_SOURCE)

check_symbol_exists(eaccess "unistd.h" SR_HAVE_EACCESS)
if(NOT SR_HAVE_EACCESS)
    message(WARNING "Function eaccess() is not supported, using access() instead which may "
        "change results of access control checks!")
endif()
check_symbol_exists(mkstemps "stdlib.h" SR_HAVE_MKSTEMPS)

list(APPEND CMAKE_REQUIRED_LIBRARIES dl)
check_symbol_exists(dlopen "dlfcn.h" SR_HAVE_DLOPEN)
list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES dl)
if(NOT SR_HAVE_DLOPEN)
    message(WARNING "Function dlopen() is not supported, disabling plugin support and 'sysrepo-plugind'.")
    set(ENABLE_SYSREPO_PLUGIND OFF)
endif()

list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_DEFAULT_SOURCE)

# libmongoc - optional
if(ENABLE_DS_MONGO)
    find_package(mongoc 2.0.2 CONFIG)
    if (NOT TARGET mongoc::shared)
        find_package(mongoc-1.0 1.24.0 CONFIG)
    endif()
    find_program(MONGO_CLI_CMD mongosh)
    if((TARGET mongoc::shared OR TARGET mongo::mongoc_shared) AND MONGO_CLI_CMD)
        # datastore plugin added if libraries exist
        list(APPEND LIB_SRC src/plugins/ds_mongo.c)
        set(SR_ENABLED_DS_PLG_MONGO 1)
        message(STATUS "Datastore plugin ds_mongo supported.")

        # try running a command in MongoDB database (should not be possible) and check authentication
        if(MONGO_SOCKET)
            set(MONGO_TMP_ARGS ${MONGO_CLI_CMD} "mongodb://${MONGO_SOCKET}" "--eval" "use sr_running" "--eval" "db.runCommand({usersInfo: 1})")
        else()
            set(MONGO_TMP_ARGS ${MONGO_CLI_CMD} "--host" "${MONGO_HOST}" "--port" "${MONGO_PORT}" "--eval" "use sr_running" "--eval" "db.runCommand({usersInfo: 1})")
        endif()
        execute_process(COMMAND ${MONGO_TMP_ARGS} RESULT_VARIABLE MONGO_RETURN_CODE ERROR_VARIABLE MONGO_STDERR OUTPUT_QUIET)
        if(${MONGO_RETURN_CODE} EQUAL 0)
            message(WARNING "MongoDB authentication is NOT supported! Data stored by sysrepo in MongoDB will be accessible by anyone.")
        else()
            if("${MONGO_STDERR}" MATCHES "^MongoServerError: .*auth.*")
                message(STATUS "MongoDB authentication is supported!")
            else()
                message(WARNING "MongoDB authentication cannot be checked - a request to MongoDB failed with: ${MONGO_STDERR}")
            endif()
        endif()
    else()
        message(STATUS "Datastore plugin ds_mongo not supported.")
    endif()
else()
    message(STATUS "MongoDB datastore plugin disabled")
endif()

# libhiredis - optional
if(ENABLE_DS_REDIS)
    find_package(LibHiredis 1.1.0)
    find_program(REDIS_CLI_CMD redis-cli)
    if(LIBHIREDIS_FOUND AND REDIS_CLI_CMD)
        # datastore plugin added if libraries exist
        list(APPEND LIB_SRC src/plugins/ds_redis.c)
        set(SR_ENABLED_DS_PLG_REDIS 1)
        message(STATUS "Datastore plugin ds_redis supported.")

        # try running a command in Redis database and check authentication
        if(REDIS_SOCKET)
            set(REDIS_TMP_ARGS ${REDIS_CLI_CMD} "-s" "${REDIS_SOCKET}" "ACL" "WHOAMI")
        else()
            set(REDIS_TMP_ARGS ${REDIS_CLI_CMD} "-h" "${REDIS_HOST}" "-p" "${REDIS_PORT}" "ACL" "WHOAMI")
        endif()
        execute_process(COMMAND ${REDIS_TMP_ARGS} RESULT_VARIABLE REDIS_RETURN_CODE OUTPUT_VARIABLE REDIS_STDOUT ERROR_VARIABLE REDIS_STDERR)
        if (${REDIS_RETURN_CODE} GREATER 0)
            message(WARNING "Redis authentication cannot be checked - a request to Redis failed with: ${REDIS_STDERR}")
        else()
            if("${REDIS_STDOUT}" MATCHES "^NOAUTH.*")
                message(STATUS "Redis authentication is supported!")
            else()
                message(WARNING "Redis authentication is NOT supported! Data stored by sysrepo in Redis will be accessible by anyone.")
            endif()
        endif()
    else()
        message(STATUS "Datastore plugin ds_redis not supported.")
    endif()
else()
    message(STATUS "Redis datastore plugin disabled")
endif()

# common database utility functions - optional
if(SR_ENABLED_DS_PLG_MONGO OR SR_ENABLED_DS_PLG_REDIS)
    # common utilities added if at least one library exists and the plugin is enabled
    list(APPEND LIB_SRC src/plugins/common_db.c)
endif()

# sysrepo
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
add_library(srobj OBJECT ${LIB_SRC} ${compatsrc})
set_target_properties(srobj PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
add_library(sysrepo $<TARGET_OBJECTS:srobj>)
set_target_properties(sysrepo PROPERTIES VERSION ${SYSREPO_SOVERSION_FULL} SOVERSION ${SYSREPO_SOVERSION})
if(SR_ENABLED_DS_PLG_MONGO)
    # cannot separately include and link mongoc library, thus add include to srobj and link with sysrepo
    # to add include directories
    if (TARGET mongoc::shared)
        get_target_property(BSON_INTERFACE_INCLUDE_DIR bson::shared INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(MONGOC_INTERFACE_INCLUDE_DIR mongoc::shared INTERFACE_INCLUDE_DIRECTORIES)
    elseif(TARGET mongo::mongoc_shared)
        get_target_property(BSON_INTERFACE_INCLUDE_DIR mongo::bson_shared INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(MONGOC_INTERFACE_INCLUDE_DIR mongo::mongoc_shared INTERFACE_INCLUDE_DIRECTORIES)
    endif()
    set_property(TARGET srobj APPEND PROPERTY INCLUDE_DIRECTORIES ${BSON_INTERFACE_INCLUDE_DIR} ${MONGOC_INTERFACE_INCLUDE_DIR})
    if (TARGET mongoc::shared)
        target_link_libraries(sysrepo mongoc::shared)
    elseif(TARGET mongo::mongoc_shared)
        target_link_libraries(sysrepo mongo::mongoc_shared)
    endif()
endif()
if (SR_ENABLED_DS_PLG_REDIS)
    # to add include directories
    target_link_libraries(sysrepo ${LIBHIREDIS_LIBRARIES})
    include_directories(${LIBHIREDIS_INCLUDE_DIRS})
endif()

if(ENABLE_SYSREPOCTL)
    # sysrepoctl tool
    add_executable(sysrepoctl ${SYSREPOCTL_SRC} ${compatsrc})
    target_link_libraries(sysrepoctl sysrepo)
endif()

if(ENABLE_SYSREPOCFG)
    # sysrepocfg tool
    add_executable(sysrepocfg ${SYSREPOCFG_SRC} ${compatsrc})
    target_link_libraries(sysrepocfg sysrepo)
endif()

if(ENABLE_SYSREPO_PLUGIND)
    # sysrepo-plugind daemon
    add_executable(sysrepo-plugind ${SYSREPOPLUGIND_SRC} ${compatsrc})
    target_link_libraries(sysrepo-plugind sysrepo)
endif()

# include repository files with highest priority
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/src/plugins")
include_directories(${PROJECT_BINARY_DIR})

# dependencies
# libatomic
check_library_exists(atomic __atomic_fetch_add_4 "" LIBATOMIC)
if(LIBATOMIC)
    target_link_libraries(sysrepo atomic)
else()
    # we may need to link it explicitly
    list(APPEND CMAKE_REQUIRED_LIBRARIES atomic)
    check_library_exists(atomic __atomic_fetch_add_4 "" LIBATOMIC)
    list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES atomic)
    if(LIBATOMIC)
        target_link_libraries(sysrepo atomic)
    endif()
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
    if(ENABLE_SYSREPO_PLUGIND)
        target_link_libraries(sysrepo-plugind ${LIBSYSTEMD_LIBRARIES})
    endif()
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

# tar
find_program(TAR_BINARY "tar")
if(NOT TAR_BINARY)
    message(FATAL_ERROR "tar binary was not found.")
endif()

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/config.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/sysrepo.pc.in" "${PROJECT_BINARY_DIR}/sysrepo.pc" @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/executables/bin_common.h.in" "${PROJECT_BINARY_DIR}/bin_common.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/executables/sysrepo-plugind.service.in" "${PROJECT_BINARY_DIR}/sysrepo-plugind.service" @ONLY)

# copy public headers
file(COPY ${LIB_MAIN_HEADERS} DESTINATION "${PROJECT_BINARY_DIR}/include")
file(COPY ${LIB_UTIL_HEADERS} DESTINATION "${PROJECT_BINARY_DIR}/include/sysrepo")

# installation
file(GLOB yangs "${PROJECT_SOURCE_DIR}/modules/*.yang")
install(FILES ${yangs} DESTINATION ${YANG_MODULE_DIR})
file(GLOB sn_yangs "${PROJECT_SOURCE_DIR}/modules/subscribed_notifications/*.yang")
install(FILES ${sn_yangs} DESTINATION ${YANG_MODULE_DIR})

install(TARGETS sysrepo DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/sysrepo.h ${PROJECT_BINARY_DIR}/include/sysrepo_types.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY ${PROJECT_BINARY_DIR}/include/sysrepo DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_BINARY_DIR}/sysrepo.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(DIRECTORY DESTINATION ${REPO_PATH}
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE WORLD_READ WORLD_WRITE WORLD_EXECUTE)

if(ENABLE_SYSREPOCTL)
    install(TARGETS sysrepoctl DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${PROJECT_SOURCE_DIR}/src/executables/sysrepoctl.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()
if(ENABLE_SYSREPOCFG)
    install(TARGETS sysrepocfg DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${PROJECT_SOURCE_DIR}/src/executables/sysrepocfg.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()
if(ENABLE_SYSREPO_PLUGIND)
    install(TARGETS sysrepo-plugind DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${PROJECT_SOURCE_DIR}/src/executables/sysrepo-plugind.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
    install(DIRECTORY DESTINATION ${SRPD_PLUGINS_PATH})
endif()
if(SR_HAVE_DLOPEN)
    install(DIRECTORY DESTINATION ${SR_PLUGINS_PATH})
endif()
if(SR_HAVE_SYSTEMD AND ENABLE_SYSREPO_PLUGIND)
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
if(ENABLE_COMMON_TARGETS)
    gen_doc("${DOXY_FILES}" ${SYSREPO_VERSION} ${SYSREPO_DESC} ${PROJECT_LOGO})
endif()

# generate API/ABI report
if("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    lib_abi_check(sysrepo "${LIB_MAIN_HEADERS};${LIB_UTIL_HEADERS}" ${SYSREPO_SOVERSION_FULL} 5accdd96d9d59ac60e975b0c8e8cc9e83911451e)
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

# flush all sysrepo related data from mongo
if(SR_ENABLED_DS_PLG_MONGO)
    if (MONGO_SOCKET)
        set(MONGO_TMP_ARGS ${MONGO_CLI_CMD} "mongodb://${MONGO_SOCKET}")
    else()
        set(MONGO_TMP_ARGS ${MONGO_CLI_CMD} "--host" "${MONGO_HOST}" "--port" "${MONGO_PORT}")
    endif()
    list(APPEND MONGO_TMP_ARGS "--eval" "use sr_startup" "--eval" "\"db.dropDatabase()\""
                            "--eval" "use sr_running" "--eval" "\"db.dropDatabase()\""
                            "--eval" "use sr_candidate" "--eval" "\"db.dropDatabase()\""
                            "--eval" "use sr_operational" "--eval" "\"db.dropDatabase()\""
                            "--eval" "use sr_factory-default" "--eval" "\"db.dropDatabase()\""
                            "1>" "/dev/null")
    add_custom_target(sr_mongo_clean COMMAND ${MONGO_CLI_CMD})
    add_dependencies(sr_clean sr_mongo_clean)
endif()

# flush all sysrepo related data from redis
if(SR_ENABLED_DS_PLG_REDIS)
    set(REDIS_SCRIPT "local reply = redis.pcall('FT._LIST'); if reply['err'] ~= nil then return reply['err']; end local n = table.getn(reply); local reply2; local index; for i=1,n do index = ''; for k,v in pairs(reply[i]) do index = index..v; end if string.sub(index,1,3) == 'sr:' then reply2 = redis.pcall('FT.DROPINDEX', index, 'DD'); if reply2['err'] ~= nil then return reply2['err']; end end end reply = redis.pcall('SCAN', '0', 'MATCH', 'sr:*', 'COUNT', '50000'); if reply['err'] ~= nil then return reply['err']; end while 1 do n = table.getn(reply[2]); for i=1,n do reply2 = redis.pcall('DEL', reply[2][i]); if reply2 ~= 1 then return reply2['err']; end end if reply[1] == '0' then break end reply = redis.pcall('SCAN', reply[1], 'MATCH', 'sr:*', 'COUNT', '50000'); if reply['err'] ~= nil then return reply['err']; end end return 0;")
    if(REDIS_SOCKET)
        set(REDIS_TMP_ARGS ${REDIS_CLI_CMD} "-s" "${REDIS_SOCKET}" "EVAL" ${REDIS_SCRIPT} "0" "1>" "/dev/null")
    else()
        set(REDIS_TMP_ARGS ${REDIS_CLI_CMD} "-h" "${REDIS_HOST}" "-p" "${REDIS_PORT}" "EVAL" ${REDIS_SCRIPT} "0" "1>" "/dev/null")
    endif()
    add_custom_target(sr_redis_clean COMMAND ${REDIS_TMP_ARGS} VERBATIM)
    add_dependencies(sr_clean sr_redis_clean)
endif()

# uninstall
if(ENABLE_COMMON_TARGETS)
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
endif()
add_custom_target(uninstall_with_repo "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
    COMMAND rm -rf ${REPO_PATH})
