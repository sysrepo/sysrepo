cmake_minimum_required(VERSION 2.8.12)
project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository")
include(GNUInstallDirs)

# setup version
set(SYSREPO_MAJOR_VERSION 0)
set(SYSREPO_MINOR_VERSION 7)
set(SYSREPO_MICRO_VERSION 7)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})
set(SYSREPO_SOVERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION})

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# setup bindings
set(GEN_LANGUAGE_BINDINGS 1 CACHE BOOL "Enable language bindings generation.")
set(GEN_PYTHON_BINDINGS 1 CACHE BOOL "Enable python bindings.")
set(GEN_LUA_BINDINGS 1 CACHE BOOL "Enable Lua bindings.")
set(GEN_CPP_BINDINGS 1 CACHE BOOL "Enable C++ bindings.")
set(BUILD_CPP_EXAMPLES 1 CACHE BOOL "Build C++ examples.")
set(GEN_JAVA_BINDINGS 0 CACHE BOOL "Enable Java bindings.")
set(GEN_PYTHON_VERSION "2" CACHE STRING "Python version")
set(GEN_LUA_VERSION "5.1" CACHE STRING "Lua version")
set(GEN_PYTHON2_TESTS 1 CACHE BOOL "Enable Python2 tests.")

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11 -Wno-language-extension-token")
if(CMAKE_COMPILER_IS_GNUCC)
    # disable strict aliasing in GCC, since it produces false alarams in libev
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing")
endif()
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

set(CALL_TARGET_BINS_DIRECTLY ON CACHE BOOL "Enable calling sysrepoctl/sysrepocfg directly at install time")
set(INDIRECT_YANG_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/" CACHE PATH "Where to store YANG files when not executing sysrepoctl directly")
set(CALL_SYSREPOCTL_BIN "${CMAKE_BINARY_DIR}/src/sysrepoctl" CACHE PATH "Path to the sysrepoctl binary to be used at install time")
set(CALL_SYSREPOCFG_BIN "${CMAKE_BINARY_DIR}/src/sysrepocfg" CACHE PATH "Path to the sysrepocfg binary to be used at install time")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")

if(NOT DEFINED IS_DEVELOPER_CONFIGURATION)
    if(CMAKE_BUILD_TYPE_LOWER MATCHES "debug" AND NOT CMAKE_BUILD_TYPE_LOWER MATCHES "^rel")
        set(IS_DEVELOPER_CONFIGURATION true)
    else()
        set(IS_DEVELOPER_CONFIGURATION false)
    endif()
endif()

# set build-type specific settings
if(${IS_DEVELOPER_CONFIGURATION})
    MESSAGE(STATUS "Preparing developer's build of sysrepo v. ${SYSREPO_VERSION}")
    set(DAEMON_PID_FILE "/tmp/sysrepod.pid" CACHE PATH "Sysrepo daemon PID file.")
    set(DAEMON_SOCKET "/tmp/sysrepod.sock" CACHE PATH "Sysrepo deamon server socket path.")
    set(PLUGIN_DAEMON_PID_FILE "/tmp/sysrepo-plugind.pid" CACHE PATH "Sysrepo plugin daemon PID file.")
    set(SUBSCRIPTIONS_SOCKET_DIR "/tmp/sysrepo-subscriptions" CACHE PATH "Sysrepo subscriptions socket directory.")
else()
    MESSAGE(STATUS "Preparing systemwide build of sysrepo v. ${SYSREPO_VERSION}")
    set(DAEMON_PID_FILE "/var/run/sysrepod.pid" CACHE PATH "Sysrepo daemon PID file.")
    set(DAEMON_SOCKET "/var/run/sysrepod.sock" CACHE PATH "Sysrepo deamon server socket path.")
    set(PLUGIN_DAEMON_PID_FILE "/var/run/sysrepo-plugind.pid" CACHE PATH "Sysrepo plugin daemon PID file.")
    set(SUBSCRIPTIONS_SOCKET_DIR "/var/run/sysrepo-subscriptions" CACHE PATH "Sysrepo subscriptions socket directory.")
endif()

# location of system repository
if(${IS_DEVELOPER_CONFIGURATION})
    set(REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository" CACHE PATH "System repository location, contains configuration schema and data files.")
else()
    set(REPOSITORY_LOC "/etc/sysrepo" CACHE PATH "System repository location, contains configuration schema and data files.")
endif()
set(SCHEMA_SEARCH_DIR "${REPOSITORY_LOC}/yang/")
set(DATA_SEARCH_DIR "${REPOSITORY_LOC}/data/")
set(INTERNAL_SCHEMA_SEARCH_DIR "${REPOSITORY_LOC}/yang/internal/")
set(INTERNAL_DATA_SEARCH_DIR "${REPOSITORY_LOC}/data/internal/")
set(NOTIF_DATA_SEARCH_DIR "${REPOSITORY_LOC}/data/notifications/")
MESSAGE(STATUS "sysrepo repository location: ${REPOSITORY_LOC}")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/inc")

# find required libraries
find_package(EV REQUIRED)
include_directories(${EV_INCLUDE_DIR})

find_package(YANG REQUIRED)
include_directories(${YANG_INCLUDE_DIR})

find_package(Protobuf-c REQUIRED)
include_directories(${PROTOBUF-C_INCLUDE_DIR})

# find libavl and/or libredblack
find_package(AVL)
find_package(RedBlack)
if((NOT AVL_FOUND) AND (NOT REDBLACK_FOUND))
    MESSAGE(WARNING "libavl or libredblack must be installed.")
endif()

if(NOT DEFINED USE_AVL_LIB)
    # no preference configured, try to find libavl and then libredblack
    if(AVL_FOUND)
        SET(USE_AVL_LIB 1 CACHE BOOL "Use libavl (1) or libredblack (0) for binary tree manipulations.")
    else(AVL_FOUND)
        if(REDBLACK_FOUND)
            SET(USE_AVL_LIB 0 CACHE BOOL "Use libavl (1) or libredblack (0) for binary tree manipulations.")
        endif(REDBLACK_FOUND)
    endif(AVL_FOUND)
endif(NOT DEFINED USE_AVL_LIB)
if(USE_AVL_LIB)
    if(AVL_FOUND)
        MESSAGE(STATUS "libavl will be used for binary tree manipulations.")
        include_directories(${AVL_INCLUDE_DIR})
    else(AVL_FOUND)
         MESSAGE(WARNING "libavl cannot be found.")
    endif(AVL_FOUND)
else(USE_AVL_LIB)
    if(REDBLACK_FOUND)
        MESSAGE(STATUS "libredblack will be used for binary tree manipulations.")
        include_directories(${REDBLACK_INCLUDE_DIR})
    else(REDBLACK_FOUND)
         MESSAGE(WARNING "libredblack cannot be found.")
    endif(REDBLACK_FOUND)
endif(USE_AVL_LIB)

# check for non-portable functions and headers
set(CMAKE_REQUIRED_LIBRARIES pthread)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckStructHasMember)
CHECK_FUNCTION_EXISTS(pthread_rwlockattr_setkind_np HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
CHECK_FUNCTION_EXISTS(getpeereid HAVE_GETPEEREID)
CHECK_FUNCTION_EXISTS(getpeerucred HAVE_GETPEERUCRED)
CHECK_INCLUDE_FILES(ucred.h HAVE_UCRED_H)
CHECK_FUNCTION_EXISTS(pthread_mutex_timedlock HAVE_TIMED_LOCK)
CHECK_FUNCTION_EXISTS(setfsuid HAVE_SETFSUID)
CHECK_FUNCTION_EXISTS(fsetxattr HAVE_FSETXATTR)
CHECK_FUNCTION_EXISTS(mkstemps HAVE_MKSTEMPS)
if(HAVE_MKSTEMPS)
    set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -DHAVE_MKSTEMPS")
endif(HAVE_MKSTEMPS)
CHECK_STRUCT_HAS_MEMBER("struct stat" st_mtim "sys/stat.h" HAVE_STAT_ST_MTIM)

# user options
set(ENABLE_NACM 0 CACHE BOOL
    "Enable NETCONF Access Control Model (RFC 6536).")

set(NACM_RECOVERY_UID 0 CACHE INTEGER
    "UID to be used to identify NACM recovery session, default value is 0.")

set(ENABLE_NOTIF_STORE 1 CACHE BOOL
    "Enable event notifications store & notifications replay.")

set(USE_SR_MEM_MGMT 1 CACHE BOOL
    "Use Sysrepo's own memory management (better overall performance but more difficult to track memory bugs).")

set(LOG_THREAD_ID 0 CACHE BOOL
    "If enabled, sysrepo logger will append thread ID (as well as function name) to each printed message.")

set(ENABLE_CONFIG_CHANGE_NOTIF 1 CACHE BOOL
    "Generate config-change notifications (RFC 6470).")

set(STORE_CONFIG_CHANGE_NOTIF 1 CACHE BOOL
    "Save config-change notifications (RFC 6470) in the notification store (slows down the commit process).")

set(FILE_FORMAT_EXT "lyb" CACHE STRING
    "Datastore file format extension used. Can be json, xml, or lyb.")
if (FILE_FORMAT_EXT STREQUAL "json")
    set(FILE_FORMAT_LY "LYD_JSON")
elseif (FILE_FORMAT_EXT STREQUAL "xml")
    set(FILE_FORMAT_LY "LYD_XML")
elseif (FILE_FORMAT_EXT STREQUAL "lyb")
    set(FILE_FORMAT_LY "LYD_LYB")
else()
    message(FATAL_ERROR "Unknown file format \"${FILE_FORMAT_EXT}\", must be json, xml, or lyb.")
endif()

# timeouts
set(REQUEST_TIMEOUT 15 CACHE INTEGER
    "Timeout (in seconds) for Sysrepo API requests. Set to 0 for no timeout.")

set(COMMIT_VERIFY_TIMEOUT 10 CACHE INTEGER
    "Timeout (in seconds) that a commit request can wait for answer from commit verifiers and change notification subscribers.")

set(OPER_DATA_PROVIDE_TIMEOUT 2 CACHE INTEGER
    "Timeout (in seconds) that a request can wait for operational data from data providers.")

set(NOTIF_AGE_TIMEOUT 60 CACHE INTEGER
    "Timeout (in minutes) after which stored notifications will be aged out and erased from notification store.")

set(NOTIF_TIME_WINDOW 10 CACHE INTEGER
    "Time window (in minutes) for notifications to be grouped into one data file (larger window produces larger data files).")

set(GET_ITEMS_FETCH_LIMIT 100 CACHE INTEGER
    "Number of items being fetched in one message from Sysrepo Engine when processing sr_get_items_iter calls. Increasing this can improve efficiency when working with large datastores at the cost of higher memory usage peaks.")

set(GET_SUBTREE_CHUNK_CHILD_LIMIT 20 CACHE INTEGER
    "Maximum number of children nodes (of any parent node) being fetched in one message from Sysrepo Engine when processing sr_get_subtree(s)_*_chunk(s). Increasing this can improve efficiency when working with large datastores at the cost of higher memory usage peaks.")

# add subdirectories
add_subdirectory(src)

# execute command at the install time
macro(EXEC_AT_INSTALL_TIME CMD)
    install(CODE "message(STATUS \"Exec: ${CMD}\")
        execute_process(COMMAND bash \"-c\" \"${CMD}\" OUTPUT_QUIET RESULT_VARIABLE ret)
        if (NOT \${ret} EQUAL 0)
          message(FATAL_ERROR \"Error: \${ret}\")
        endif()"
        )
endmacro(EXEC_AT_INSTALL_TIME)

set(SH_INSTALL_YANG_CMDS "#!/bin/bash\n\nset -eux -o pipefail\nshopt -s failglob\n\nSYSREPOCTL=sysrepoctl\n\n")
macro(INSTALL_YANG MODULE_NAME REVISION PERMISSIONS)
    if(CALL_TARGET_BINS_DIRECTLY)
        EXEC_AT_INSTALL_TIME("${CALL_SYSREPOCTL_BIN} --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}${REVISION}.yang --permissions=${PERMISSIONS}")
    else()
        set(SH_INSTALL_YANG_CMDS "${SH_INSTALL_YANG_CMDS}\\\${SYSREPOCTL} --install --yang=${INDIRECT_YANG_INSTALL_DIR}/${MODULE_NAME}${REVISION}.yang --permissions=${PERMISSIONS}\n")
    endif()
endmacro(INSTALL_YANG)

# Examples
SET(BUILD_EXAMPLES 1 CACHE BOOL "Build examples and install example YANG models.")
if(BUILD_EXAMPLES)
    MESSAGE(STATUS "Example code and YANG models will be built and installed.")
    add_subdirectory(examples)
endif()

# Testing
SET(ENABLE_TESTS 1 CACHE BOOL "Enable unit tests.")
if(ENABLE_TESTS)
    find_package(CMOCKA)
    if(CMOCKA_FOUND)
        MESSAGE(STATUS "CMocka found, tests are enabled.")
        enable_testing()
        add_subdirectory(tests)
    else(CMOCKA_FOUND)
        MESSAGE(WARNING "CMocka not found, tests are disabled.")
        SET(ENABLE_TESTS false)
    endif(CMOCKA_FOUND)
endif(ENABLE_TESTS)

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    find_program(DOT_PATH dot PATH_SUFFIXES graphviz2.38/bin graphviz/bin)
    if(DOT_PATH)
        set(HAVE_DOT "YES")
    else()
        set(HAVE_DOT "NO")
        message(AUTHOR_WARNING "Doxygen: to generate UML diagrams please install graphviz")
    endif()
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif(DOXYGEN_FOUND)
if(NOT MAN_INSTALL_DIR)
    set(MAN_INSTALL_DIR share/man)
endif()

# install repository directories
install (DIRECTORY DESTINATION ${REPOSITORY_LOC} DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
install (DIRECTORY DESTINATION ${SCHEMA_SEARCH_DIR} DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
install (DIRECTORY DESTINATION ${DATA_SEARCH_DIR} DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
install (DIRECTORY DESTINATION ${INTERNAL_DATA_SEARCH_DIR} DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

# install subscriptions socket directory
install (DIRECTORY DESTINATION ${SUBSCRIPTIONS_SOCKET_DIR} DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_WRITE GROUP_EXECUTE
    WORLD_READ WORLD_WRITE WORLD_EXECUTE)

# install plugins directory
install(DIRECTORY DESTINATION ${PLUGINS_DIR})

# install internal YANGs
set(INTERNAL_YANGS
    ${PROJECT_SOURCE_DIR}/yang/sysrepo-persistent-data.yang
    ${PROJECT_SOURCE_DIR}/yang/sysrepo-module-dependencies.yang
    ${PROJECT_SOURCE_DIR}/yang/sysrepo-notification-store.yang
)
install (FILES ${INTERNAL_YANGS} DESTINATION ${INTERNAL_SCHEMA_SEARCH_DIR})

# install NACM YANG module
if(ENABLE_NACM)
    INSTALL_YANG("ietf-netconf-acm" "@2018-02-14" "644")
endif(ENABLE_NACM)

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("libsysrepo.pc.in" "libsysrepo.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libsysrepo.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()

# install doc (man)
install(FILES ${PROJECT_SOURCE_DIR}/doc/sysrepoctl.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES ${PROJECT_SOURCE_DIR}/doc/sysrepocfg.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

if(WITH_SYSTEMD)
    # systemd units
    add_custom_target(systemd-units SOURCES
        ${PROJECT_SOURCE_DIR}/deploy/systemd/sysrepod.service
        ${PROJECT_SOURCE_DIR}/deploy/systemd/sysrepo-plugind.service
    )
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/deploy/systemd/ DESTINATION "/lib/systemd/system"
        FILES_MATCHING PATTERN "*.service")
endif()

INSTALL_YANG("ietf-netconf-notifications" "" "666")
INSTALL_YANG("nc-notifications" "" "666")
INSTALL_YANG("notifications" "" "666")

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
add_custom_target(uninstall_with_repo "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
    COMMAND rm -rf ${REPOSITORY_LOC})

if(GEN_LANGUAGE_BINDINGS)
    add_subdirectory(swig)
endif()

if(NOT CALL_TARGET_BINS_DIRECTLY)
    install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/yang/"
            DESTINATION "${INDIRECT_YANG_INSTALL_DIR}"
            FILES_MATCHING PATTERN "*.yang")
    set(install_yang_file_name "${CMAKE_CURRENT_BINARY_DIR}/install-yang.sh")
    install(CODE "file(WRITE \"${install_yang_file_name}\" \"${SH_INSTALL_YANG_CMDS}\")")
    install(CODE "message(STATUS \"Installation commands were written to ${install_yang_file_name}\")")
endif()
