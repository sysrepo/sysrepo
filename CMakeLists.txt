cmake_minimum_required(VERSION 2.8.12)
project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository")
include(GNUInstallDirs)
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckStructHasMember)

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(SYSREPO_MAJOR_VERSION 1)
set(SYSREPO_MINOR_VERSION 3)
set(SYSREPO_MICRO_VERSION 17)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(SYSREPO_MAJOR_SOVERSION 4)
set(SYSREPO_MINOR_SOVERSION 1)
set(SYSREPO_MICRO_SOVERSION 4)
set(SYSREPO_SOVERSION_FULL ${SYSREPO_MAJOR_SOVERSION}.${SYSREPO_MINOR_SOVERSION}.${SYSREPO_MICRO_SOVERSION})
set(SYSREPO_SOVERSION ${SYSREPO_MAJOR_SOVERSION})

# options
if((CMAKE_BUILD_TYPE_LOWER STREQUAL debug) OR (CMAKE_BUILD_TYPE_LOWER STREQUAL package))
    option(ENABLE_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)

if(ENABLE_COVERAGE)
    find_program(PATH_GCOV NAMES gcov)
    if(NOT PATH_GCOV)
        message(WARNING "'gcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_LCOV NAMES lcov)
    if(NOT PATH_GCOV)
        message(WARNING "'lcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_GENHTML NAMES genhtml)
    if(NOT PATH_GCOV)
        message(WARNING "'genhtml' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    if(NOT CMAKE_COMPILER_IS_GNUCC)
        message(WARNING "Compiler is not gcc! Coverage may break the tests!")
    endif()

    if(ENABLE_COVERAGE)
        set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    endif()
endif()

# binding options
option(GEN_LANGUAGE_BINDINGS "Enable library bindings for different languages." OFF)

option(GEN_CPP_BINDINGS "Enable C++ bindings." ON)
option(BUILD_CPP_EXAMPLES "Enable C++ example application compilation." ON)

option(GEN_PYTHON_BINDINGS "Enable Python bindings." ON)
option(ENABLE_PYTHON_TESTS "Enable Python tests." ON)

# compilation flags
set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE} -Wall -Wextra -Wpedantic -std=c99")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

# paths
if(NOT REPO_PATH)
    if(CMAKE_BUILD_TYPE_LOWER STREQUAL debug)
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
if(NOT PLUGINS_PATH)
    set(PLUGINS_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/sysrepo/plugins/" CACHE PATH
        "Sysrepo plugin daemon plugins path.")
endif()
message(STATUS "SRPD plugins path:  ${PLUGINS_PATH}")

# required functions
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_GNU_SOURCE")
check_symbol_exists(eaccess "unistd.h" SR_HAVE_EACCESS)
if(NOT SR_HAVE_EACCESS)
    message(WARNING "Function eaccess() is not supported, using access() instead which may "
        "change results of access control checks!")
endif()
check_include_file("stdatomic.h" SR_HAVE_STDATOMIC)
check_struct_has_member(pthread_mutex_t __align pthread.h SR_MUTEX_HAS_ALIGN LANGUAGE C)
if(NOT SR_MUTEX_HAS_ALIGN)
    set(SR_MUTEX_HAS_ALIGN 0)
endif()
check_struct_has_member(pthread_cond_t __align pthread.h SR_COND_HAS_ALIGN LANGUAGE C)
if(NOT SR_COND_HAS_ALIGN)
    set(SR_COND_HAS_ALIGN 0)
endif()

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/common.h.in" "${PROJECT_BINARY_DIR}/common.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/src/executables/bin_common.h.in" "${PROJECT_BINARY_DIR}/bin_common.h" ESCAPE_QUOTES @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/libsysrepo.pc.in" "${PROJECT_BINARY_DIR}/libsysrepo.pc" @ONLY)
include_directories(${PROJECT_BINARY_DIR})
include_directories("${PROJECT_SOURCE_DIR}/src")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

# objects
set(LIB_SRC
    src/sysrepo.c
    src/common.c
    src/log.c
    src/replay.c
    src/modinfo.c
    src/edit_diff.c
    src/lyd_mods.c
    src/shm_main.c
    src/shm_mod.c
    src/shm_sub.c
    src/utils/values.c
    src/utils/xpath.c)

set (SYSREPOCTL_SRC
    src/executables/sysrepoctl.c)

set (SYSREPOCFG_SRC
    src/executables/sysrepocfg.c)

set (SYSREPOPLUGIND_SRC
    src/executables/sysrepo-plugind.c)

# libsysrepo
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
add_library(srobj OBJECT ${LIB_SRC})
set_target_properties(srobj PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
add_library(sysrepo SHARED $<TARGET_OBJECTS:srobj>)
set_target_properties(sysrepo PROPERTIES VERSION ${SYSREPO_SOVERSION_FULL} SOVERSION ${SYSREPO_SOVERSION})

# dependencies
target_link_libraries(sysrepo rt)

find_package(YANG REQUIRED)
target_link_libraries(sysrepo ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(sysrepo ${CMAKE_THREAD_LIBS_INIT})

set(CMAKE_REQUIRED_LIBRARIES pthread)

# sysrepoctl tool
add_executable(sysrepoctl ${SYSREPOCTL_SRC})
target_link_libraries(sysrepoctl sysrepo ${LIBYANG_LIBRARIES})

# sysrepocfg tool
add_executable(sysrepocfg ${SYSREPOCFG_SRC})
target_link_libraries(sysrepocfg sysrepo ${LIBYANG_LIBRARIES})

# sysrepo-plugind daemon
add_executable(sysrepo-plugind ${SYSREPOPLUGIND_SRC})
target_link_libraries(sysrepo-plugind sysrepo dl)

# installation
install(TARGETS sysrepo DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/sysrepo.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/utils/values.h ${PROJECT_SOURCE_DIR}/src/utils/xpath.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo)
install(TARGETS sysrepoctl sysrepocfg sysrepo-plugind DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES "${PROJECT_BINARY_DIR}/libsysrepo.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# doxygen documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    find_program(DOT_PATH dot PATH_SUFFIXES graphviz2.38/bin graphviz/bin)
    if(DOT_PATH)
        set(HAVE_DOT "YES")
    else()
        set(HAVE_DOT "NO")
        message(AUTHOR_WARNING "Doxygen: to generate UML diagrams please install graphviz")
    endif()
    add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    configure_file(Doxyfile.in Doxyfile)
endif()

# examples
if(BUILD_CPP_EXAMPLES)
    add_subdirectory(examples)
endif()

# tests
if(ENABLE_TESTS)
    find_package(CMocka 1.0.0)
    if(CMOCKA_FOUND)
        enable_testing()
        add_subdirectory(tests)
    else(CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka.")
        set(ENABLE_BUILD_TESTS NO)
    endif(CMOCKA_FOUND)
endif(ENABLE_TESTS)

# bindings
if(GEN_LANGUAGE_BINDINGS)
    add_subdirectory(bindings)
endif()

# phony target for clearing all sysrepo data
add_custom_target(sr_clean
    COMMAND rm -rf /dev/shm/sr_*
    COMMAND rm -rf /dev/shm/srsub_*
    COMMAND rm -rf ${REPO_PATH}
)

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
add_custom_target(uninstall_with_repo "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
    COMMAND rm -rf ${REPOSITORY_LOC})
