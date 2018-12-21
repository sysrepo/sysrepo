cmake_minimum_required(VERSION 2.8.12)
project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository")
include(GNUInstallDirs)

# setup version
set(SYSREPO_MAJOR_VERSION 1)
set(SYSREPO_MINOR_VERSION 0)
set(SYSREPO_MICRO_VERSION 0)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})
set(SYSREPO_SOVERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION})

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -std=c99 -Wno-language-extension-token")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

# options
if((CMAKE_BUILD_TYPE_LOWER STREQUAL debug) OR (CMAKE_BUILD_TYPE_LOWER STREQUAL package))
    option(ENABLE_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()

# location of sysrepo repository
if(NOT REPO_PATH)
    if(CMAKE_BUILD_TYPE_LOWER STREQUAL debug)
        set(REPO_PATH "${CMAKE_BINARY_DIR}/repository" CACHE PATH "Repository path, contains configuration schema and data files.")
    else()
        set(REPO_PATH "/etc/sysrepo" CACHE PATH "Repository path, contains configuration schema and data files.")
    endif()
else()
    set(REPO_PATH "${REPO_PATH}" CACHE PATH "Repository path, contains configuration schema and data files.")
endif()
message(STATUS "Sysrepo repository location: ${REPO_PATH}")

# generate common file
configure_file("${PROJECT_SOURCE_DIR}/src/common.h.in" "${PROJECT_BINARY_DIR}/common.h" ESCAPE_QUOTES @ONLY)
include_directories(${PROJECT_BINARY_DIR})
include_directories("${PROJECT_SOURCE_DIR}/src")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

set(LIBSRC
    src/sysrepo.c
    src/common.c
    src/edit_diff.c
    src/shm_main.c
    src/shm_mod.c
    src/shm_sub.c)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
add_library(srobj OBJECT ${LIBSRC})
add_library(sysrepo SHARED $<TARGET_OBJECTS:srobj>)

# dependencies
find_package(YANG REQUIRED)
target_link_libraries(sysrepo ${LIBYANG_LIBRARIES})
include_directories(${YANG_INCLUDE_DIR})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(sysrepo ${CMAKE_THREAD_LIBS_INIT})

# check for non-portable functions and headers
set(CMAKE_REQUIRED_LIBRARIES pthread)

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

# phony target for clearing all sysrepo data
add_custom_target(sr_clean
    COMMAND rm -rf /dev/shm/sr_*
    COMMAND rm -rf ${REPO_PATH}
)
