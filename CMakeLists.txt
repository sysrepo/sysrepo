cmake_minimum_required(VERSION 2.8)
project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository")

# setup version
set(SYSREPO_MAJOR_VERSION 0)
set(SYSREPO_MINOR_VERSION 1)
set(SYSREPO_MICRO_VERSION 2)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-coverage -g -O0")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

if(NOT LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR "lib")
endif()

if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR "include")
endif()

find_package(YANG REQUIRED)
find_package(Protobuf-c REQUIRED)
include_directories(${PROTOBUF-C_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# find libavl or libredblack
find_package(AVL)
if(AVL_FOUND)
    MESSAGE(STATUS "libavl will be used as binary tree minipulation library.")
else(AVL_FOUND)
    find_package(RedBlack)
    if(REDBLACK_FOUND)
        MESSAGE(STATUS "libredblack will be used as binary tree minipulation library.")
    else(REDBLACK_FOUND)
        MESSAGE(FATAL_ERROR "Either libavl or libredblack is required to build sysrepo.")
    endif(REDBLACK_FOUND)
endif(AVL_FOUND)

# location of system repository
set(REPOSITORY_LOC "${PROJECT_SOURCE_DIR}/tests/data/" CACHE PATH "System repository location, contains configuration schema and data files.")
set(SCHEMA_SEARCH_DIR "${REPOSITORY_LOC}/yang/")
set(DATA_SEARCH_DIR "${REPOSITORY_LOC}/data/")

#add subdirectories
add_subdirectory(src)
add_subdirectory(inc)
add_subdirectory(examples)



#Testing
SET(ENABLE_TESTS 1 CACHE BOOL "Enable unit tests.")
if(ENABLE_TESTS)
    find_package(CMOCKA)
    if(CMOCKA_FOUND)
        MESSAGE(STATUS "CMocka found, tests are enabled.")
        enable_testing()
        add_subdirectory(tests)
    else(CMOCKA_FOUND)
        MESSAGE(WARNING "CMocka not found, tests are disabled.")
    endif(CMOCKA_FOUND)
endif(ENABLE_TESTS)

#Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif(DOXYGEN_FOUND)


#install
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
    GROUP_READ GROUP_WRITE GROUP_EXECUTE
    WORLD_READ WORLD_WRITE WORLD_EXECUTE)


find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("libsysrepo.pc.in" "libsysrepo.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libsysrepo.pc" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")
endif()

