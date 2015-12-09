cmake_minimum_required(VERSION 2.8)
project(sysrepo)

set(SYSREPO_MAJOR_VERSION 0)
set(SYSREPO_MINOR_VERSION 0)
set(SYSREPO_MICRO_VERSION 1)

set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})
set(CMAKE_C_FLAGS "-Wall -Werror -Wpedantic -std=gnu11 ")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

add_subdirectory(src)
add_subdirectory(inc)
add_subdirectory(examples)

find_package(YANG REQUIRED)

SET(ENABLE_TESTS 1 CACHE BOOL "Test enabled by default")
if(ENABLE_TESTS)
    find_package(CMOCKA)
    if(CMOCKA_FOUND)
        MESSAGE(STATUS "Test are enabled")
        enable_testing()
        add_subdirectory(test)
    else(CMOCKA_FOUND)
        MESSAGE(WARNING "Cmocka not found")
    endif(CMOCKA_FOUND)
endif(ENABLE_TESTS)

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




