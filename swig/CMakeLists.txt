cmake_minimum_required(VERSION 3.1)
set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")

project(Sysrepo_cpp)
set(SYSREPO_CPP_SOURCES
	cpp/src/Sysrepo.cpp
	cpp/src/Value.cpp
        cpp/src/Connection.cpp
        cpp/src/Session.cpp)

set(SYSREPO_H_SOURCES
	cpp/src/Sysrepo.h
	cpp/src/Value.h
        cpp/src/Connection.h
        cpp/src/Session.h)

add_library(Sysrepo_cpp SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)
target_link_libraries(Sysrepo_cpp sysrepo)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

# Examples
set(BUILD_CPP_EXAMPLES 1 CACHE BOOL "Build C++ examples")
if(BUILD_CPP_EXAMPLES)
	add_subdirectory(cpp/examples)
endif()

# install binary
install(TARGETS Sysrepo_cpp DESTINATION ${BIN_INSTALL_DIR})
