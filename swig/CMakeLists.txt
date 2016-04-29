cmake_minimum_required(VERSION 3.1)

project(Sysrepo_cpp)
set(SYSREPO_CPP_SOURCES
	cpp/src/Sysrepo.cpp
        cpp/src/Connection.cpp
        cpp/src/Session.cpp)

set(SYSREPO_H_SOURCES
	cpp/src/Sysrepo.h
        cpp/src/Connection.h
        cpp/src/Session.h)

add_library(Sysrepo_cpp SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)
add_dependencies(Sysrepo_cpp sysrepo)
target_link_libraries(Sysrepo_cpp ${CMAKE_BINARY_DIR}/src/libsysrepo.so)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

set(LUA_SWIG_BINDING_51 libsysrepoLua51)

find_package(SWIG)
if (SWIG_FOUND)
    include(${SWIG_USE_FILE})
    find_package(Lua51)
endif(SWIG_FOUND)

if (SWIG_FOUND AND LUA51_FOUND)
    include_directories(${LUA_INCLUDE_DIR})

    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)

    set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/src")
    set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})

    set(CMAKE_SWIG_FLAGS "-c++")
    set_source_files_properties(lua/${LUA_SWIG_BINDING_51}.i PROPERTIES CPLUSPLUS ON)

    swig_add_module(${LUA_SWIG_BINDING_51} lua lua/${LUA_SWIG_BINDING_51}.i)
    swig_link_libraries(${LUA_SWIG_BINDING_51} ${LUA_LIBRARIES} Sysrepo_cpp)

    file(COPY "lua/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/lua")

    # TODO generalize this
    add_custom_command(
        TARGET Sysrepo_cpp POST_BUILD
        COMMAND ln -sf "${CMAKE_CURRENT_BINARY_DIR}/${LUA_SWIG_BINDING_51}.so" "${CMAKE_CURRENT_BINARY_DIR}/lua/examples/${LUA_SWIG_BINDING_51}.so"
    )
endif()

# Examples
set(BUILD_CPP_EXAMPLES 1 CACHE BOOL "Build C++ examples and install example YANG models.")
if(BUILD_CPP_EXAMPLES)
    add_subdirectory(cpp/examples)
endif()

# install binary
install(TARGETS Sysrepo_cpp DESTINATION ${BIN_INSTALL_DIR})
