add_definitions(-DSWIG)
add_definitions(-DSWIGLUA)

project(Sysrepo_Lua)

add_library(Sysrepo_Lua SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(Sysrepo_Lua sysrepo)

set(LUA_SWIG_BINDING_52 libsysrepoLua52)

include(${SWIG_USE_FILE})
include_directories(${LUA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/inc")
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})

set_source_files_properties(${LUA_SWIG_BINDING_52}.i PROPERTIES CPLUSPLUS ON)

file(COPY "examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

swig_add_module(${LUA_SWIG_BINDING_52} lua ${LUA_SWIG_BINDING_52}.i)
swig_link_libraries(${LUA_SWIG_BINDING_52} ${LUA_LIBRARIES} Sysrepo_Lua)

# install binary
install(TARGETS Sysrepo_Lua DESTINATION ${BIN_INSTALL_DIR})
