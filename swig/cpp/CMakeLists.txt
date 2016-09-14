remove_definitions(-DSWIG)

project(Sysrepo_cpp)

add_library(Sysrepo_cpp SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(Sysrepo_cpp sysrepo)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

# Examples
set(BUILD_CPP_EXAMPLES 1 CACHE BOOL "Build C++ examples")
if(BUILD_CPP_EXAMPLES)
	add_subdirectory(examples)
endif()

# install binary
install(TARGETS Sysrepo_cpp DESTINATION ${BIN_INSTALL_DIR})
