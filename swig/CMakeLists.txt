set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
add_definitions(-DSWIG)

project(Sysrepo_bindings)
set(SYSREPO_CPP_SOURCES
	cpp/src/Sysrepo.cpp
        cpp/src/Connection.cpp
        cpp/src/Session.cpp
        cpp/src/Struct.cpp
        cpp/src/Xpath.cpp)

set(SYSREPO_H_SOURCES
	cpp/src/Sysrepo.h
        cpp/src/Connection.h
        cpp/src/Session.h
        cpp/src/Struct.h
        cpp/src/Xpath.h)

add_library(Sysrepo_bindings SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)
target_link_libraries(Sysrepo_bindings sysrepo)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

set(PYTHON_SWIG_BINDING_2 libsysrepoPython2)

find_package(SWIG)
if (SWIG_FOUND)
    include(${SWIG_USE_FILE})
    find_package(PythonLibs 2 REQUIRED)
endif(SWIG_FOUND)

if (SWIG_FOUND AND PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)
    include(${SWIG_USE_FILE})
    include_directories(${PYTHON_INCLUDE_PATH})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})

    set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
    set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})

    set(CMAKE_SWIG_FLAGS "-c++")
    set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")

    set_source_files_properties(python2/${PYTHON_SWIG_BINDING_2}.i PROPERTIES CPLUSPLUS ON)

    swig_add_module(${PYTHON_SWIG_BINDING_2} python python2/${PYTHON_SWIG_BINDING_2}.i)
    swig_link_libraries(${PYTHON_SWIG_BINDING_2} ${PYTHON_LIBRARIES} Sysrepo_bindings)

    file(COPY "python2/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/python2")

    add_custom_command(
        TARGET Sysrepo_bindings POST_BUILD
	COMMAND ln -sf "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_2}.py" "${CMAKE_CURRENT_BINARY_DIR}/python2/examples/${PYTHON_SWIG_BINDING_2}.py"
	COMMAND ln -sf "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_2}.so" "${CMAKE_CURRENT_BINARY_DIR}/python2/examples/_${PYTHON_SWIG_BINDING_2}.so"
    )
endif()

# install binary
install(TARGETS Sysrepo_bindings DESTINATION ${BIN_INSTALL_DIR})

# build C++ bindings
add_subdirectory(cpp)
