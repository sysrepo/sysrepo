set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
add_definitions(-DSWIG)
remove_definitions(-DSWIGLUA)

project(Sysrepo_bindings)
set(SYSREPO_CPP_SOURCES
	${CMAKE_SOURCE_DIR}/swig/cpp/src/Sysrepo.cpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Connection.cpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Session.cpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Struct.cpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Xpath.cpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Tree.cpp
	${CMAKE_SOURCE_DIR}/swig/cpp/src/Internal.cpp)

set(SYSREPO_H_SOURCES
	${CMAKE_SOURCE_DIR}/swig/cpp/src/Sysrepo.h
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Connection.h
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Session.h
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Struct.h
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Xpath.h
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Tree.h
	${CMAKE_SOURCE_DIR}/swig/cpp/src/Internal.h)

add_library(Sysrepo_bindings SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)
target_link_libraries(Sysrepo_bindings sysrepo)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

find_package(SWIG)
if (SWIG_FOUND)
    include(${SWIG_USE_FILE})
endif(SWIG_FOUND)

if(SWIG_FOUND AND GEN_PYTHON_BINDINGS AND ${GEN_PYTHON_VERSION} STREQUAL "2")
    find_package(PythonLibs 2 REQUIRED)
    set(PYTHON_SWIG_BINDING_2 libsysrepoPython2)
    if (PYTHONLIBS_FOUND)
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
endif()

if(SWIG_FOUND AND GEN_PYTHON_BINDINGS AND ${GEN_PYTHON_VERSION} STREQUAL "3")
    find_package(PythonLibs 3 REQUIRED)
    set(PYTHON_SWIG_BINDING_3 libsysrepoPython3)
    if (PYTHONLIBS_FOUND)
        include(${SWIG_USE_FILE})
        include_directories(${PYTHON_INCLUDE_PATH})
        include_directories(${CMAKE_CURRENT_SOURCE_DIR})

        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
        set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})

        set(CMAKE_SWIG_FLAGS "-c++")
        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")

        set_source_files_properties(python3/${PYTHON_SWIG_BINDING_3}.i PROPERTIES CPLUSPLUS ON)

        swig_add_module(${PYTHON_SWIG_BINDING_3} python python3/${PYTHON_SWIG_BINDING_3}.i)
        swig_link_libraries(${PYTHON_SWIG_BINDING_3} ${PYTHON_LIBRARIES} Sysrepo_bindings)

        file(COPY "python3/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/python3")

		add_custom_command(
        TARGET Sysrepo_bindings POST_BUILD
        COMMAND ln -sf "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_3}.py" "${CMAKE_CURRENT_BINARY_DIR}/python3/examples/${PYTHON_SWIG_BINDING_3}.py"
        COMMAND ln -sf "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_3}.so" "${CMAKE_CURRENT_BINARY_DIR}/python3/examples/_${PYTHON_SWIG_BINDING_3}.so"
        )
    endif()
endif()

# install binary
install(TARGETS Sysrepo_bindings DESTINATION ${BIN_INSTALL_DIR})

# build Lua bindings
if(SWIG_FOUND AND GEN_LUA_BINDINGS AND ${GEN_LUA_VERSION} STREQUAL "5.1")
    add_subdirectory(lua51)
elseif(SWIG_FOUND AND GEN_LUA_BINDINGS AND ${GEN_LUA_VERSION} STREQUAL "5.2")
    add_subdirectory(lua52)
endif()

# build C++ bindings
if(GEN_CPP_BINDINGS)
    add_subdirectory(cpp)
endif()
