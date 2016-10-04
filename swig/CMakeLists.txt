set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11 -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
remove_definitions(-DSWIGLUA)

# find SWIG package
if(GEN_LANGUAGE_BINDINGS)
    find_package(SWIG)
    if(NOT SWIG_FOUND)
        message(WARNING "SWIG library not found")
    else()
        include(${SWIG_USE_FILE})
    endif()
endif()

# find Lua package
if(GEN_LUA_BINDINGS AND SWIG_FOUND)
    message("-- Lua version ${GEN_LUA_VERSION} was selected")
    if(${GEN_LUA_VERSION} STREQUAL "5.1")
        find_package(Lua51)
        if(NOT LUA51_FOUND)
            message(WARNING "Did not found Lua version 5.1")
            message("-- Sysrepo supports Lua 5.1 and Lua 5.2")
        endif()
    elseif(${GEN_LUA_VERSION} STREQUAL "5.2")
        find_package(Lua 5.2)
        if(NOT LUA_FOUND)
            message(WARNING "Did not found Lua version 5.2")
            message("-- Sysrepo supports Lua 5.1 and Lua 5.2")
        endif()
    else()
        message(WARNING "Sysrepo supports Lua 5.1 and Lua 5.2")
    endif()
endif()

# find Python package
if(GEN_PYTHON_BINDINGS AND SWIG_FOUND)
    message("-- Python version ${GEN_PYTHON_VERSION} was selected")
    if(${GEN_PYTHON_VERSION} STREQUAL "2")
        find_package(PythonLibs 2)
        find_package(PythonInterp)
        if(NOT PYTHONLIBS_FOUND)
            message(WARNING "Did not found Python version 2.x")
            message("-- Sysrepo supports Python 2.x and Python 3.x")
        endif()
    elseif(${GEN_PYTHON_VERSION} STREQUAL "3")
        find_package(PythonLibs 3)
        find_package(PythonInterp)
        if(NOT PYTHONLIBS_FOUND)
            message(WARNING "Did not found Python version 3.x")
            message("-- Sysrepo supports Python 2.x and Python 3.x")
        endif()
    else()
        message(WARNING "Sysrepo supports Python 2.x and Python 3.x")
    endif()
endif()

# find Python package
if(GEN_JAVA_BINDINGS AND SWIG_FOUND)
    find_package(Java REQUIRED)
    find_package(JNI REQUIRED)
    if(NOT JAVA_FOUND)
        message(WARNING "Did not found Java")
    endif()
endif()


project(Sysrepo-cpp)
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

add_library(Sysrepo-cpp SHARED ${SYSREPO_CPP_SOURCES})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/cpp/src")
target_link_libraries(Sysrepo-cpp sysrepo)

if(NOT BIN_INSTALL_DIR)
	set(BIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()

if(PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND AND ${GEN_PYTHON_VERSION} STREQUAL "2")
        set(PYTHON_SWIG_BINDING_2 libsysrepoPython2)
        include_directories(${PYTHON_INCLUDE_PATH})
        include_directories(${CMAKE_CURRENT_SOURCE_DIR})

        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
        set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})

        set(CMAKE_SWIG_FLAGS "-c++")
        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")

        set_source_files_properties(python2/${PYTHON_SWIG_BINDING_2}.i PROPERTIES CPLUSPLUS ON)

        swig_add_module(${PYTHON_SWIG_BINDING_2} python python2/${PYTHON_SWIG_BINDING_2}.i)
        swig_link_libraries(${PYTHON_SWIG_BINDING_2} ${PYTHON_LIBRARIES} Sysrepo-cpp)

        file(COPY "python2/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/python2")

        add_custom_command(
        TARGET Sysrepo-cpp POST_BUILD
        COMMAND ln -sf "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_2}.py" "${CMAKE_CURRENT_BINARY_DIR}/python2/examples/${PYTHON_SWIG_BINDING_2}.py"
        COMMAND ln -sf "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_2}.so" "${CMAKE_CURRENT_BINARY_DIR}/python2/examples/_${PYTHON_SWIG_BINDING_2}.so"
        )
endif()

if(PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND AND ${GEN_PYTHON_VERSION} STREQUAL "3")
        set(PYTHON_SWIG_BINDING_3 libsysrepoPython3)
        include_directories(${PYTHON_INCLUDE_PATH})
        include_directories(${CMAKE_CURRENT_SOURCE_DIR})

        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
        set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR})

        set(CMAKE_SWIG_FLAGS "-c++")
        set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")

        set_source_files_properties(python3/${PYTHON_SWIG_BINDING_3}.i PROPERTIES CPLUSPLUS ON)

        swig_add_module(${PYTHON_SWIG_BINDING_3} python python3/${PYTHON_SWIG_BINDING_3}.i)
        swig_link_libraries(${PYTHON_SWIG_BINDING_3} ${PYTHON_LIBRARIES} Sysrepo-cpp)

        file(COPY "python3/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/python3")

	add_custom_command(
        TARGET Sysrepo-cpp POST_BUILD
        COMMAND ln -sf "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_3}.py" "${CMAKE_CURRENT_BINARY_DIR}/python3/examples/${PYTHON_SWIG_BINDING_3}.py"
        COMMAND ln -sf "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_3}.so" "${CMAKE_CURRENT_BINARY_DIR}/python3/examples/_${PYTHON_SWIG_BINDING_3}.so"
        )
endif()

if(JAVA_FOUND)
        set(JAVA_SWIG_BINDING libsysrepoJava)
        include(UseJava)
        include(UseSWIG)

	include(${SWIG_USE_FILE})
	include_directories(${CMAKE_CURRENT_SOURCE_DIR})
	include_directories(${JAVA_INCLUDE_PATH})
	#include_directories("${JAVA_INCLUDE_PATH}/linux")
	include_directories(${JAVA_INCLUDE_DIRS})
        set(CMAKE_SWIG_FLAGS "-c++")

	set_source_files_properties(java/${JAVA_SWIG_BINDING}.i PROPERTIES CPLUSPLUS ON)

	set(CMAKE_SWIG_OUTDIR "${CMAKE_CURRENT_BINARY_DIR}/java")
	file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/classes")

	swig_add_module(${JAVA_SWIG_BINDING} java java/${JAVA_SWIG_BINDING}.i)
	swig_link_libraries(${JAVA_SWIG_BINDING} ${JAVA_LIBRARIES} Sysrepo-cpp)

	file(COPY "java/examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/java")

	add_custom_command(TARGET ${JAVA_SWIG_BINDING} POST_BUILD COMMAND "${Java_JAVAC_EXECUTABLE}" -d classes java/*.java COMMAND "${Java_JAR_EXECUTABLE}" -cfM Sysrepo.jar -C classes . )
	set(NATIVE_JAR "${CMAKE_CURRENT_BINARY_DIR}/Sysrepo.jar")
endif()

# install binary
install(TARGETS Sysrepo-cpp DESTINATION ${LIB_INSTALL_DIR})

# Examples
if(GEN_CPP_BINDINGS AND BUILD_CPP_EXAMPLES)
	add_subdirectory(cpp/examples)
endif()

# build Lua bindings
if(LUA51_FOUND)
    add_subdirectory(lua51)
elseif(LUA_FOUND)
    add_subdirectory(lua52)
endif()
