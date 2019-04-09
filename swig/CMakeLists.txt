set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11 -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")

# find SWIG package
if(GEN_LANGUAGE_BINDINGS)
    find_package(SWIG 3.0.12)
    if(NOT SWIG_FOUND)
        message(WARNING "SWIG library not found")
    else()
        include(${SWIG_USE_FILE})
    endif()
endif()

# find Python package
if(GEN_PYTHON_BINDINGS AND SWIG_FOUND)
    message(STATUS "Python version ${GEN_PYTHON_VERSION} was selected")
    unset(PYTHON_LIBRARY CACHE)
    unset(PYTHON_EXECUTABLE CACHE)
    unset(PYTHON_INCLUDE_DIR CACHE)
    unset(PYTHON_LIBRARY_DEBUG CACHE)
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
        else()
            set(GEN_PYTHON3_TESTS 1 CACHE BOOL "Enable Python3 tests.")
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
    if(NOT JNI_FOUND)
        message(WARNING "Did not found JNI")
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

set(SYSREPO_HPP_SOURCES
    ${CMAKE_SOURCE_DIR}/swig/cpp/src/Sysrepo.hpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Connection.hpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Session.hpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Struct.hpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Xpath.hpp
        ${CMAKE_SOURCE_DIR}/swig/cpp/src/Tree.hpp
    ${CMAKE_SOURCE_DIR}/swig/cpp/src/Internal.hpp)

add_library(Sysrepo-cpp SHARED ${SYSREPO_CPP_SOURCES})
SET_TARGET_PROPERTIES(Sysrepo-cpp PROPERTIES
              VERSION ${SYSREPO_VERSION} SOVERSION ${SYSREPO_SOVERSION})

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/cpp/src")
target_link_libraries(Sysrepo-cpp sysrepo)

# install binary
install(TARGETS Sysrepo-cpp DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${SYSREPO_HPP_SOURCES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo-cpp)

# CPP bindings
if(GEN_CPP_BINDINGS)
    # generate and install pkg-config file
    configure_file("cpp/libSysrepo-cpp.pc.in" "libSysrepo-cpp.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libSysrepo-cpp.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

    # Examples
    if(BUILD_CPP_EXAMPLES)
        add_subdirectory(cpp/examples)

        if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}" AND ENABLE_TESTS)
            add_subdirectory(cpp/tests)

            # make Sysrepo-cpp depend on sysrepoctl
            add_dependencies(Sysrepo-cpp sysrepoctl)

            macro(INSTALL_YANG MODULE_NAME MODULE_REVISION)

              set(CPP_TEST_MODULE ${MODULE_NAME})
              set(CPP_TEST_MODULE_REV ${MODULE_REVISION} )
              set(CPP_SWIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
              set(CPP_TEST_DIR ${CPP_SWIG_DIR}/tests)
              set(CPP_YANG_DIR ${CPP_TEST_DIR}/yang)

              ADD_CUSTOM_COMMAND(
                TARGET Sysrepo-cpp
                POST_BUILD
                COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${CPP_YANG_DIR}/${CPP_TEST_MODULE}@${CPP_TEST_MODULE_REV}.yang
                VERBATIM)
            endmacro(INSTALL_YANG)

            INSTALL_YANG("swig-test-cpp-changes"    "2017-03-09")
            INSTALL_YANG("swig-test-cpp-operations" "2017-03-09")
        endif()
    endif()
endif()

if(PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND AND (${GEN_PYTHON_VERSION} STREQUAL "2" OR ${GEN_PYTHON_VERSION} STREQUAL "3"))
    add_subdirectory(python)
endif()

if(JAVA_FOUND)
    add_subdirectory(java)
endif()
