cmake_minimum_required(VERSION 2.8)
project(sysrepo)
set(SYSREPO_DESC "YANG-based system repository")

# setup version
set(SYSREPO_MAJOR_VERSION 0)
set(SYSREPO_MINOR_VERSION 1)
set(SYSREPO_MICRO_VERSION 24)
set(SYSREPO_VERSION ${SYSREPO_MAJOR_VERSION}.${SYSREPO_MINOR_VERSION}.${SYSREPO_MICRO_VERSION})

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11")
if(CMAKE_COMPILER_IS_GNUCC)
    # disable strict aliasing in GCC, since it produces false alarams in libev
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing")
endif()
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

if(NOT LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR "lib")
endif()
if(NOT BIN_INSTALL_DIR)
    set(BIN_INSTALL_DIR "bin")
endif()
if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR "include")
endif()

# set build-type specific settings
if(CMAKE_BUILD_TYPE_LOWER MATCHES "debug")
    MESSAGE(STATUS "Preparing debug build of sysrepo v. ${SYSREPO_VERSION}")
    set(DAEMON_PID_FILE "/tmp/sysrepo.pid" CACHE PATH "Sysrepo daemon PID file.")
    set(DAEMON_SOCKET "/tmp/sysrepod.sock" CACHE PATH "Sysrepo deamon server socket path.")
else()
    MESSAGE(STATUS "Preparing release build of sysrepo v. ${SYSREPO_VERSION}")
    set(DAEMON_PID_FILE "/var/run/sysrepo.pid" CACHE PATH "Sysrepo daemon PID file.")
    set(DAEMON_SOCKET "/var/run/sysrepod.sock" CACHE PATH "Sysrepo deamon server socket path.")
endif()

# location of system repository
if(CMAKE_BUILD_TYPE_LOWER MATCHES "debug")
    set(REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository" CACHE PATH "System repository location, contains configuration schema and data files.")
else()
    set(REPOSITORY_LOC "/etc/sysrepo" CACHE PATH "System repository location, contains configuration schema and data files.")
endif()
set(SCHEMA_SEARCH_DIR "${REPOSITORY_LOC}/yang/")
set(DATA_SEARCH_DIR "${REPOSITORY_LOC}/data/")
set(INTERNAL_SCHEMA_SEARCH_DIR "${REPOSITORY_LOC}/yang/internal/")
MESSAGE(STATUS "sysrepo repository location: ${REPOSITORY_LOC}")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# find required libraries
find_package(EV REQUIRED)
include_directories(${EV_INCLUDE_DIR})

find_package(YANG REQUIRED)
include_directories(${YANG_INCLUDE_DIR})

find_package(Protobuf-c REQUIRED)
include_directories(${PROTOBUF-C_INCLUDE_DIR})

# find libavl and/or libredblack
find_package(AVL)
find_package(RedBlack)
if((NOT AVL_FOUND) AND (NOT REDBLACK_FOUND))
    MESSAGE(WARNING "libavl or libredblack must be installed.")
endif()

if(NOT DEFINED USE_AVL_LIB)
    # no preference configured, try to find libavl and then libredblack
    if(AVL_FOUND)
        SET(USE_AVL_LIB 1 CACHE BOOL "Use libavl (1) or libredblack (0) for binary tree manipulations.")
    else(AVL_FOUND)
        if(REDBLACK_FOUND)
            SET(USE_AVL_LIB 0 CACHE BOOL "Use libavl (1) or libredblack (0) for binary tree manipulations.")
        endif(REDBLACK_FOUND)
    endif(AVL_FOUND)
endif(NOT DEFINED USE_AVL_LIB)
if(USE_AVL_LIB)
    if(AVL_FOUND)
        MESSAGE(STATUS "libavl will be used for binary tree manipulations.")
        include_directories(${AVL_INCLUDE_DIR})
    else(AVL_FOUND)
         MESSAGE(WARNING "libavl cannot be found.")
    endif(AVL_FOUND)
else(USE_AVL_LIB)
    if(REDBLACK_FOUND)
        MESSAGE(STATUS "libredblack will be used for binary tree manipulations.")
        include_directories(${REDBLACK_INCLUDE_DIR})
    else(REDBLACK_FOUND)
         MESSAGE(WARNING "libredblack cannot be found.")
    endif(REDBLACK_FOUND)
endif(USE_AVL_LIB)

# check for non-portable functions and headers
set(CMAKE_REQUIRED_LIBRARIES pthread)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckStructHasMember)
CHECK_FUNCTION_EXISTS(pthread_rwlockattr_setkind_np HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
CHECK_FUNCTION_EXISTS(getpeereid HAVE_GETPEEREID)
CHECK_FUNCTION_EXISTS(getpeerucred HAVE_GETPEERUCRED)
CHECK_INCLUDE_FILES(ucred.h HAVE_UCRED_H)
CHECK_FUNCTION_EXISTS(setfsuid HAVE_SETFSUID)
CHECK_STRUCT_HAS_MEMBER("struct stat" st_mtim "sys/stat.h" HAVE_STAT_ST_MTIM)

# add subdirectories
add_subdirectory(src)
add_subdirectory(inc)

# Examples
SET(BUILD_EXAMPLES 1 CACHE BOOL "Build examples and install example YANG models.")
if(BUILD_EXAMPLES)
    MESSAGE(STATUS "Example code and YANG models will be built and installed.")
    add_subdirectory(examples)
endif()

# Testing
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

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif(DOXYGEN_FOUND)

set(PYTHON_SWIG_BINDING sysrepoPy)
set(LUA_SWIG_BINDING sysrepoLua)

FIND_PACKAGE(SWIG)
if (SWIG_FOUND)
    INCLUDE(${SWIG_USE_FILE})
    FIND_PACKAGE(PythonLibs 2)
    FIND_PACKAGE(PythonInterp)
    FIND_PACKAGE(Lua51)
    if (PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)
        INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_DIRS})
        INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/inc")
        SET(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/inc")
        SET(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/swig/python)

        SWIG_ADD_MODULE(${PYTHON_SWIG_BINDING} python swig/python/${PYTHON_SWIG_BINDING}.i)
        SWIG_LINK_LIBRARIES(${PYTHON_SWIG_BINDING} ${PYTHON_LIBRARIES} sysrepo_so)

        #move .so file to proper location
        add_custom_command(
          TARGET ${SWIG_MODULE_${PYTHON_SWIG_BINDING}_REAL_NAME}
          POST_BUILD
          COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING}.so" "${CMAKE_CURRENT_BINARY_DIR}/swig/python"
        )
    else ()
        MESSAGE(WARNING "Python libs not found, python bindings will not be generated.")
    endif()

    #FIND_PACKAGE(JNI REQUIRED)
    #FIND_PACKAGE(Java REQUIRED)

    #INCLUDE_DIRECTORIES(${JAVA_INCLUDE_PATH})
    #INCLUDE_DIRECTORIES(${JAVA_INCLUDE_PATH2})
    #SWIG_ADD_MODULE(sysrepo_java java sysrepo.i)
endif(SWIG_FOUND)


# install repository directories
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
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)

# install internal YANGs
install (FILES ${PROJECT_SOURCE_DIR}/yang/sysrepo-persistent-data.yang DESTINATION ${INTERNAL_SCHEMA_SEARCH_DIR})

# install swig bindings
if (SWIG_FOUND AND PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)
    #install python bindings
    execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c
                "from distutils import sysconfig; print( sysconfig.get_python_lib( plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}' ) )"
                OUTPUT_VARIABLE _ABS_PYTHON_MODULE_PATH
                OUTPUT_STRIP_TRAILING_WHITESPACE )
    get_filename_component ( _ABS_PYTHON_MODULE_PATH ${_ABS_PYTHON_MODULE_PATH} ABSOLUTE )
    file ( RELATIVE_PATH _REL_PYTHON_MODULE_PATH ${CMAKE_INSTALL_PREFIX} ${_ABS_PYTHON_MODULE_PATH} )
    set (PYTHON_MODULE_PATH ${_REL_PYTHON_MODULE_PATH})

    INSTALL ( FILES ${CMAKE_CURRENT_BINARY_DIR}/swig/python/_${PYTHON_SWIG_BINDING}.so DESTINATION ${PYTHON_MODULE_PATH} )
    INSTALL ( FILES ${CMAKE_CURRENT_BINARY_DIR}/swig/python/${PYTHON_SWIG_BINDING}.py DESTINATION ${PYTHON_MODULE_PATH} )
    INSTALL ( DIRECTORY ${PROJECT_SOURCE_DIR}/swig/python/SysrepoWrappers DESTINATION ${PYTHON_MODULE_PATH} )

endif()

if (SWIG_FOUND AND LUA51_FOUND)
    INCLUDE_DIRECTORIES(${LUA_INCLUDE_DIR})

    SET(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/inc")
    SET(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/swig/lua)

    SWIG_ADD_MODULE(${LUA_SWIG_BINDING} lua swig/lua/${LUA_SWIG_BINDING}.i)
    SWIG_LINK_LIBRARIES(${LUA_SWIG_BINDING} ${LUA_LIBRARIES} sysrepo_so)

    SET_SOURCE_FILES_PROPERTIES(swig/${LUA_SWIG_BINDING}.i PROPERTIES CPLUSPLUS ON)
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    # generate and install pkg-config file
    configure_file("libsysrepo.pc.in" "libsysrepo.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libsysrepo.pc" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")
endif()
