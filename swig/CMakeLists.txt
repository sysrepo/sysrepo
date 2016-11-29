set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11 -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")
set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")
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
            message("-- Sysrepo supports Lua 5.1, Lua 5.2 and Lua 5.3")
        endif()
    elseif(${GEN_LUA_VERSION} STREQUAL "5.2")
        find_package(Lua 5.2)
        if(NOT LUA_FOUND)
            message(WARNING "Did not found Lua version 5.2")
            message("-- Sysrepo supports Lua 5.1, Lua 5.2 and Lua 5.3")
        endif()
    elseif(${GEN_LUA_VERSION} STREQUAL "5.3")
        find_package(Lua 5.3)
        if(NOT LUA_FOUND)
            message(WARNING "Did not found Lua version 5.3")
            message("-- Sysrepo supports Lua 5.1, Lua 5.2 and Lua 5.3")
        endif()
    else()
        message(WARNING "Sysrepo supports Lua 5.1, Lua 5.2 and Lua 5.3")
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

        execute_process(COMMAND
            ${PYTHON_EXECUTABLE} -c
            "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE PYTHON_MODULE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)

        install( FILES "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_2}.so" DESTINATION ${PYTHON_MODULE_PATH} )
        install( FILES "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_2}.py" DESTINATION ${PYTHON_MODULE_PATH} )

        if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}" AND ENABLE_TESTS AND GEN_PYTHON2_TESTS)
          set(PY2_SWIG_DIR ${CMAKE_BINARY_DIR}/swig/python2)

          file(COPY "python2/tests" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/python2")
          file(COPY "python2/run_python_test.sh" DESTINATION "${PY2_SWIG_DIR}")

          macro(ADD_PYTHON_TEST TEST_NAME)
            add_test(NAME python_${TEST_NAME}
              COMMAND sh ${PY2_SWIG_DIR}/run_python_test.sh
              "${CMAKE_BINARY_DIR}/src:${CMAKE_BINARY_DIR}/tests:${CMAKE_BINARY_DIR}/repository"
              "${PY2_SWIG_DIR}:${PROJECT_SOURCE_DIR}/swig/python2:${PYTHON_BUILD_DIR}"
              "${PYTHON_EXECUTABLE}"
              "${PY2_SWIG_DIR}/tests/${TEST_NAME}.py"
              WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
              )
          endmacro(ADD_PYTHON_TEST)

          ADD_PYTHON_TEST(SysrepoBasicTest)
          ADD_PYTHON_TEST(SchemasManagementTest)
          ADD_PYTHON_TEST(LockingTest)
          ADD_PYTHON_TEST(CommitTest)
          ADD_PYTHON_TEST(MoveTest)
          ADD_PYTHON_TEST(SubscriptionTest)
          ADD_PYTHON_TEST(NotificationTest) # note: needs notifications_test_app to work

          add_custom_command(TARGET ${SWIG_MODULE_${PYTHON_SWIG_BINDING_2}_REAL_NAME} POST_BUILD
            COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_2}.so" ${PY2_SWIG_DIR}/tests
            COMMAND cp "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_2}.py" ${PY2_SWIG_DIR}/tests
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            )
        endif()
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

        execute_process(COMMAND
            ${PYTHON_EXECUTABLE} -c
            "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE PYTHON_MODULE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)

        install( FILES "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_3}.so" DESTINATION ${PYTHON_MODULE_PATH} )
        install( FILES "${CMAKE_BINARY_DIR}/${PYTHON_SWIG_BINDING_3}.py" DESTINATION ${PYTHON_MODULE_PATH} )
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

	# install so file
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib${JAVA_SWIG_BINDING}.so" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

# install binary
install(TARGETS Sysrepo-cpp DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/cpp/src/" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo-cpp
    FILES_MATCHING PATTERN "*.h")

# Examples
if(GEN_CPP_BINDINGS AND BUILD_CPP_EXAMPLES)
	add_subdirectory(cpp/examples)
endif()

# build Lua bindings
if(LUA51_FOUND OR LUA_FOUND)
    add_subdirectory(lua)
endif()
