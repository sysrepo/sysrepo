set(PYTHON_SWIG_BINDING_3 libsysrepoPython3)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})
set(PYTHON3_SWIG_MIN_VERSION "3.0.5")

find_package(SWIG ${PYTHON3_SWIG_MIN_VERSION})
if (NOT SWIG_FOUND)
  message(WARNING "Minimum SWIG version for Python is ${PYTHON2_SWIG_MIN_VERSION}. Tests won't be generated.")
endif()

set_source_files_properties(${PYTHON_SWIG_BINDING_3}.i PROPERTIES CPLUSPLUS ON)

swig_add_module(${PYTHON_SWIG_BINDING_3} python ${PYTHON_SWIG_BINDING_3}.i)
swig_link_libraries(${PYTHON_SWIG_BINDING_3} ${PYTHON_LIBRARIES} Sysrepo-cpp)

file(COPY "examples" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

execute_process(COMMAND
    ${PYTHON_EXECUTABLE} -c
    "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
OUTPUT_VARIABLE PYTHON_MODULE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)

install( FILES "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_3}.so" DESTINATION ${PYTHON_MODULE_PATH} )
install( FILES "${CMAKE_CURRENT_BINARY_DIR}/${PYTHON_SWIG_BINDING_3}.py" DESTINATION ${PYTHON_MODULE_PATH} )

if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}" AND ENABLE_TESTS)
    set(PY3_SWIG_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(PY3_TEST_DIR ${PY3_SWIG_DIR}/tests)

    file(COPY "tests" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
    file(COPY "run_python_test.sh" DESTINATION "${PY3_SWIG_DIR}")

    macro(ADD_PYTHON_TEST TEST_NAME)
        add_test(NAME python_${TEST_NAME}
            COMMAND sh ${PY3_SWIG_DIR}/run_python_test.sh
            "${CMAKE_BINARY_DIR}/src:${CMAKE_BINARY_DIR}/tests:${CMAKE_BINARY_DIR}/repository:${PY3_TEST_DIR}"
            "${PY3_SWIG_DIR}:${PROJECT_SOURCE_DIR}/swig/python3:${PYTHON_BUILD_DIR}"
            "${PYTHON_EXECUTABLE}"
            "${PY3_SWIG_DIR}/tests/${TEST_NAME}.py"
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

    add_custom_command(TARGET ${SWIG_MODULE_${PYTHON_SWIG_BINDING_3}_REAL_NAME} POST_BUILD
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING_3}.so" ${PY3_SWIG_DIR}/tests
		    COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/${PYTHON_SWIG_BINDING_3}.py" ${PY3_SWIG_DIR}/tests
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
endif()
