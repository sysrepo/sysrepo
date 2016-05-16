set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")
set(TEST_SCHEMA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/yang/")
set(TEST_DATA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/data/")
set(TEST_INTERNAL_SCHEMA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/yang/internal/")

set(TEST_HELPERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/helpers/")

CHECK_INCLUDE_FILES(regex.h HAVE_REGEX_H)

configure_file("${TEST_HELPERS_DIR}/test_data.h.in" "${TEST_HELPERS_DIR}/test_data.h" ESCAPE_QUOTES @ONLY) 

include_directories ("${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/src/common" "${PROJECT_SOURCE_DIR}/inc" "${TEST_HELPERS_DIR}")

find_program(valgrind_FOUND valgrind)

# create test target with specified options
macro(ADD_UNIT_TEST_WITH_OPTS TEST_NAME USE_HELPERS USE_VALGRIND WRAP_FUNCTION)
    if(${USE_HELPERS})
        set(TEST_SRC
            ${TEST_NAME}.c
            ${TEST_HELPERS_DIR}rp_dt_context_helper.c
            ${TEST_HELPERS_DIR}test_module_helper.c
            ${TEST_HELPERS_DIR}system_helper.c
            )
    else()
        set(TEST_SRC
            ${TEST_NAME}.c
            )
    endif()
    if ("${WRAP_FUNCTION}" STREQUAL "")
        set(test_link_flags "")
    else()
        set(test_link_flags "-Wl,--wrap,${WRAP_FUNCTION}")
    endif()
    add_executable(${TEST_NAME} ${TEST_SRC})
    target_link_libraries(${TEST_NAME} ${CMOCKA_LIBRARIES} sysrepo sysrepo-engine ${test_link_flags})
    add_test(${TEST_NAME} ${TEST_NAME})
    if(valgrind_FOUND)
       if(${USE_VALGRIND})
           add_test(${TEST_NAME}_valgrind valgrind
                --error-exitcode=1 --read-var-info=yes
                --leak-check=full --show-leak-kinds=all
                --suppressions=${TEST_HELPERS_DIR}valgrind.supp
                ./${TEST_NAME})
       endif(${USE_VALGRIND})
    endif(valgrind_FOUND)
endmacro(ADD_UNIT_TEST_WITH_OPTS)

# create default test target with valgrind is on
macro(ADD_UNIT_TEST TEST_NAME USE_HELPERS)
    ADD_UNIT_TEST_WITH_OPTS(${TEST_NAME} ${USE_HELPERS} 1 "")
endmacro(ADD_UNIT_TEST)


ADD_UNIT_TEST(common_test 0)
ADD_UNIT_TEST(ac_test 1)

ADD_UNIT_TEST(cm_sm_test 0)
ADD_UNIT_TEST_WITH_OPTS(np_test 1 1 "cm_msg_send")
ADD_UNIT_TEST_WITH_OPTS(pm_test 1 1 "cm_msg_send")

ADD_UNIT_TEST(dm_test 1)

ADD_UNIT_TEST(rp_dt_xpath_test 0)
ADD_UNIT_TEST(rp_datatree_test 1)
ADD_UNIT_TEST(rp_dt_edit_test 1)
ADD_UNIT_TEST(rp_dt_running_test 1)

if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}")
    # end-to-end tests that work only if test repository location equals to 
    # global procject's repository location
    
    ADD_UNIT_TEST(cm_test 1)
    ADD_UNIT_TEST(rp_test 0)
    
    ADD_UNIT_TEST(cl_test 1)
    ADD_UNIT_TEST(concurr_test 1)
    ADD_UNIT_TEST_WITH_OPTS(perf_test 1 0 "")
    ADD_UNIT_TEST_WITH_OPTS(daemon_test 0 0 "")
    ADD_UNIT_TEST_WITH_OPTS(sysrepoctl_test 1 0 "")

    # Python tests
    FIND_PACKAGE(PythonInterp)
    FIND_PACKAGE(SWIG)
    FIND_PACKAGE(PythonLibs 2)
    
    if (SWIG_FOUND AND PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)
        macro(ADD_PYTHON_TEST TEST_NAME)
            add_test(NAME python_${TEST_NAME}
                COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/run_python_test.sh "${CMAKE_BINARY_DIR}/src:${CMAKE_BINARY_DIR}/tests" "${CMAKE_BINARY_DIR}/swig/python:${PROJECT_SOURCE_DIR}/swig/python" ${PYTHON_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/python/${TEST_NAME}.py
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            )
        endmacro(ADD_PYTHON_TEST)
        ADD_PYTHON_TEST(SysrepoBasicTest)
        ADD_PYTHON_TEST(LockingTest)
        ADD_PYTHON_TEST(CommitTest)
        ADD_PYTHON_TEST(MoveTest)
        ADD_PYTHON_TEST(SubscriptionTest)
        ADD_PYTHON_TEST(PerfTest)
    endif()
    add_executable(measure_perf measure_performance.c ${TEST_HELPERS_DIR}test_module_helper.c)
    target_link_libraries(measure_perf ${CMOCKA_LIBRARIES} sysrepo sysrepo-engine)
    add_executable(subscription_test_app subscription_test_app.c)
    target_link_libraries(subscription_test_app ${CMOCKA_LIBRARIES} sysrepo sysrepo-engine)

else()
    message(STATUS "Test repostory location differs to system repository location, some tests will be disabled.")
endif()


# create test repository directories and copy internal schemas
EXECUTE_PROCESS(
  COMMAND mkdir -p "${TEST_SCHEMA_SEARCH_DIR}" "${TEST_DATA_SEARCH_DIR}" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
  COMMAND cp "${PROJECT_SOURCE_DIR}/yang/sysrepo-persistent-data.yang" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
  COMMAND cp "${PROJECT_SOURCE_DIR}/yang/sysrepo-persistent-data.yin" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
  ERROR_QUIET
)

# make common_test depend on sysrepoctl
add_dependencies(common_test sysrepoctl)

# install testing YANG modules
macro(INSTALL_YANG_MODULE MODULE_NAME)
    ADD_CUSTOM_COMMAND(
        TARGET common_test
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}.yang -0 ${TEST_REPOSITORY_LOC} > /dev/null
        VERBATIM
    )
endmacro(INSTALL_YANG_MODULE)

INSTALL_YANG_MODULE("example-module")
INSTALL_YANG_MODULE("test-module")
INSTALL_YANG_MODULE("small-module")
INSTALL_YANG_MODULE("info-module")
INSTALL_YANG_MODULE("module-a@2016-02-02")
INSTALL_YANG_MODULE("module-a@2016-02-10")
INSTALL_YANG_MODULE("module-b@2016-02-05")
INSTALL_YANG_MODULE("iana-if-type")
INSTALL_YANG_MODULE("ietf-interfaces@2014-05-08")
INSTALL_YANG_MODULE("ietf-ip@2014-06-16")
