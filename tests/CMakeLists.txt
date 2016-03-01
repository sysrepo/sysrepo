set(TEST_REPOSITORY_LOC "${PROJECT_SOURCE_DIR}/tests/data/")

configure_file("${PROJECT_SOURCE_DIR}/tests/data/test_data.h.in" "${PROJECT_SOURCE_DIR}/tests/data/test_data.h" ESCAPE_QUOTES @ONLY) 

include_directories ("${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/src/common" "${PROJECT_SOURCE_DIR}/inc" "${PROJECT_SOURCE_DIR}/tests/data/" "${PROJECT_SOURCE_DIR}/tests/helpers/")
set(HELPERS_DIR "${PROJECT_SOURCE_DIR}/tests/helpers/")

find_program(valgrind_FOUND valgrind)

macro(ADD_UNIT_TEST_WITH_OPTS TEST_NAME TEST_SRC LIBS USE_VALGRIND)
    add_executable(${TEST_NAME} ${TEST_SRC})
    target_link_libraries(${TEST_NAME} ${LIBS} ${CMOCKA_LIBRARIES} sysrepo sysrepo-engine)
    add_test(${TEST_NAME} ${TEST_NAME})
    if(valgrind_FOUND)
       if(${USE_VALGRIND})
           add_test(${TEST_NAME}_valgrind valgrind
                --error-exitcode=1 --read-var-info=yes
                --leak-check=full --show-leak-kinds=all
                ./${TEST_NAME})
       endif(${USE_VALGRIND})
    endif(valgrind_FOUND)
endmacro(ADD_UNIT_TEST_WITH_OPTS)

#Create default test target source file is derived from test name and valgrind is on
macro(ADD_UNIT_TEST TEST_NAME)
    ADD_UNIT_TEST_WITH_OPTS(${TEST_NAME} ${TEST_NAME}.c "" 1)
endmacro(ADD_UNIT_TEST)


#Create test target source with helper functions included 
macro(ADD_UNIT_TEST_WITH_HELPERS TEST_NAME)
     set(t_files
        ${TEST_NAME}.c
        ${HELPERS_DIR}dt_xpath_helpers.c
        ${HELPERS_DIR}rp_dt_context_helper.c
        ${HELPERS_DIR}test_module_helper.c
        )
    ADD_UNIT_TEST_WITH_OPTS(${TEST_NAME} "${t_files}" "" 1)
endmacro(ADD_UNIT_TEST_WITH_HELPERS)

ADD_UNIT_TEST_WITH_HELPERS(ac_test)
ADD_UNIT_TEST(common_test)

ADD_UNIT_TEST(xp_parser_test)
ADD_UNIT_TEST(xp_yang_test)

ADD_UNIT_TEST(sm_test)
ADD_UNIT_TEST(cm_test)

ADD_UNIT_TEST_WITH_HELPERS(dm_test)
ADD_UNIT_TEST(rp_dt_xpath_test)
ADD_UNIT_TEST(rp_test)

ADD_UNIT_TEST_WITH_HELPERS(rp_datatree_test)
ADD_UNIT_TEST(rp_node_stack_test)
ADD_UNIT_TEST_WITH_HELPERS(rp_dt_edit_test)
ADD_UNIT_TEST_WITH_HELPERS(rp_dt_running_test)


ADD_UNIT_TEST_WITH_HELPERS(cl_test)
ADD_UNIT_TEST(concurr_test)
ADD_UNIT_TEST_WITH_OPTS(perf_test perf_test.c "" 0)
ADD_UNIT_TEST_WITH_OPTS(daemon_test daemon_test.c "" 0)

