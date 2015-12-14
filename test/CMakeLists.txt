set(TEST_DATA_DIR_V "${PROJECT_SOURCE_DIR}/test/data")

configure_file("${PROJECT_SOURCE_DIR}/test/data/test_data.h.in" "${PROJECT_SOURCE_DIR}/test/data/test_data.h" ESCAPE_QUOTES @ONLY) 
include_directories ("${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/test/data/")

find_program(valgrind_FOUND valgrind)

macro(ADD_UNIT_TEST TEST_NAME TEST_SRC LIBS USE_VALGRIND)
    add_executable(${TEST_NAME} ${TEST_SRC})
    target_link_libraries(${TEST_NAME} ${LIBS} sysrepo-engine cmocka)
    add_test(${TEST_NAME} ${TEST_NAME})
    if(valgrind_FOUND)
       if(${USE_VALGRIND})
           add_test(${TEST_NAME}_valgrind valgrind
                --error-exitcode=1 --read-var-info=yes
                --leak-check=full --show-leak-kinds=all
                ./${TEST_NAME})
       endif(${USE_VALGRIND})
    endif(valgrind_FOUND)
endmacro(ADD_UNIT_TEST)

ADD_UNIT_TEST(test_parser xpath_processor_parser.c "" 1)
ADD_UNIT_TEST(test_yang xpath_processor_yang.c "yang" 0)

ADD_UNIT_TEST(test_session_manager session_manager.c "" 1)
ADD_UNIT_TEST(test_data_manager data_manager.c "" 1)

