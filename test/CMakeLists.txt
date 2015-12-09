set(TEST_DATA_DIR_V "${PROJECT_SOURCE_DIR}/test/data")
configure_file("${PROJECT_SOURCE_DIR}/test/data/test_data.h.in" "${PROJECT_SOURCE_DIR}/test/data/test_data.h" ESCAPE_QUOTES @ONLY) 

include_directories ("${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/test/data/")
add_executable(test_parser xpath_processor_parser.c)
add_dependencies(test_parser test_parser)
target_link_libraries(test_parser sysrepo-engine cmocka)

add_test(test_parser test_parser)
add_test(test_parser_valgrind valgrind
             --error-exitcode=1 --read-var-info=yes
             --leak-check=full --show-leak-kinds=all
            ./test_parser)

add_executable(test_yang xpath_processor_yang.c)
target_link_libraries(test_yang sysrepo-engine cmocka yang)
add_test(test_yang test_yang)
