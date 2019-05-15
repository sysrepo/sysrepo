cmake_minimum_required(VERSION 2.8.12)

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set TESTS_DIR to realpath
get_filename_component(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests" REALPATH)

# lists of all the tests
set(tests test_modules test_validation test_edit test_candidate test_operational test_lock test_apply_changes
    test_copy_config test_rpc_action test_notif)

include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})

foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_name}.c)
endforeach(test_name)

# set common attributes of all tests
foreach(test_name IN LISTS tests)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} sysrepo yang)
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
    set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT "MALLOC_CHECK_=3 CMOCKA_TEST_ABORT=1")
endforeach(test_name)

# get notification directory
if(NOTIFICATION_PATH)
    set(TESTS_NOTIF_DIR "${NOTIFICATION_PATH}")
else()
    set(TESTS_NOTIF_DIR "${REPO_PATH}/data/notif")
endif()

# generate config
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_BINARY_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

# valgrind tests
find_program(VALGRIND_FOUND valgrind)
if(ENABLE_VALGRIND_TESTS)
    if(VALGRIND_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach(test_name)
    else(VALGRIND_FOUND)
        message(WARNING "valgrind executable not found! Disabling memory leak tests.")
    endif(VALGRIND_FOUND)
endif()
