cmake_minimum_required(VERSION 2.8.12)

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set TESTS_DIR to realpath
get_filename_component(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests" REALPATH)

include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# check for pthread_barrier existence
check_function_exists(pthread_barrier_init SR_HAVE_PTHREAD_BARRIER)
if(SR_HAVE_PTHREAD_BARRIER)
    set(test_sources "")
else()
    set(test_sources "pthread_barrier.c")
endif()

# generate config
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_BINARY_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

# lists of all the tests
set(tests test_modules test_validation test_edit test_candidate test_operational test_lock test_apply_changes
    test_copy_config test_rpc_action test_notif test_get test_process test_multi_connection)

foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_sources} ${test_name}.c)
endforeach(test_name)

# set common attributes of all tests
foreach(test_name IN LISTS tests)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} sysrepo)
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
    set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
        "MALLOC_CHECK_=3"
        "CMOCKA_TEST_ABORT=1"
        "SYSREPO_REPOSITORY_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}"
        "SYSREPO_SHM_PREFIX=_tests_sr_${test_name}"
    )
endforeach(test_name)

# phony target for clearing all sysrepo test data
add_custom_target(test_clean
    COMMAND rm -rf ${PROJECT_BINARY_DIR}/test_repositories
    COMMAND rm -rf /dev/shm/_tests_sr_*
)

# measure_performance benchmark binary
set(SR_PERF measure_performance)
add_executable(${SR_PERF} ${SR_PERF}.c)
target_link_libraries(${SR_PERF} ${CMOCKA_LIBRARIES} sysrepo)

# valgrind tests
find_program(VALGRIND_FOUND valgrind)
if(ENABLE_VALGRIND_TESTS)
    if(VALGRIND_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_BINARY_DIR}/tests/${test_name})
            set_property(TEST ${test_name}_valgrind APPEND PROPERTY ENVIRONMENT
                "SYSREPO_REPOSITORY_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}"
                "SYSREPO_SHM_PREFIX=_tests_sr_${test_name}"
            )
        endforeach(test_name)
    else(VALGRIND_FOUND)
        message(WARNING "valgrind executable not found! Disabling memory leak tests.")
    endif(VALGRIND_FOUND)
endif()

if(ENABLE_COVERAGE)
    # Destination
    set(COVERAGE_DIR        "${CMAKE_BINARY_DIR}/tests/code_coverage/")
    set(COVERAGE_FILE_RAW   "${CMAKE_BINARY_DIR}/tests/coverage_raw.info")
    set(COVERAGE_FILE_CLEAN "${CMAKE_BINARY_DIR}/tests/coverage_clean.info")

    # Add coverage target
    add_custom_target(coverage
        COMMENT "Generating code coverage..."
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        # Cleanup code counters
        COMMAND "${PATH_LCOV}" --directory . --zerocounters --quiet

        # Run tests
        COMMAND "${CMAKE_CTEST_COMMAND}" --quiet

        # Capture the counters
        COMMAND "${PATH_LCOV}"
            --directory .
            --rc lcov_branch_coverage=1
            --rc 'lcov_excl_line=assert'
            --capture --quiet
            --output-file "${COVERAGE_FILE_RAW}"
        # Remove coverage of tests, system headers, etc.
        COMMAND "${PATH_LCOV}"
            --remove "${COVERAGE_FILE_RAW}" '${CMAKE_SOURCE_DIR}/tests/*'
            --rc lcov_branch_coverage=1
            --quiet --output-file "${COVERAGE_FILE_CLEAN}"
        # Generate HTML report
        COMMAND "${PATH_GENHTML}"
            --branch-coverage --function-coverage --quiet --title "sysrepo"
            --legend --show-details --output-directory "${COVERAGE_DIR}"
            "${COVERAGE_FILE_CLEAN}"
        # Delete the counters
        COMMAND "${CMAKE_COMMAND}" -E remove
            ${COVERAGE_FILE_RAW} ${COVERAGE_FILE_CLEAN}
        )

    add_custom_command(TARGET coverage POST_BUILD
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        COMMENT "To see the code coverage report, open ${COVERAGE_DIR}index.html"
        COMMAND ;
        )
endif()
