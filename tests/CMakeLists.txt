# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set TESTS_DIR to realpath
get_filename_component(TESTS_DIR "${CMAKE_SOURCE_DIR}/tests" REALPATH)

include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# headers test for including compat.h
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/ ${CMAKE_SOURCE_DIR}/src/executables/ ${CMAKE_SOURCE_DIR}/src/utils/)

# format
if (${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND make format-check)
endif()

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
        "TZ=CET+02:00"
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
if(ENABLE_VALGRIND_TESTS)
    foreach(test_name IN LISTS tests)
        add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_BINARY_DIR}/tests/${test_name})
        set_property(TEST ${test_name}_valgrind APPEND PROPERTY ENVIRONMENT
            "TZ=CET+02:00"
            "SYSREPO_REPOSITORY_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}"
            "SYSREPO_SHM_PREFIX=_tests_sr_${test_name}"
        )
    endforeach(test_name)
endif()
