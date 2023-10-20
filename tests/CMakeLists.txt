include(CheckFunctionExists)

if(NOT SYSREPO_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# set paths to realpath
get_filename_component(TESTS_SRC_DIR "${CMAKE_SOURCE_DIR}/tests" REALPATH)
get_filename_component(TESTS_REPO_DIR "${CMAKE_BINARY_DIR}" REALPATH)

include_directories(SYSTEM ${CMOCKA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR}/tests)

# headers test for including compat.h
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/ ${CMAKE_SOURCE_DIR}/src/executables/ ${CMAKE_SOURCE_DIR}/src/utils/)

set(test_sources "tcommon.c")

# check for pthread_barrier existence
check_function_exists(pthread_barrier_init SR_HAVE_PTHREAD_BARRIER)
if(NOT SR_HAVE_PTHREAD_BARRIER)
    list(APPEND test_sources "pthread_barrier.c")
endif()

# generate config
configure_file("${PROJECT_SOURCE_DIR}/tests/tcommon.h.in" "${PROJECT_BINARY_DIR}/tests/tcommon.h" ESCAPE_QUOTES @ONLY)

set(TEST_CLEAR_REPOS_CMD rm -rf ${PROJECT_BINARY_DIR}/test_repositories)
set(TEST_CLEAR_SHM_CMD find /dev/shm/ -maxdepth 1 -readable -name _tests_sr_* -delete)
if(${CMAKE_VERSION} VERSION_GREATER "3.7")
    # tests cleanup fixtures
    add_test(NAME tests_clear_repos
        COMMAND ${TEST_CLEAR_REPOS_CMD}
    )
    set_tests_properties(tests_clear_repos PROPERTIES FIXTURES_CLEANUP tests_cleanup)
    add_test(NAME tests_clear_shm
        COMMAND ${TEST_CLEAR_SHM_CMD}
    )
    set_tests_properties(tests_clear_shm PROPERTIES FIXTURES_CLEANUP tests_cleanup)
endif()

if(ENABLE_TESTS)
    # format
    if(${SOURCE_FORMAT_ENABLED})
        add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND cmake --build ${CMAKE_BINARY_DIR} --target format-check)
    endif()

    # lists of all the tests
    set(tests test_modules test_context_change test_validation test_edit test_candidate test_oper_pull test_oper_push
        test_lock test_apply_changes test_copy_config test_rpc_action test_notif test_get test_process
        test_multi_connection test_nacm test_rotation test_sub_notif)

    foreach(test_name IN LISTS tests)
        add_executable(${test_name} ${test_sources} ${test_name}.c)
    endforeach()

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

        # avoid loading installed plugins by sysrepo-plugind
        if(${test_name} STREQUAL "test_rotation")
            set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
                "SRPD_PLUGINS_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}/testing")
        endif()

        if(${CMAKE_VERSION} VERSION_GREATER "3.7")
            set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
        endif()
    endforeach()
endif()

# sr_perf benchmark binary
if(ENABLE_PERF_TESTS)
    add_executable(sr_perf ${CMAKE_CURRENT_SOURCE_DIR}/perf.c)
    target_link_libraries(sr_perf sysrepo)

    add_test(NAME sr_perf_1000 COMMAND sr_perf 1000 10)
    add_test(NAME sr_perf_100000 COMMAND sr_perf 100000 3)
endif()

# valgrind tests
if(ENABLE_VALGRIND_TESTS)
    foreach(test_name IN LISTS tests)
        add_test(NAME ${test_name}_valgrind COMMAND valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1 ${CMAKE_BINARY_DIR}/tests/${test_name})
        set(test_name "${test_name}_valgrind")
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
            "SYSREPO_REPOSITORY_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}"
            "SYSREPO_SHM_PREFIX=_tests_sr_${test_name}"
        )

        # avoid loading installed plugins by sysrepo-plugind
        if(${test_name} STREQUAL "test_rotation_valgrind")
            set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
                "SRPD_PLUGINS_PATH=${PROJECT_BINARY_DIR}/test_repositories/${test_name}/testing")
        endif()

        if(${CMAKE_VERSION} VERSION_GREATER "3.7")
            set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED tests_cleanup)
        endif()
    endforeach()
endif()

# phony target for clearing all sysrepo test data
add_custom_target(test_clean
    COMMAND ${TEST_CLEAR_REPOS_CMD}
    COMMAND ${TEST_CLEAR_SHM_CMD}
)
