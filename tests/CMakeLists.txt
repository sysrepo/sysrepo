set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")
set(TEST_SCHEMA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/yang/")
set(TEST_DATA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/data/")
set(TEST_INTERNAL_SCHEMA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/yang/internal/")
set(TEST_INTERNAL_DATA_SEARCH_DIR "${TEST_REPOSITORY_LOC}/data/internal/")

set(TEST_HELPERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/helpers/")
set(TEST_HELPERS_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/helpers/")

CHECK_INCLUDE_FILES(regex.h HAVE_REGEX_H)

configure_file("${TEST_HELPERS_DIR}/test_data.h.in" "${TEST_HELPERS_BIN_DIR}/test_data.h" ESCAPE_QUOTES @ONLY)

include_directories (
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/clientlib"
    "${PROJECT_SOURCE_DIR}/src/common"
    "${PROJECT_BINARY_DIR}/src/common"
    "${PROJECT_SOURCE_DIR}/inc"
    "${TEST_HELPERS_DIR}"
    "${TEST_HELPERS_BIN_DIR}"
)

find_program(valgrind_FOUND valgrind)
find_program(timeout_FOUND timeout)

add_library(HELPERS OBJECT ${TEST_HELPERS_DIR}rp_dt_context_helper.c
            ${TEST_HELPERS_DIR}test_module_helper.c
            ${TEST_HELPERS_DIR}system_helper.c
            ${TEST_HELPERS_DIR}nacm_module_helper.c)
add_dependencies(HELPERS COMMON)

# create test target with specified options
macro(ADD_UNIT_TEST_WITH_OPTS TEST_NAME USE_HELPERS USE_VALGRIND WRAP_FUNCTION)
    if ("${WRAP_FUNCTION}" STREQUAL "")
        set(test_link_flags "")
    else()
        set(test_link_flags "-Wl,--wrap,${WRAP_FUNCTION}")
    endif()
    if(${USE_HELPERS})
        add_executable(${TEST_NAME} ${TEST_NAME}.c $<TARGET_OBJECTS:HELPERS>)
    else()
        add_executable(${TEST_NAME} ${TEST_NAME}.c)
    endif()

    target_link_libraries(${TEST_NAME} ${CMOCKA_LIBRARIES} sysrepo_a ${test_link_flags})
    if(timeout_FOUND AND NOT ${CMAKE_C_FLAGS} MATCHES "-fsanitize")
        add_test(${TEST_NAME} timeout
            --signal=6 360
            ./${TEST_NAME})
    else()
        add_test(${TEST_NAME} ${TEST_NAME})
    endif()
    if(valgrind_FOUND AND ${USE_VALGRIND} AND NOT ${CMAKE_C_FLAGS} MATCHES "-fsanitize")
        add_test(${TEST_NAME}_valgrind valgrind
            --error-exitcode=1 --read-var-info=yes
            --leak-check=full --show-leak-kinds=all
            --num-callers=20
            --suppressions=${TEST_HELPERS_DIR}valgrind.supp
            ./${TEST_NAME})
    endif()
    add_dependencies(${TEST_NAME} COMMON)
endmacro(ADD_UNIT_TEST_WITH_OPTS)

# create default test target with valgrind is on
macro(ADD_UNIT_TEST TEST_NAME USE_HELPERS)
    ADD_UNIT_TEST_WITH_OPTS(${TEST_NAME} ${USE_HELPERS} "1" "")
endmacro(ADD_UNIT_TEST)


ADD_UNIT_TEST(common_test 1)
ADD_UNIT_TEST(xpath_utils_test 1)
ADD_UNIT_TEST(ac_test 1)
if(USE_SR_MEM_MGMT)
    ADD_UNIT_TEST(mem_mgmt_test 1)
endif(USE_SR_MEM_MGMT)
ADD_UNIT_TEST(values_test 1)
ADD_UNIT_TEST(trees_test 1)

ADD_UNIT_TEST(cm_sm_test 1)
IF (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    ADD_UNIT_TEST_WITH_OPTS(np_test 1 1 "cm_msg_send")
    ADD_UNIT_TEST_WITH_OPTS(pm_test 1 1 "cm_msg_send")
ENDIF()

ADD_UNIT_TEST(dm_test 1)

ADD_UNIT_TEST(rp_dt_xpath_test 1)
ADD_UNIT_TEST(rp_datatree_test 1)
ADD_UNIT_TEST(rp_dt_edit_test 1)
ADD_UNIT_TEST(rp_dt_running_test 1)

ADD_UNIT_TEST(md_test 1)

if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}")
    # end-to-end tests that work only if test repository location equals to
    # global procject's repository location

    ADD_UNIT_TEST(cm_test 1)
    ADD_UNIT_TEST(rp_test 1)
    if(ENABLE_NACM)
        ADD_UNIT_TEST(nacm_test 1)
    endif(ENABLE_NACM)

    ADD_UNIT_TEST(cl_test 1)
    ADD_UNIT_TEST(cl_test2 1)
    ADD_UNIT_TEST(cl_notifications_test 1)
    ADD_UNIT_TEST(cl_state_data_test 1)
    ADD_UNIT_TEST(cl_fd_watcher_test 1)
    if(ENABLE_NACM)
        ADD_UNIT_TEST(nacm_cl_test 1)
    endif(ENABLE_NACM)
    ADD_UNIT_TEST(concurr_test 1)
    ADD_UNIT_TEST_WITH_OPTS(perf_test 1 0 "")
    ADD_UNIT_TEST_WITH_OPTS(daemon_test 1 0 "")
    ADD_UNIT_TEST_WITH_OPTS(plugin_daemon_test 1 0 "")
    ADD_UNIT_TEST_WITH_OPTS(sysrepoctl_test 1 0 "")
    ADD_UNIT_TEST_WITH_OPTS(sysrepocfg_test 1 0 "")
    ADD_UNIT_TEST(rp_dt_edit_test_features 1)
    IF (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        ADD_UNIT_TEST_WITH_OPTS(np_test_store 1 1 "cm_msg_send")
    ENDIF()

    ADD_CUSTOM_COMMAND(
        TARGET sysrepocfg_test
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/sysrepocfg_test_editor.sh ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
    )

    add_executable(measure_perf measure_performance.c ${TEST_HELPERS_DIR}test_module_helper.c)
    target_link_libraries(measure_perf ${CMOCKA_LIBRARIES} sysrepo_a)
    add_executable(subscription_test_app subscription_test_app.c)
    target_link_libraries(subscription_test_app ${CMOCKA_LIBRARIES} sysrepo_a)
    add_executable(notifications_test_app notifications_test_app.c)
    target_link_libraries(notifications_test_app ${CMOCKA_LIBRARIES} sysrepo_a)

else()
    message(STATUS "Test repostory location differs to system repository location, some tests will be disabled.")
endif()


# create test repository directories and copy internal schemas
add_custom_target(create_internals
    COMMAND mkdir -p "${TEST_SCHEMA_SEARCH_DIR}" "${TEST_DATA_SEARCH_DIR}" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}" "${TEST_INTERNAL_DATA_SEARCH_DIR}"
    COMMAND cp "${PROJECT_SOURCE_DIR}/yang/sysrepo-persistent-data.yang" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
    COMMAND cp "${PROJECT_SOURCE_DIR}/yang/sysrepo-module-dependencies.yang" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
    COMMAND cp "${PROJECT_SOURCE_DIR}/yang/sysrepo-notification-store.yang" "${TEST_INTERNAL_SCHEMA_SEARCH_DIR}"
)

# make common_test depend on sysrepoctl
add_dependencies(common_test create_internals sysrepoctl)

# install testing YANG modules
macro(INSTALL_YANG_FOR_TESTS MODULE_NAME)
    ADD_CUSTOM_COMMAND(
        TARGET common_test
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}.yang -0 ${TEST_REPOSITORY_LOC} > /dev/null
        VERBATIM
    )
endmacro(INSTALL_YANG_FOR_TESTS)

macro(ENABLE_FEATURE_FOR_TESTS MODULE_NAME FEATURE_NAME)
    ADD_CUSTOM_COMMAND(
        TARGET common_test
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --feature-enable ${FEATURE_NAME} --module ${MODULE_NAME} -0 ${TEST_REPOSITORY_LOC} > /dev/null
        VERBATIM
    )
endmacro(ENABLE_FEATURE_FOR_TESTS)

if(ENABLE_NACM)
    INSTALL_YANG_FOR_TESTS("ietf-netconf-acm@2018-02-14")
endif(ENABLE_NACM)
INSTALL_YANG_FOR_TESTS("example-module")
INSTALL_YANG_FOR_TESTS("test-module")
INSTALL_YANG_FOR_TESTS("small-module")
INSTALL_YANG_FOR_TESTS("info-module")
INSTALL_YANG_FOR_TESTS("id-ref-aug")
INSTALL_YANG_FOR_TESTS("id-ref-hello")
INSTALL_YANG_FOR_TESTS("id-def-extended")
INSTALL_YANG_FOR_TESTS("id-ref-main")
INSTALL_YANG_FOR_TESTS("id-ref-installed")
INSTALL_YANG_FOR_TESTS("augm_leafref_m1")
INSTALL_YANG_FOR_TESTS("module-a@2016-02-10")
INSTALL_YANG_FOR_TESTS("module-b@2016-02-05")
INSTALL_YANG_FOR_TESTS("ietf-interfaces@2014-05-08")
INSTALL_YANG_FOR_TESTS("iana-if-type")
INSTALL_YANG_FOR_TESTS("ietf-ip@2014-06-16")
INSTALL_YANG_FOR_TESTS("state-module@2016-07-01")
INSTALL_YANG_FOR_TESTS("top-level-mandatory")
INSTALL_YANG_FOR_TESTS("referenced-data")
INSTALL_YANG_FOR_TESTS("cross-module")
INSTALL_YANG_FOR_TESTS("turing-machine")
INSTALL_YANG_FOR_TESTS("ietf-netconf-notifications")
INSTALL_YANG_FOR_TESTS("nc-notifications")
INSTALL_YANG_FOR_TESTS("servers")
INSTALL_YANG_FOR_TESTS("commit-nacm")


# dummy testing plugins
add_library(dummy-plugin-1 SHARED ${TEST_HELPERS_DIR}dummy_plugin.c)
target_link_libraries(dummy-plugin-1 sysrepo)

add_library(dummy-plugin-2 SHARED ${TEST_HELPERS_DIR}dummy_plugin.c)
target_link_libraries(dummy-plugin-2 sysrepo)
