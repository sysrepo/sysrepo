include_directories("${PROJECT_SOURCE_DIR}/inc")

add_subdirectory(plugins)

add_executable(sr_get_item_example sr_get_item_example.c)
add_executable(sr_get_items_example sr_get_items_example.c)
add_executable(sr_get_items_iter_example sr_get_items_iter_example.c)
add_executable(sr_set_item_example sr_set_item_example.c)
add_executable(sr_delete_item_example sr_delete_item_example.c)
add_executable(sr_get_changes_iter_example sr_get_changes_iter_example.c)
add_executable(application_example application_example.c)
add_executable(application_changes_example application_changes_example.c)
add_executable(application_fd_watcher_example application_fd_watcher_example.c)
add_executable(oper_data_example oper_data_example.c)

target_link_libraries(sr_get_item_example sysrepo)
target_link_libraries(sr_get_items_example sysrepo)
target_link_libraries(sr_get_items_iter_example sysrepo)
target_link_libraries(sr_set_item_example sysrepo)
target_link_libraries(sr_delete_item_example sysrepo)
target_link_libraries(sr_get_changes_iter_example sysrepo)
target_link_libraries(application_example sysrepo)
target_link_libraries(application_changes_example sysrepo)
target_link_libraries(application_fd_watcher_example sysrepo)
target_link_libraries(oper_data_example sysrepo)

macro(EXEC_AT_INSTALL_TIME CMD)
    install(CODE "message(STATUS \"Exec: ${CMD}\")
        execute_process(COMMAND ${CMD} OUTPUT_QUIET RESULT_VARIABLE ret)
        if (NOT \${ret} EQUAL 0)
          message(FATAL_ERROR \"Error: \${ret}\")
        endif()"
        )
endmacro()

macro(INSTALL_EXAMPLE_YANG MODULE_NAME REVISION)
    # install the YANG module
    EXEC_AT_INSTALL_TIME("${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}${REVISION}.yang --permissions=666")
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}.data.xml)
        # import data into module
        EXEC_AT_INSTALL_TIME("${CMAKE_BINARY_DIR}/src/sysrepocfg --import=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}.data.xml --datastore=startup --format=xml --level=0 ${MODULE_NAME}")
    endif()
endmacro(INSTALL_EXAMPLE_YANG)

INSTALL_EXAMPLE_YANG("turing-machine" "")
INSTALL_EXAMPLE_YANG("iana-if-type" "")
INSTALL_EXAMPLE_YANG("ietf-ip" "@2014-06-16")
INSTALL_EXAMPLE_YANG("ietf-interfaces" "@2014-05-08")
