include_directories("${PROJECT_SOURCE_DIR}/inc")

add_executable(sr_get_item_example sr_get_item_example.c)
add_executable(sr_get_items_example sr_get_items_example.c)
add_executable(sr_get_items_iter_example sr_get_items_iter_example.c)
add_executable(sr_set_item_example sr_set_item_example.c)
add_executable(sr_delete_item_example sr_delete_item_example.c)
add_executable(application_example application_example.c)

target_link_libraries(sr_get_item_example sysrepo)
target_link_libraries(sr_get_items_example sysrepo)
target_link_libraries(sr_get_items_iter_example sysrepo)
target_link_libraries(sr_set_item_example sysrepo)
target_link_libraries(sr_delete_item_example sysrepo)
target_link_libraries(application_example sysrepo)

macro(INSTALL_EXAMPLE_YANG MODULE_NAME REVISION)
    # install the YANG module
    set(CMD "${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}${REVISION}.yang")
    install(CODE "execute_process(COMMAND ${CMD} OUTPUT_QUIET)")
    # import data into module
    set(CMD "${CMAKE_BINARY_DIR}/src/sysrepoctl --import=xml --module=${MODULE_NAME}")
    install(CODE "execute_process(COMMAND ${CMD} OUTPUT_QUIET INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/yang/${MODULE_NAME}.data.xml)")
endmacro(INSTALL_EXAMPLE_YANG)

INSTALL_EXAMPLE_YANG("turing-machine" "")
INSTALL_EXAMPLE_YANG("iana-if-type" "")
INSTALL_EXAMPLE_YANG("ietf-ip" "@2014-06-16")
INSTALL_EXAMPLE_YANG("ietf-interfaces" "@2014-05-08")
