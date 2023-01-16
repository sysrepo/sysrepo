if(NOT SYSREPO_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# list of all the examples
set(examples application_changes_example sr_set_item_example sr_get_items_example notif_subscribe_example
    notif_send_example rpc_send_example rpc_subscribe_example oper_data_pull_example oper_data_push_example
    oper_pull_push_example oper_data_poll_example)

foreach(app_name IN LISTS examples)
    add_executable(${app_name} ${app_name}.c)
    target_link_libraries(${app_name} sysrepo)
endforeach(app_name)

# oven plugin
add_library(oven MODULE plugin/oven.c)
set_target_properties(oven PROPERTIES PREFIX "")
target_link_libraries(oven sysrepo)
