include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(examples cpp_get_item_example cpp_set_item_example cpp_get_items_example cpp_get_data_example cpp_delete_item_example cpp_application_example cpp_application_changes_example cpp_rpc_example cpp_turing_rpc_example cpp_oper_data_example cpp_notif_example cpp_module_info)

foreach(example IN LISTS examples)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} sysrepo-cpp)
endforeach(example)
