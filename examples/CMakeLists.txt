include_directories("${PROJECT_SOURCE_DIR}/inc")
include_directories("${PROJECT_SOURCE_DIR}/src")

add_executable(sr_get_item_example sr_get_item_example.c)

target_link_libraries(sr_get_item_example sysrepo)
