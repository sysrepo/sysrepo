include_directories("${PROJECT_SOURCE_DIR}/inc")
include_directories("${PROJECT_SOURCE_DIR}/src")

add_executable(ex1 ex1.c)

target_link_libraries(ex1 sysrepo)
