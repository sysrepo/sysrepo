include_directories("${PROJECT_SOURCE_DIR}/inc")

# turing-machine plugin
add_library(turing-machine SHARED turing-machine.c)
target_link_libraries(turing-machine sysrepo)

# oven plugin
add_library(oven SHARED oven.c)
target_link_libraries(oven sysrepo)

install(TARGETS turing-machine DESTINATION ${PLUGINS_DIR})
