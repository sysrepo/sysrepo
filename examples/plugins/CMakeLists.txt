include_directories("${PROJECT_SOURCE_DIR}/inc")

# turing-machine plugin
add_library(turing-machine SHARED turing-machine.c)
target_link_libraries(turing-machine sysrepo)

install(TARGETS turing-machine DESTINATION ${PLUGINS_DIR})
