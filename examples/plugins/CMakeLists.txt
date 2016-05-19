include_directories("${PROJECT_SOURCE_DIR}/inc")

# turing-machine plugin
add_library(turing-machine SHARED turing-machine.c)
target_link_libraries(turing-machine sysrepo)

# plugins should be installed into ${PLUGINS_DIR}
# (default is "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/")
install(TARGETS turing-machine DESTINATION ${PLUGINS_DIR})
