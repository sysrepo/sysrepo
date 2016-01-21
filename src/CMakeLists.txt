include_directories("${PROJECT_SOURCE_DIR}/inc")


#compile protobuf-c
set(PROTO_NAME sysrepo)
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.proto")
set(GENERATED_PROTO  "${PROTO_NAME}.pb-c.c")

get_filename_component(ABS_PATH ${PROTO_FILE} PATH)
add_custom_command(
    OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.pb-c.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.pb-c.h"
   COMMAND  ${PROTOBUFC_PROTOC_EXECUTABLE}
   ARGS --c_out  ${CMAKE_CURRENT_SOURCE_DIR} -I ${ABS_PATH} ${PROTO_FILE}
   DEPENDS ${PROTO_FILE}
   COMMENT "Running C protocol buffer compiler on ${PROTO_FILE}"
   VERBATIM )

add_custom_target(proto DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.pb-c.c)

configure_file("${PROJECT_SOURCE_DIR}/src/dm_location.h.in" "${PROJECT_SOURCE_DIR}/src/dm_location.h" ESCAPE_QUOTES @ONLY)

#setup library sources
set(SYSREPO-SOURCES
    ${GENERATED_PROTO}
    client_library.c
    sr_common.c
    sr_logger.c
)

set(SYSREPO-ENGINE-SOURCES
    ${GENERATED_PROTO}
    connection_manager.c
    session_manager.c
    request_processor.c
    rp_data_tree.c
    rp_node_stack.c
    data_manager.c
    xpath_processor.c
    sr_common.c
    sr_logger.c
)

set(HEADERS "${PROJECT_SOURCE_DIR}/inc/sysrepo.h")

#shared and static library
add_library(sysrepo ${SYSREPO-SOURCES})
add_library(sysrepo_so SHARED ${SYSREPO-SOURCES})
SET_TARGET_PROPERTIES(sysrepo_so PROPERTIES
              OUTPUT_NAME sysrepo CLEAN_DIRECT_OUTPUT 1)

add_library(sysrepo-engine ${SYSREPO-ENGINE-SOURCES})
add_library(sysrepo-engine_so SHARED ${SYSREPO-ENGINE-SOURCES})
SET_TARGET_PROPERTIES(sysrepo-engine_so PROPERTIES
              OUTPUT_NAME sysrepo-engine CLEAN_DIRECT_OUTPUT 1)

set(LINK_LIBRARIES avl ev pthread protobuf-c yang)

target_link_libraries(sysrepo ${LINK_LIBRARIES} sysrepo-engine)
target_link_libraries(sysrepo_so ${LINK_LIBRARIES} sysrepo-engine_so)
target_link_libraries(sysrepo-engine ${LINK_LIBRARIES})
target_link_libraries(sysrepo-engine_so ${LINK_LIBRARIES})

install(TARGETS sysrepo_so DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepo-engine_so DESTINATION ${LIB_INSTALL_DIR})
install(FILES ${HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR})
