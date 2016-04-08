set(COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common")

include_directories("${PROJECT_SOURCE_DIR}/inc" "${CMAKE_CURRENT_SOURCE_DIR}" "${COMMON_DIR}")

#compile protobuf-c
set(PROTO_NAME sysrepo)
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.proto")
set(GENERATED_PROTO "${COMMON_DIR}/${PROTO_NAME}.pb-c.c")

get_filename_component(ABS_PATH ${PROTO_FILE} PATH)
add_custom_command(
    OUTPUT "${COMMON_DIR}/${PROTO_NAME}.pb-c.c"
    "${COMMON_DIR}/${PROTO_NAME}.pb-c.h"
   COMMAND  ${PROTOBUFC_PROTOC_EXECUTABLE}
   ARGS --c_out ${COMMON_DIR} -I ${ABS_PATH} ${PROTO_FILE}
   DEPENDS ${PROTO_FILE}
   COMMENT "Running C protocol buffer compiler on ${PROTO_FILE}"
   VERBATIM )

add_custom_target(proto DEPENDS ${COMMON_DIR}/${PROTO_NAME}.pb-c.c)

configure_file("${COMMON_DIR}/sr_constants.h.in" "${COMMON_DIR}/sr_constants.h" ESCAPE_QUOTES @ONLY)

# common sources
set (COMMON_SOURCES
    common/sr_common.c
    common/sr_btree.c
    common/sr_logger.c
)

# client library sources
set(SYSREPO_SOURCES
    ${COMMON_SOURCES}
    ${GENERATED_PROTO}
    client_library.c
    cl_subscription_manager.c
    cl_common.c
)

# sysrepo engine sources
set(SYSREPO_ENGINE_SOURCES
    ${COMMON_SOURCES}
    ${GENERATED_PROTO}
    access_control.c
    connection_manager.c
    cm_session_manager.c
    request_processor.c
    rp_dt_xpath.c
    rp_dt_lookup.c
    rp_dt_get.c
    rp_dt_edit.c
    data_manager.c
    notification_processor.c
    persistence_manager.c
)

set(HEADERS "${PROJECT_SOURCE_DIR}/inc/sysrepo.h")

if(USE_AVL_LIB)
    set(LINK_LIBRARIES pthread ${AVL_LIBRARIES} ${EV_LIBRARIES} ${PROTOBUF-C_LIBRARIES} ${YANG_LIBRARIES})
else(USE_AVL_LIB)
    set(LINK_LIBRARIES pthread ${REDBLACK_LIBRARIES} ${EV_LIBRARIES} ${PROTOBUF-C_LIBRARIES} ${YANG_LIBRARIES})
endif(USE_AVL_LIB)

# sysrepo library
add_library(sysrepo ${SYSREPO_SOURCES})
add_library(sysrepo_so SHARED ${SYSREPO_SOURCES})
SET_TARGET_PROPERTIES(sysrepo_so PROPERTIES
              OUTPUT_NAME sysrepo CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(sysrepo ${LINK_LIBRARIES} sysrepo-engine)
target_link_libraries(sysrepo_so ${LINK_LIBRARIES} sysrepo-engine_so)

# sysrepo-engine library
add_library(sysrepo-engine ${SYSREPO_ENGINE_SOURCES})
add_library(sysrepo-engine_so SHARED ${SYSREPO_ENGINE_SOURCES})
SET_TARGET_PROPERTIES(sysrepo-engine_so PROPERTIES
              OUTPUT_NAME sysrepo-engine CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(sysrepo-engine ${LINK_LIBRARIES})
target_link_libraries(sysrepo-engine_so ${LINK_LIBRARIES})

# sysrepo daemon
add_executable(sysrepod daemon.c)
target_link_libraries(sysrepod sysrepo-engine)

# sysrepo ctl tool
add_executable(sysrepoctl sysrepoctl.c)
target_link_libraries(sysrepoctl sysrepo ${YANG_LIBRARIES})

install(TARGETS sysrepo_so DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepo-engine_so DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepod DESTINATION ${BIN_INSTALL_DIR})
install(TARGETS sysrepoctl DESTINATION ${BIN_INSTALL_DIR})
install(FILES ${HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR})
