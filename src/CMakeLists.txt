set(CLIENTLIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/clientlib")
set(COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/common")
set(COMMON_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/common")
set(EXECUTABLES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/executables")
set(UTILS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/utils")

include_directories(
    "${PROJECT_SOURCE_DIR}/inc" 
    "${CMAKE_CURRENT_SOURCE_DIR}" 
    "${CLIENTLIB_DIR}" 
    "${COMMON_DIR}" 
    "${COMMON_BIN_DIR}"
    "${EXECUTABLES_DIR}" 
    "${UTILS_DIR}"
)

#compile protobuf-c
set(PROTO_NAME sysrepo)
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_NAME}.proto")
set(GENERATED_PROTO_H "${COMMON_BIN_DIR}/${PROTO_NAME}.pb-c.h")
set(GENERATED_PROTO_C "${COMMON_BIN_DIR}/${PROTO_NAME}.pb-c.c")

get_filename_component(ABS_PATH ${PROTO_FILE} PATH)
add_custom_command(
    OUTPUT "${GENERATED_PROTO_C}"
           "${GENERATED_PROTO_H}"
   COMMAND  ${PROTOBUFC_PROTOC_EXECUTABLE}
   ARGS --c_out ${COMMON_BIN_DIR} -I ${ABS_PATH} ${PROTO_FILE}
   DEPENDS ${PROTO_FILE}
   COMMENT "Running C protocol buffer compiler on ${PROTO_FILE}"
   VERBATIM )

add_custom_target(proto DEPENDS "${GENERATED_PROTO_C}" "${GENERATED_PROTO_H}")

configure_file("${COMMON_DIR}/sr_constants.h.in" "${COMMON_BIN_DIR}/sr_constants.h" ESCAPE_QUOTES @ONLY)

# common sources
set (COMMON_SOURCES
    ${GENERATED_PROTO_C}
    ${COMMON_DIR}/sr_common.c
    ${COMMON_DIR}/sr_utils.c
    ${COMMON_DIR}/sr_data_structs.c
    ${COMMON_DIR}/sr_logger.c
    ${COMMON_DIR}/sr_protobuf.c
    ${COMMON_DIR}/sr_mem_mgmt.c
    ${UTILS_DIR}/plugins.c
    ${UTILS_DIR}/trees.c
    ${UTILS_DIR}/values.c
    ${UTILS_DIR}/xpath.c
)

# client library sources
set(SYSREPO_SOURCES
    ${CLIENTLIB_DIR}/client_library.c
    ${CLIENTLIB_DIR}/cl_subscription_manager.c
    ${CLIENTLIB_DIR}/cl_common.c
    ${CLIENTLIB_DIR}/cl_trees.c
)

# sysrepo engine sources
set(SYSREPO_ENGINE_SOURCES
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
    module_dependencies.c
)

add_library(COMMON OBJECT ${COMMON_SOURCES})
set_property(TARGET COMMON PROPERTY COMPILE_FLAGS "-fPIC")

add_library(SR_SRC OBJECT  ${SYSREPO_SOURCES})
set_property(TARGET SR_SRC PROPERTY COMPILE_FLAGS "-fPIC")

add_library(SR_ENGINE OBJECT  ${SYSREPO_ENGINE_SOURCES})
set_property(TARGET SR_ENGINE PROPERTY COMPILE_FLAGS "-fPIC")

add_dependencies(COMMON proto)
add_dependencies(SR_SRC COMMON)
add_dependencies(SR_ENGINE COMMON)

if(USE_AVL_LIB)
    set(LINK_LIBRARIES pthread ${AVL_LIBRARIES} ${EV_LIBRARIES} ${PROTOBUF-C_LIBRARIES} ${YANG_LIBRARIES})
else(USE_AVL_LIB)
    set(LINK_LIBRARIES pthread ${REDBLACK_LIBRARIES} ${EV_LIBRARIES} ${PROTOBUF-C_LIBRARIES} ${YANG_LIBRARIES})
endif(USE_AVL_LIB)

#handle rt library that doesn't exist on OS X
if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(LINK_LIBRARIES rt ${LINK_LIBRARIES})
endif()

# sysrepo library
add_library(sysrepo SHARED $<TARGET_OBJECTS:COMMON> $<TARGET_OBJECTS:SR_SRC>)
add_library(sysrepo_a $<TARGET_OBJECTS:COMMON> $<TARGET_OBJECTS:SR_SRC>)
SET_TARGET_PROPERTIES(sysrepo_a PROPERTIES
              OUTPUT_NAME sysrepo CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(sysrepo ${LINK_LIBRARIES} sysrepo-engine)
target_link_libraries(sysrepo_a ${LINK_LIBRARIES} sysrepo-engine_a)

# sysrepo-engine library
add_library(sysrepo-engine SHARED $<TARGET_OBJECTS:COMMON> $<TARGET_OBJECTS:SR_ENGINE>)
add_library(sysrepo-engine_a $<TARGET_OBJECTS:COMMON> $<TARGET_OBJECTS:SR_ENGINE>)
SET_TARGET_PROPERTIES(sysrepo-engine_a PROPERTIES
              OUTPUT_NAME sysrepo-engine CLEAN_DIRECT_OUTPUT 1)
target_link_libraries(sysrepo-engine_a ${LINK_LIBRARIES})
target_link_libraries(sysrepo-engine ${LINK_LIBRARIES})

# sysrepo daemon
add_executable(sysrepod ${EXECUTABLES_DIR}/sysrepod.c)
target_link_libraries(sysrepod sysrepo-engine)

# sysrepo plugin daemon
add_executable(sysrepo-plugind ${EXECUTABLES_DIR}/sysrepo-plugind.c)
target_link_libraries(sysrepo-plugind sysrepo ${EV_LIBRARIES} ${CMAKE_DL_LIBS})

# sysrepoctl tool
add_executable(sysrepoctl ${EXECUTABLES_DIR}/sysrepoctl.c)
target_link_libraries(sysrepoctl sysrepo ${YANG_LIBRARIES})

# sysrepocfg tool
add_executable(sysrepocfg ${EXECUTABLES_DIR}/sysrepocfg.c)
target_link_libraries(sysrepocfg sysrepo ${YANG_LIBRARIES})

install(TARGETS sysrepo DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepo_a DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepo-engine DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepo-engine_a DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS sysrepod DESTINATION ${BIN_INSTALL_DIR})
install(TARGETS sysrepo-plugind DESTINATION ${BIN_INSTALL_DIR})
install(TARGETS sysrepoctl DESTINATION ${BIN_INSTALL_DIR})
install(TARGETS sysrepocfg DESTINATION ${BIN_INSTALL_DIR})
install(DIRECTORY "${PROJECT_SOURCE_DIR}/inc/" DESTINATION ${INCLUDE_INSTALL_DIR})
