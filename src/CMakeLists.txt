include_directories("${PROJECT_SOURCE_DIR}/inc")
set(SYSREPO-SOURCES
     sr_access.c
     )

set(SYSREPO-ENGINE-SOURCES
     data_manager.c
     connection_manager.c
     xpath_processor.c
     sr_common.c
)

set(HEADERS "${PROJECT_SOURCE_DIR}/inc/sysrepo.h" "${PROJECT_SOURCE_DIR}/inc/sr_engine.h")

#shared and static library
add_library(sysrepo ${SYSREPO-SOURCES})
add_library(sysrepo_so SHARED ${SYSREPO-SOURCES})
SET_TARGET_PROPERTIES(sysrepo_so PROPERTIES
              OUTPUT_NAME sysrepo CLEAN_DIRECT_OUTPUT 1)

add_library(sysrepo-engine ${SYSREPO-ENGINE-SOURCES})
add_library(sysrepo-engine_so SHARED ${SYSREPO-ENGINE-SOURCES})
SET_TARGET_PROPERTIES(sysrepo-engine_so PROPERTIES
              OUTPUT_NAME sysrepo-engine CLEAN_DIRECT_OUTPUT 1)


install(TARGETS sysrepo DESTINATION ${LIB_INSTALL_DIR})
install(FILES ${HEADERS} DESTINATION ${INCLUDE_INSTALL_DIR})
