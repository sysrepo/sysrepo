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

#shared and static library
add_library(sysrepo ${SYSREPO-SOURCES})
add_library(sysrepo-engine ${SYSREPO-ENGINE-SOURCES})