#  YANG_FOUND - System has libyang
#  YANG_INCLUDE_DIRS - The libyang include directories
#  YANG_LIBRARIES - The libraries needed to use libyang
#  YANG_DEFINITIONS - Compiler switches required for using libyang

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_YANG QUIET yang)
    set(YANG_DEFINITIONS ${PC_YANG_CFLAGS_OTHER})
endif()

find_path(YANG_INCLUDE_DIR libyang/libyang.h
          HINTS ${PC_YANG_INCLUDEDIR} ${PC_YANG_INCLUDE_DIRS}
          PATH_SUFFIXES yang)

find_library(YANG_LIBRARY NAMES yang 
             HINTS ${PC_YANG_LIBDIR} ${PC_YANG_LIBRARY_DIRS})

set(YANG_LIBRARIES ${YANG_LIBRARY} )
set(YANG_INCLUDE_DIRS ${YANG_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(yang  DEFAULT_MSG
                                  YANG_LIBRARY YANG_INCLUDE_DIR)

mark_as_advanced(YANG_INCLUDE_DIR YANG_LIBRARY)
