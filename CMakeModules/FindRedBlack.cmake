#  REDBLACK_FOUND - System has libredblack
#  REDBLACK_INCLUDE_DIRS - The libredblack include directories
#  REDBLACK_LIBRARIES - The libraries needed to use libredblack
#  REDBLACK_DEFINITIONS - Compiler switches required for using libredblack

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_REDBLACK QUIET redblack)
    set(REDBLACK_DEFINITIONS ${PC_REDBLACK_CFLAGS_OTHER})
endif()

find_path(REDBLACK_INCLUDE_DIR redblack.h
          HINTS ${PC_REDBLACK_INCLUDEDIR} ${PC_REDBLACK_INCLUDE_DIRS}
          PATH_SUFFIXES redblack)

find_library(REDBLACK_LIBRARY NAMES redblack
             HINTS ${PC_REDBLACK_LIBDIR} ${PC_REDBLACK_LIBRARY_DIRS})

set(REDBLACK_LIBRARIES ${REDBLACK_LIBRARY})
set(REDBLACK_INCLUDE_DIRS ${REDBLACK_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(redblack DEFAULT_MSG
                                  REDBLACK_LIBRARY REDBLACK_INCLUDE_DIR)

mark_as_advanced(REDBLACK_INCLUDE_DIR REDBLACK_LIBRARY)
