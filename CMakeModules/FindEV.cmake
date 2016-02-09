#  EV_FOUND - System has libev
#  EV_INCLUDE_DIRS - The libev include directories
#  EV_LIBRARIES - The libraries needed to use libev
#  EV_DEFINITIONS - Compiler switches required for using libev

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_EV QUIET ev)
    set(EV_DEFINITIONS ${PC_EV_CFLAGS_OTHER})
endif()

find_path(EV_INCLUDE_DIR ev.h
          HINTS ${PC_EV_INCLUDEDIR} ${PC_EV_INCLUDE_DIRS}
          PATH_SUFFIXES ev)

find_library(EV_LIBRARY NAMES ev
             HINTS ${PC_EV_LIBDIR} ${PC_EV_LIBRARY_DIRS})

set(EV_LIBRARIES ${EV_LIBRARY})
set(EV_INCLUDE_DIRS ${EV_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ev DEFAULT_MSG
                                  EV_LIBRARY EV_INCLUDE_DIR)

mark_as_advanced(EV_INCLUDE_DIR EV_LIBRARY)
