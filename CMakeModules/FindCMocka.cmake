#  CMOCKA_FOUND - System has CMocka
#  CMOCKA_INCLUDE_DIRS - The CMocka include directories
#  CMOCKA_LIBRARIES - The libraries needed to use CMocka
#  CMOCKA_DEFINITIONS - Compiler switches required for using CMocka

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_CMOCKA QUIET cmocka)
    set(CMOCKA_DEFINITIONS ${PC_CMOCKA_CFLAGS_OTHER})
endif()

find_path(CMOCKA_INCLUDE_DIR cmocka.h
          HINTS ${PC_CMOCKA_INCLUDEDIR} ${PC_CMOCKA_INCLUDE_DIRS}
          PATH_SUFFIXES cmocka)

find_library(CMOCKA_LIBRARY NAMES cmocka 
             HINTS ${PC_CMOCKA_LIBDIR} ${PC_CMOCKA_LIBRARY_DIRS})

set(CMOCKA_LIBRARIES ${CMOCKA_LIBRARY})
set(CMOCKA_INCLUDE_DIRS ${CMOCKA_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(cmocka  DEFAULT_MSG
                                  CMOCKA_LIBRARY CMOCKA_INCLUDE_DIR)

mark_as_advanced(CMOCKA_INCLUDE_DIR CMOCKA_LIBRARY)
