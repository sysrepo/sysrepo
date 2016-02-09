#  AVL_FOUND - System has libavl
#  AVL_INCLUDE_DIRS - The libavl include directories
#  AVL_LIBRARIES - The libraries needed to use libavl
#  AVL_DEFINITIONS - Compiler switches required for using libavl

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_AVL QUIET avl)
    set(AVL_DEFINITIONS ${PC_AVL_CFLAGS_OTHER})
endif()

find_path(AVL_INCLUDE_DIR avl.h
          HINTS ${PC_AVL_INCLUDEDIR} ${PC_AVL_INCLUDE_DIRS}
          PATH_SUFFIXES avl)

find_library(AVL_LIBRARY NAMES avl
             HINTS ${PC_AVL_LIBDIR} ${PC_AVL_LIBRARY_DIRS})

set(AVL_LIBRARIES ${AVL_LIBRARY})
set(AVL_INCLUDE_DIRS ${AVL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(avl DEFAULT_MSG
                                  AVL_LIBRARY AVL_INCLUDE_DIR)

mark_as_advanced(AVL_INCLUDE_DIR AVL_LIBRARY)
