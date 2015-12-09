#  SYSREPO_FOUND - System has SYSREPO
#  SYSREPO_INCLUDE_DIRS - The SYSREPO include directories
#  SYSREPO_LIBRARIES - The libraries needed to use SYSREPO
#  SYSREPO_DEFINITIONS - Compiler switches required for using SYSREPO

find_package(PkgConfig)
pkg_check_modules(PC_SYSREPO QUIET sysrepo)
set(SYSREPO_DEFINITIONS ${PC_SYSREPO_CFLAGS_OTHER})

find_path(SYSREPO_INCLUDE_DIR libisysrepo.h
          HINTS ${PC_SYSREPO_INCLUDEDIR} ${PC_SYSREPO_INCLUDE_DIRS}
          PATH_SUFFIXES sysrepo )

find_library(SYSREPO_LIBRARY NAMES sysrepo 
             HINTS ${PC_SYSREPO_LIBDIR} ${PC_SYSREPO_LIBRARY_DIRS} )

set(SYSREPO_LIBRARIES ${SYSREPO_LIBRARY} )
set(SYSREPO_INCLUDE_DIRS ${SYSREPO_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SYSREPO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(sysrepo  DEFAULT_MSG
                                  SYSREPO_LIBRARY SYSREPO_INCLUDE_DIR)

mark_as_advanced(SYSREPO_INCLUDE_DIR SYSREPO_LIBRARY )
