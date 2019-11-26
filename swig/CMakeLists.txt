set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11 -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")

project(Sysrepo-cpp)

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(SYSREPO_CPP_MAJOR_SOVERSION 2)
set(SYSREPO_CPP_MINOR_SOVERSION 2)
set(SYSREPO_CPP_MICRO_SOVERSION 0)
set(SYSREPO_CPP_SOVERSION_FULL ${SYSREPO_MAJOR_SOVERSION}.${SYSREPO_MINOR_SOVERSION}.${SYSREPO_MICRO_SOVERSION})
set(SYSREPO_CPP_SOVERSION ${SYSREPO_MAJOR_SOVERSION})

set(SYSREPO_CPP_SOURCES
    cpp/src/Sysrepo.cpp
    cpp/src/Connection.cpp
    cpp/src/Session.cpp
    cpp/src/Struct.cpp
    cpp/src/Xpath.cpp
    cpp/src/Internal.cpp)

set(SYSREPO_HPP_SOURCES
    cpp/src/Sysrepo.hpp
    cpp/src/Connection.hpp
    cpp/src/Session.hpp
    cpp/src/Struct.hpp
    cpp/src/Xpath.hpp
    cpp/src/Internal.hpp)

add_library(Sysrepo-cpp SHARED ${SYSREPO_CPP_SOURCES})
set_target_properties(Sysrepo-cpp PROPERTIES VERSION ${SYSREPO_CPP_SOVERSION_FULL} SOVERSION ${SYSREPO_CPP_SOVERSION})

# dependencies
include_directories(${LIBYANG_CPP_INCLUDE_DIRS})
target_link_libraries(Sysrepo-cpp ${LIBYANG_CPP_LIBRARIES})

include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(Sysrepo-cpp sysrepo)

# install binary
install(TARGETS Sysrepo-cpp DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${SYSREPO_HPP_SOURCES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo-cpp)

# generate and install pkg-config file
configure_file("cpp/libSysrepo-cpp.pc.in" "libSysrepo-cpp.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libSysrepo-cpp.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Examples
if(BUILD_CPP_EXAMPLES)
    add_subdirectory(cpp/examples)
endif()
