project(sysrepo-cpp)

set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wpedantic -std=c++11 -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -O0")

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(SYSREPO_CPP_MAJOR_SOVERSION 4)
set(SYSREPO_CPP_MINOR_SOVERSION 0)
set(SYSREPO_CPP_MICRO_SOVERSION 0)
set(SYSREPO_CPP_SOVERSION_FULL ${SYSREPO_MAJOR_SOVERSION}.${SYSREPO_MINOR_SOVERSION}.${SYSREPO_MICRO_SOVERSION})
set(SYSREPO_CPP_SOVERSION ${SYSREPO_MAJOR_SOVERSION})

set(SYSREPO_CPP_SOURCES
    src/Sysrepo.cpp
    src/Connection.cpp
    src/Session.cpp
    src/Struct.cpp
    src/Xpath.cpp
    src/Internal.cpp)

set(SYSREPO_HPP_SOURCES
    src/Sysrepo.hpp
    src/Connection.hpp
    src/Session.hpp
    src/Struct.hpp
    src/Xpath.hpp
    src/Internal.hpp)

add_library(sysrepo-cpp SHARED ${SYSREPO_CPP_SOURCES})
set_target_properties(sysrepo-cpp PROPERTIES VERSION ${SYSREPO_CPP_SOVERSION_FULL} SOVERSION ${SYSREPO_CPP_SOVERSION})

# dependencies
include_directories(${LIBYANG_CPP_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../src")
target_link_libraries(sysrepo-cpp sysrepo ${LIBYANG_CPP_LIBRARIES})

# install binary
install(TARGETS sysrepo-cpp DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${SYSREPO_HPP_SOURCES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sysrepo-cpp)

# generate and install pkg-config file
configure_file("sysrepo-cpp.pc.in" "sysrepo-cpp.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/sysrepo-cpp.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Examples
if(BUILD_CPP_EXAMPLES)
    add_subdirectory(examples)
endif()
