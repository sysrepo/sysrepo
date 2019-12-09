set(PYTHON_SWIG_BINDING sysrepo)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(../cpp/src/)
set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
set(CMAKE_SWIG_FLAGS "-threads")
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})
set(PYTHON_SWIG_MIN_VERSION "3.0.5")

find_package(SWIG ${PYTHON_SWIG_MIN_VERSION})
if (NOT SWIG_FOUND)
  message(WARNING "Minimum SWIG version for Python is ${PYTHON_SWIG_MIN_VERSION}. Tests won't be generated.")
endif()

set_source_files_properties(${PYTHON_SWIG_BINDING}.i PROPERTIES CPLUSPLUS ON)

if(${CMAKE_VERSION} VERSION_LESS "3.8.0")
    swig_add_module(${PYTHON_SWIG_BINDING} python ${PYTHON_SWIG_BINDING}.i)
else()
    swig_add_library(${PYTHON_SWIG_BINDING} LANGUAGE python SOURCES ${PYTHON_SWIG_BINDING}.i)
endif()
swig_link_libraries(${PYTHON_SWIG_BINDING} ${PYTHON_LIBRARIES} Sysrepo-cpp)

execute_process(COMMAND
    ${PYTHON_EXECUTABLE} -c
    "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
OUTPUT_VARIABLE PYTHON_MODULE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)

install( FILES "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING}.so" DESTINATION ${PYTHON_MODULE_PATH} )
install( FILES "${CMAKE_CURRENT_BINARY_DIR}/${PYTHON_SWIG_BINDING}.py" DESTINATION ${PYTHON_MODULE_PATH} )

