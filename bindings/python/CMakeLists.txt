set(PYTHON_SWIG_BINDING sysrepo)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../cpp/src")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
set(CMAKE_SWIG_FLAGS "-threads")
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})

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

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/_${PYTHON_SWIG_BINDING}.so" DESTINATION ${PYTHON_MODULE_PATH})
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PYTHON_SWIG_BINDING}.py" DESTINATION ${PYTHON_MODULE_PATH})

# tests
if(ENABLE_PYTHON_TESTS)
    macro(ADD_PYTHON_TEST TEST_NAME)
        add_test(NAME python_${TEST_NAME}
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/run_python_test.sh
            "${CMAKE_CURRENT_BINARY_DIR}:${PROJECT_SOURCE_DIR}/swig/python3:${PYTHON_BUILD_DIR}"
            "${PYTHON_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}/tests/${TEST_NAME}.py"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endmacro(ADD_PYTHON_TEST)

    ADD_PYTHON_TEST(SysrepoBasicTest)
endif()
