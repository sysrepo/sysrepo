set(JAVA_SWIG_BINDING libsysrepoJava)
include(UseJava)
include(UseSWIG)

include(${SWIG_USE_FILE})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${JAVA_INCLUDE_PATH})
include_directories("${JAVA_INCLUDE_PATH}/linux")
include_directories(${JAVA_INCLUDE_DIRS})

set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}")
set(CMAKE_SWIG_OUTDIR "${CMAKE_CURRENT_BINARY_DIR}")

set_source_files_properties(${JAVA_SWIG_BINDING}.i PROPERTIES CPLUSPLUS ON SWIG_FLAGS "-package;org.sysrepo")

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/org/sysrepo")

swig_add_module(${JAVA_SWIG_BINDING} java ${JAVA_SWIG_BINDING}.i)
set_target_properties(${SWIG_MODULE_${JAVA_SWIG_BINDING}_REAL_NAME} PROPERTIES PREFIX "")
swig_link_libraries(${JAVA_SWIG_BINDING} ${JAVA_LIBRARIES} Sysrepo-cpp)

file(COPY "examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

add_custom_command(TARGET ${JAVA_SWIG_BINDING} POST_BUILD COMMAND "${Java_JAVAC_EXECUTABLE}" *.java -d . COMMAND "${Java_JAR_EXECUTABLE}" -cvf Sysrepo.jar org)
set(NATIVE_JAR "${CMAKE_CURRENT_BINARY_DIR}/Sysrepo.jar")

# install so file
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${JAVA_SWIG_BINDING}.so" DESTINATION "${CMAKE_INSTALL_LIBDIR}")

add_custom_command(TARGET ${JAVA_SWIG_BINDING} POST_BUILD
  COMMAND ${Java_JAVAC_EXECUTABLE} -cp .:${NATIVE_JAR} ${CMAKE_SWIG_OUTDIR}/examples/javaApplicationExample.java
  COMMAND ${Java_JAVAC_EXECUTABLE} -cp .:${NATIVE_JAR} ${CMAKE_SWIG_OUTDIR}/examples/javaApplicationChangesExample.java
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# testing
if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}" AND ENABLE_TESTS)
    set(JAVA_TEST_MODULE "swig-test")
    set(JAVA_TEST_MODULE_REV "2017-03-09")
    set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")
    set(JAVA_SWIG_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(JAVA_TEST_DIR ${JAVA_SWIG_DIR}/tests)
    set(JAVA_YANG_DIR ${JAVA_TEST_DIR}/yang)

    ADD_CUSTOM_COMMAND(
       TARGET libsysrepoJava
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${JAVA_YANG_DIR}/${JAVA_TEST_MODULE}@${JAVA_TEST_MODULE_REV}.yang # -0 ${TEST_REPOSITORY_LOC} > /dev/null
        VERBATIM)

  file(COPY "tests" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  add_subdirectory(tests)
endif()
