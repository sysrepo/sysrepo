set(JAVA_TEST_DIR ${CMAKE_SWIG_OUTDIR}/tests)
set(JUNIT_JAR ${JAVA_TEST_DIR}/junit.jar)
set(JAVA_TEST_SRC
  Changes
  Operations)

add_custom_target("java_tests")

foreach(JTEST ${JAVA_TEST_SRC})

  add_custom_command(TARGET "java_tests"
    COMMAND
    ${Java_JAVAC_EXECUTABLE} -cp .:${NATIVE_JAR}:${JUNIT_JAR} ${JAVA_TEST_DIR}/${JTEST}.java)

  add_test(NAME java_${JTEST}
    COMMAND ${Java_JAVA_EXECUTABLE}  -Djava.library.path=${CMAKE_SWIG_OUTDIR} -cp ..:.:${NATIVE_JAR}:${JUNIT_JAR} ${JTEST}
    WORKING_DIRECTORY ${JAVA_TEST_DIR})

endforeach()
