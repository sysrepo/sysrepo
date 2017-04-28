include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(CPP_TEST_SRC
  changes
  operations)

macro(ADD_CPP_TEST TEST)
  set(TEST_NAME cpp_${TEST})
  add_executable(${TEST_NAME} ${TEST}.cpp)
  target_link_libraries(${TEST_NAME} Sysrepo-cpp)
  add_test(${TEST_NAME} ${TEST_NAME})
endmacro(ADD_CPP_TEST)

foreach(TEST ${CPP_TEST_SRC})
  ADD_CPP_TEST(${TEST})
endforeach()
