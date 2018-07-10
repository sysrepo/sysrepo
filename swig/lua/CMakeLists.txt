add_definitions(-DSWIG)
add_definitions(-DSWIGLUA)

project(Sysrepo_Lua)

add_library(Sysrepo_Lua SHARED ${SYSREPO_CPP_SOURCES})
SET_TARGET_PROPERTIES(Sysrepo_Lua PROPERTIES
              VERSION ${SYSREPO_VERSION} SOVERSION ${SYSREPO_SOVERSION})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(Sysrepo_Lua sysrepo)

set(LUA_SWIG_BINDING libsysrepoLua)

include(${SWIG_USE_FILE})
include_directories(${LUA_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_SWIG_FLAGS "-c++")
set(CMAKE_SWIG_FLAGS "-I${PROJECT_SOURCE_DIR}/inc")
set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})

set_source_files_properties(${LUA_SWIG_BINDING}.i PROPERTIES CPLUSPLUS ON)

if(${CMAKE_VERSION} VERSION_LESS "3.8.0")
    swig_add_module(${LUA_SWIG_BINDING} lua ${LUA_SWIG_BINDING}.i)
else()
    swig_add_library(${LUA_SWIG_BINDING} LANGUAGE lua SOURCES ${LUA_SWIG_BINDING}.i)
endif()
set_target_properties(${SWIG_MODULE_${LUA_SWIG_BINDING}_REAL_NAME} PROPERTIES PREFIX "")
swig_link_libraries(${LUA_SWIG_BINDING} ${LUA_LIBRARIES} Sysrepo_Lua)

# tests
if("${TEST_REPOSITORY_LOC}" STREQUAL "${REPOSITORY_LOC}" AND ENABLE_TESTS)

    set(LUA_TEST_MODULE "swig-test")
    set(LUA_TEST_MODULE_REV "2017-03-09")
    set(TEST_REPOSITORY_LOC "${CMAKE_BINARY_DIR}/repository")
    set(LUA_SWIG_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(LUA_TEST_DIR ${LUA_SWIG_DIR}/tests)
    set(LUA_YANG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/yang)

    # make libsysrepoLua depend on sysrepoctl
    add_dependencies(libsysrepoLua sysrepoctl)

    ADD_CUSTOM_COMMAND(
       TARGET libsysrepoLua
        POST_BUILD
        COMMAND ${CMAKE_BINARY_DIR}/src/sysrepoctl --install --yang=${LUA_YANG_DIR}/${LUA_TEST_MODULE}@${LUA_TEST_MODULE_REV}.yang # -0 ${TEST_REPOSITORY_LOC} > /dev/null
        VERBATIM
    )

    file(COPY "examples" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
    file(COPY "tests" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
    file(COPY "run_lua_test.sh" DESTINATION "${LUA_SWIG_DIR}")
    # file(COPY "utils.lua" DESTINATION "${LUA_SWIG_DIR}")
    file(COPY "luaunit.lua" DESTINATION "${LUA_SWIG_DIR}")

    set(LUA_EXECUTABLE /usr/bin/lua) #hack?

    macro(ADD_LUA_TEST TEST_NAME)
      add_test(NAME lua_${TEST_NAME}
        COMMAND sh ${LUA_SWIG_DIR}/run_lua_test.sh
        "${CMAKE_BINARY_DIR}/tests:${CMAKE_BINARY_DIR}/repository:${LUA_TEST_DIR}"
        "${LUA_SWIG_DIR}" # LUA_PATH
        "${LUA_EXECUTABLE}"
        "${LUA_TEST_DIR}/${TEST_NAME}.lua"
        WORKING_DIRECTORY ${LUA_SWIG_DIR})
    endmacro(ADD_LUA_TEST)

    ADD_LUA_TEST(sysrepo_init)
    ADD_LUA_TEST(basic_item_handling)
    ADD_LUA_TEST(changes)
endif()

# install binary
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${LUA_SWIG_BINDING}.so" DESTINATION "${CMAKE_INSTALL_LIBDIR}/lua/${GEN_LUA_VERSION}/")
install(TARGETS Sysrepo_Lua DESTINATION ${CMAKE_INSTALL_LIBDIR})
