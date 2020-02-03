# binding dependencies
if(GEN_PYTHON_BINDINGS AND NOT GEN_CPP_BINDINGS)
    message(WARNING "Python bindings depend on C++, enabling them.")
    set(GEN_CPP_BINDINGS ON)
endif()

# C++ bindings
if(GEN_CPP_BINDINGS)
    if(NOT LIBYANG_CPP_FOUND)
        message(FATAL_ERROR "Required libyang C++ bindings not found!")
    endif()
    add_subdirectory(cpp)
endif()

# Python bindings
if(GEN_PYTHON_BINDINGS)
    find_package(SWIG 3.0.12 REQUIRED)
    include(${SWIG_USE_FILE})

    unset(PYTHON_LIBRARY CACHE)
    unset(PYTHON_EXECUTABLE CACHE)
    unset(PYTHON_INCLUDE_DIR CACHE)
    unset(PYTHON_LIBRARY_DEBUG CACHE)
    find_package(PythonInterp 3)
    find_package(PythonLibs 3)
    if(NOT PYTHONLIBS_FOUND)
        message(FATAL_ERROR "Python 3 libraries not found!")
    endif()
    if(NOT PYTHONINTERP_FOUND)
        message(FATAL_ERROR "Python 3 interpreter not found!")
    endif()
    add_subdirectory(python)
endif()
