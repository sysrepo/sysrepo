# - Use compat library providing various functions and macros that may be missing on some systems
# Once done this will define
#
# compatsrc - sources to add to compilation
#
# Additionally, "compat.h" include directory is added and can be included.
#
# Author Michal Vasko <mvasko@cesnet.cz>
#  Copyright (c) 2021 - 2023 CESNET, z.s.p.o.
#
# This source code is licensed under BSD 3-Clause License (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/BSD-3-Clause
#
include(CheckSymbolExists)
include(CheckIncludeFile)
include(TestBigEndian)
if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()

macro(USE_COMPAT)
    # compatibility checks
    set(CMAKE_REQUIRED_DEFINITIONS -D_POSIX_C_SOURCE=200809L)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D__BSD_VISIBLE=1)
    set(CMAKE_REQUIRED_LIBRARIES pthread)

    check_symbol_exists(_POSIX_TIMERS "unistd.h" HAVE_CLOCK)
    if(NOT HAVE_CLOCK)
        message(FATAL_ERROR "Missing support for clock_gettime() and similar functions!")
    endif()

    check_symbol_exists(pthread_mutex_timedlock "pthread.h" HAVE_PTHREAD_MUTEX_TIMEDLOCK)
    check_symbol_exists(pthread_mutex_clocklock "pthread.h" HAVE_PTHREAD_MUTEX_CLOCKLOCK)
    check_symbol_exists(pthread_rwlock_clockrdlock "pthread.h" HAVE_PTHREAD_RWLOCK_CLOCKRDLOCK)
    check_symbol_exists(pthread_rwlock_clockwrlock "pthread.h" HAVE_PTHREAD_RWLOCK_CLOCKWRLOCK)
    check_symbol_exists(pthread_cond_clockwait "pthread.h" HAVE_PTHREAD_COND_CLOCKWAIT)
    if(HAVE_PTHREAD_MUTEX_CLOCKLOCK)
        # can use CLOCK_MONOTONIC only if we have pthread_mutex_clocklock()
        check_symbol_exists(_POSIX_MONOTONIC_CLOCK "unistd.h" HAVE_CLOCK_MONOTONIC)
    endif()
    if(HAVE_CLOCK_MONOTONIC)
        set(COMPAT_CLOCK_ID "CLOCK_MONOTONIC")
    else()
        set(COMPAT_CLOCK_ID "CLOCK_REALTIME")
    endif()

    check_symbol_exists(vdprintf "stdio.h;stdarg.h" HAVE_VDPRINTF)
    check_symbol_exists(asprintf "stdio.h" HAVE_ASPRINTF)
    check_symbol_exists(vasprintf "stdio.h" HAVE_VASPRINTF)
    check_symbol_exists(getline "stdio.h" HAVE_GETLINE)

    check_symbol_exists(strndup "string.h" HAVE_STRNDUP)
    check_symbol_exists(strnstr "string.h" HAVE_STRNSTR)
    check_symbol_exists(strdupa "string.h" HAVE_STRDUPA)
    check_symbol_exists(strchrnul "string.h" HAVE_STRCHRNUL)

    check_symbol_exists(get_current_dir_name "unistd.h" HAVE_GET_CURRENT_DIR_NAME)

    TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

    check_include_file("stdatomic.h" HAVE_STDATOMIC)

    unset(CMAKE_REQUIRED_DEFINITIONS)
    unset(CMAKE_REQUIRED_LIBRARIES)

    # header and source file (adding the source directly allows for hiding its symbols)
    configure_file(${PROJECT_SOURCE_DIR}/compat/compat.h.in ${PROJECT_BINARY_DIR}/compat/compat.h @ONLY)
    include_directories(${PROJECT_BINARY_DIR}/compat)
    set(compatsrc ${PROJECT_SOURCE_DIR}/compat/compat.c)
endmacro()
