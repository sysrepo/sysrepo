# Find the address to use for the printed context.
#
# The following variables are used:
# PRINTED_CONTEXT_ADDRESS - Address to use for the printed context
#
# The following macros are defined:
# SR_PCTX_ADDR - Address to map the printed context to
#
# If PRINTED_CONTEXT_ADDRESS is not provided, the address will be calculated.
# The address calculation is done by compiling and executing a simple program that prints resulting address.
# The address is then used to map the printed context to the correct memory location.
#
# If the address calculation fails and PRINTED_CONTEXT_ADDRESS is not provided, then a printed context will not be used.
#
# Author Roman Janota <janota@cesnet.cz>
# Copyright (c) 2025 CESNET, z.s.p.o.
#
# This source code is licensed under BSD 3-Clause License (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/BSD-3-Clause
#

include(CheckCSourceCompiles)

# clear any previous definitions
set(CMAKE_REQUIRED_DEFINITIONS)
set(CMAKE_REQUIRED_INCLUDES sys/mman.h)

# check if MAP_FIXED_NOREPLACE is available by compiling a simple C program that uses it
function(_check_map_fixed_noreplace)
    check_c_source_compiles(
        "
        #include <sys/mman.h>

        int main() {
            int flag = MAP_FIXED_NOREPLACE;
            (void)flag; // Suppress unused variable warning
            return 0;
        }
        "
        HAVE_MAP_FIXED_NOREPLACE
    )

    set(HAVE_MAP_FIXED_NOREPLACE ${HAVE_MAP_FIXED_NOREPLACE} PARENT_SCOPE)
endfunction()

# calculate printed context address
function(_calculate_printed_context_address result_var)
    set(${result_var} "" PARENT_SCOPE)

    set(calculator_path "${CMAKE_CURRENT_LIST_DIR}/pctx_addr_calculator.c")

    # check if calculator source exists
    if(NOT EXISTS "${calculator_path}")
        message(WARNING "Printed context address calculator not found: ${calculator_path}")
        return()
    endif()

    # compile the calculator
    try_compile(calc_success
        ${CMAKE_BINARY_DIR}
        SOURCES ${calculator_path}
        OUTPUT_VARIABLE compile_output
        COPY_FILE ${CMAKE_BINARY_DIR}/pctx_addr_calculator
    )

    if(NOT calc_success)
        message(WARNING "Failed to compile address calculator:\n${compile_output}")
        return()
    endif()

    # execute the address calculator
    execute_process(
        COMMAND ${CMAKE_BINARY_DIR}/pctx_addr_calculator
        OUTPUT_VARIABLE calculated_addr
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE exec_result
        ERROR_VARIABLE exec_error
    )

    if(NOT exec_result EQUAL 0)
        message(WARNING "Address calculation failed (${exec_result}): ${exec_error}")
        return()
    endif()

    # propagate the calculated address to the calling scope
    set(${result_var} ${calculated_addr} PARENT_SCOPE)
endfunction()

# configure printed context
function(_configure_printed_context)
    # determine the address to use
    if(DEFINED PRINTED_CONTEXT_ADDRESS)
        set(address ${PRINTED_CONTEXT_ADDRESS})
        message(STATUS "Using provided printed context address: ${address}")
    else()
        message(STATUS "Calculating printed context address...")

        # this will set address variable to the calculated address on success
        _calculate_printed_context_address(address)

        if(NOT address)
            message(WARNING "Could not determine printed context address. "
                           "Provide PRINTED_CONTEXT_ADDRESS manually or set ENABLE_PRINTED_CONTEXT=OFF")
            return()
        endif()

        message(STATUS "Using calculated printed context address: ${address}")
    endif()

    # apply the configuration
    add_compile_definitions(SR_PCTX_ADDR=${address})
    set(PRINTED_CONTEXT_ADDRESS ${address} CACHE INTERNAL "Printed context address")

    # set the address for config.h.in, just set a new var instead of renaming the existing one
    # to keep its name similar to other options (without SR_ prefix)
    message(STATUS "Setting printed context address in config.h.in: ${address}")
    set(SR_PRINTED_LYCTX_ADDRESS ${address} CACHE INTERNAL "Printed libyang context address")
endfunction()

# check if MAP_FIXED_NOREPLACE is available, this will set HAVE_MAP_FIXED_NOREPLACE variable
_check_map_fixed_noreplace()

# MAP_FIXED_NOREPLACE is not available, but printed context may still be used with MAP_FIXED
if(NOT HAVE_MAP_FIXED_NOREPLACE)
    if(ENABLE_PRINTED_CONTEXT)
        if(DEFINED PRINTED_CONTEXT_ADDRESS)
            # use printed context with provided address
            message(WARNING "MAP_FIXED_NOREPLACE not available but printed context requested. "
                           "Using provided address ${PRINTED_CONTEXT_ADDRESS}. "
                           "Consider disabling ASLR to avoid undefined behavior.")
            _configure_printed_context()
        else()
            # no address provided, printed context cannot be used
            message(WARNING "MAP_FIXED_NOREPLACE not available and no address provided. "
                           "Provide page-aligned PRINTED_CONTEXT_ADDRESS and disable ASLR, or set ENABLE_PRINTED_CONTEXT=OFF. "
                           "Printed context disabled.")
        endif()
    else()
        message(STATUS "MAP_FIXED_NOREPLACE not available. Printed context disabled.")
    endif()
    return()
endif()

# MAP_FIXED_NOREPLACE is available
if((NOT DEFINED ENABLE_PRINTED_CONTEXT) OR ENABLE_PRINTED_CONTEXT)
    # this module is included before options in main Cmake are set, but
    # ENABLE_PRINTED_CONTEXT should be ON by default so just assume it is ON if it is undefined
    _configure_printed_context()
else()
    message(STATUS "Printed context disabled.")
endif()
