# Configure printed libyang context address.
#
# The following variables are used:
# PRINTED_CONTEXT_ADDRESS - Optional. Pre-defined address to use for the printed context mapping
#
# The following cache variables are set:
# PRINTED_CONTEXT_ADDRESS - The final address used for printed context mapping
#
# Behavior:
# 1. Checks if MAP_FIXED_NOREPLACE is available on the system
# 2. If PRINTED_CONTEXT_ADDRESS is provided, uses that address
# 3. If not provided, attempts to calculate address using pctx_addr_calculator.c
# 4. If MAP_FIXED_NOREPLACE is unavailable:
#    - Requires manual PRINTED_CONTEXT_ADDRESS and warns about ASLR
#    - Falls back to MAP_FIXED with potential undefined behavior
# 5. Sets PRINTED_CONTEXT_ADDRESS for use in source code
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

include(CheckSymbolExists)

# check if MAP_FIXED_NOREPLACE is available
check_symbol_exists(MAP_FIXED_NOREPLACE "sys/mman.h" HAVE_MAP_FIXED_NOREPLACE)

# handle case when MAP_FIXED_NOREPLACE is not available
if(NOT HAVE_MAP_FIXED_NOREPLACE)
    # MAP_FIXED_NOREPLACE is not available, but printed context may still be used with MAP_FIXED
    if(DEFINED PRINTED_CONTEXT_ADDRESS)
        message(WARNING "MAP_FIXED_NOREPLACE not available, but printed context requested. "
                        "Consider disabling ASLR to avoid undefined behavior.")
    else()
        # no address provided, printed context cannot be used, we can end here
        message(WARNING "MAP_FIXED_NOREPLACE not available and no address provided. "
                        "Provide page-aligned PRINTED_CONTEXT_ADDRESS and consider disabling ASLR to use printed context. "
                        "Printed context disabled.")
        return()
    endif()
endif()

# determine the address to use
set(address "")

if(DEFINED PRINTED_CONTEXT_ADDRESS)
    set(address ${PRINTED_CONTEXT_ADDRESS})
else()
    message(STATUS "Calculating printed context address...")

    # calculate printed context address
    set(calculator_path "${CMAKE_CURRENT_LIST_DIR}/pctx_addr_calculator.c")

    # compile the calculator
    try_compile(calc_success
        ${CMAKE_BINARY_DIR}
        SOURCES ${calculator_path}
        OUTPUT_VARIABLE compile_output
        COPY_FILE ${CMAKE_BINARY_DIR}/pctx_addr_calculator
    )

    if(NOT calc_success)
        message(WARNING "Failed to compile address calculator:\n${compile_output}")
    else()
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
        else()
            set(address ${calculated_addr})
        endif()
    endif()
endif()

# set and cache the address for use in source code
if (NOT address)
    message(WARNING "Could not determine printed context address. "
                       "Provide PRINTED_CONTEXT_ADDRESS manually to enable printed context.")
else()
    set(PRINTED_CONTEXT_ADDRESS ${address} CACHE INTERNAL "Printed context address")
    message(STATUS "Using printed context address: ${PRINTED_CONTEXT_ADDRESS}")
endif()
