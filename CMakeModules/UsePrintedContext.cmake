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

# check if a value (address) was provided directly
if(DEFINED PRINTED_CONTEXT_ADDRESS)
    message(STATUS "Using provided PRINTED_CONTEXT_ADDRESS: ${PRINTED_CONTEXT_ADDRESS}")
    add_compile_definitions(SR_PCTX_ADDR=${PRINTED_CONTEXT_ADDRESS})
    set(PRINTED_CONTEXT_ADDRESS ${PRINTED_CONTEXT_ADDRESS} CACHE INTERNAL "Printed context address")
else()
    # no value provided, need to calculate it
    message(STATUS "Calculating printed context address...")

    # verify the calculator source exists
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/pctx_addr_calculator.c")
        message(WARNING "Printed context address calculator source not found at ${CMAKE_CURRENT_LIST_DIR}/pctx_addr_calculator.c")
    else()
        # compile the address calculator program
        try_compile(CALC_SUCCESS
            ${CMAKE_BINARY_DIR}
            SOURCES ${CMAKE_CURRENT_LIST_DIR}/pctx_addr_calculator.c
            OUTPUT_VARIABLE CALC_COMPILATION_OUTPUT
            COPY_FILE ${CMAKE_BINARY_DIR}/pctx_addr_calculator
        )

        if(NOT CALC_SUCCESS)
            message(WARNING "Failed to compile printed context address calculator: ${CALC_COMPILATION_OUTPUT}\n"
                            "Either provide PRINTED_CONTEXT_ADDRESS or disable printed context usage.")
        else()
            # execute the address calculation
            execute_process(
                COMMAND ${CMAKE_BINARY_DIR}/pctx_addr_calculator
                OUTPUT_VARIABLE CALCULATED_VALUE
                OUTPUT_STRIP_TRAILING_WHITESPACE
                RESULT_VARIABLE CALC_RESULT
                ERROR_VARIABLE CALC_ERROR
            )

            if(NOT CALC_RESULT EQUAL 0)
                message(WARNING "Printed context address calculation failed (${CALC_RESULT}): ${CALC_ERROR}")
            else()
                message(STATUS "Calculated printed context address: ${CALCULATED_VALUE}")
                add_compile_definitions(SR_PCTX_ADDR=${CALCULATED_VALUE})
                set(PRINTED_CONTEXT_ADDRESS ${CALCULATED_VALUE} CACHE INTERNAL "")
            endif()
        endif()
    endif()
endif()
