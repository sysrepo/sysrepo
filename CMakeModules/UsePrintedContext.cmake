# Configure printed libyang context address.
#
# The following variables are used:
# PRINTED_CONTEXT_ADDRESS - Pre-defined address to use for the printed context mapping, "" if not set, 0 if disabled
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

function(SETUP_PRINTED_CONTEXT)
    # get the docstring for the address
    get_property(PRINTED_CONTEXT_ADDRESS_DOCSTRING CACHE PRINTED_CONTEXT_ADDRESS PROPERTY HELPSTRING)

    # handle case when MAP_FIXED_NOREPLACE is not available
    if(NOT HAVE_MAP_FIXED_NOREPLACE)
        # MAP_FIXED_NOREPLACE is not available, but printed context may still be used with MAP_FIXED
        if(NOT "${PRINTED_CONTEXT_ADDRESS}" STREQUAL "" AND NOT "${PRINTED_CONTEXT_ADDRESS}" STREQUAL "0")
            message(WARNING "MAP_FIXED_NOREPLACE not available, but printed context enabled. "
                            "Consider disabling ASLR (Address Space Layout Randomization) to avoid overwriting existing memory mappings.")
            message(STATUS "Printed context: enabled (using provided address ${PRINTED_CONTEXT_ADDRESS})")
        else()
            # no address provided, printed context cannot be used, we can end here
            message(WARNING "MAP_FIXED_NOREPLACE not available and no valid address provided. "
                            "Provide page-aligned PRINTED_CONTEXT_ADDRESS to use printed context.")
            message(STATUS "Printed context: disabled")
            set(PRINTED_CONTEXT_ADDRESS 0 CACHE STRING "${PRINTED_CONTEXT_ADDRESS_DOCSTRING}" FORCE)
        endif()

        return()
    endif()

    # check if no address is provided
    if("${PRINTED_CONTEXT_ADDRESS}" STREQUAL "")
        # calculate printed context address
        # no point compiling the calculator if sbrk() is not available
        if (NOT HAVE_SBRK)
            message(WARNING "sbrk() is required to calculate printed context address, but it is not available. "
                            "Provide PRINTED_CONTEXT_ADDRESS manually to enable printed context.")
            message(STATUS "Printed context: disabled")
            set(PRINTED_CONTEXT_ADDRESS 0 CACHE STRING "${PRINTED_CONTEXT_ADDRESS_DOCSTRING}" FORCE)
            return()
        endif()

        # compile and run the address calculator
        try_run(
            exec_result compile_result
            ${CMAKE_BINARY_DIR}
            SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/pctx_addr_calculator.c"
            COMPILE_OUTPUT_VARIABLE compile_output
            RUN_OUTPUT_STDOUT_VARIABLE calculated_addr
        )

        if (NOT compile_result)
            message(WARNING "Failed to compile address calculator:\n${compile_output}\n"
                            "Provide PRINTED_CONTEXT_ADDRESS manually to enable printed context.")
            message(STATUS "Printed context: disabled")
            set(PRINTED_CONTEXT_ADDRESS 0 CACHE STRING "${PRINTED_CONTEXT_ADDRESS_DOCSTRING}" FORCE)
            return()
        endif()

        if(exec_result EQUAL 0)
            # overwrite the cached address
            set(PRINTED_CONTEXT_ADDRESS ${calculated_addr} CACHE STRING "${PRINTED_CONTEXT_ADDRESS_DOCSTRING}" FORCE)
            message(STATUS "Printed context: enabled (using generated address ${PRINTED_CONTEXT_ADDRESS})")
        else()
            message(WARNING "Address calculator failed to run. "
                            "Provide PRINTED_CONTEXT_ADDRESS manually to enable printed context.")
            message(STATUS "Printed context: disabled")
            set(PRINTED_CONTEXT_ADDRESS 0 CACHE STRING "${PRINTED_CONTEXT_ADDRESS_DOCSTRING}" FORCE)
        endif()
    elseif("${PRINTED_CONTEXT_ADDRESS}" STREQUAL "0")
        # address is 0, printed context is disabled
        message(STATUS "Printed context: disabled")
    else()
        # address provided, use it
        message(STATUS "Printed context: enabled (using provided address ${PRINTED_CONTEXT_ADDRESS})")
    endif()
endfunction()
