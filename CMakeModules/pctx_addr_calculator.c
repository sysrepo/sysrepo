/**
 * @file pcx_addr_calculator.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief Calculator for the memory address to map the printed libyang context to
 *
 * Copyright (c) 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/**
 * @brief Macro to align an address to the nearest page boundary.
 *
 * @param[in] addr The address to align.
 */
#define PAGE_ALIGNED_ADDR(addr) \
    (void *)(((uintptr_t)addr + getpagesize() - 1) & ~(getpagesize() - 1))

/**
 * @brief Calculates a page-aligned address approximately halfway between the stack and heap.
 *
 * @note Assumes that the stack grows downwards and the heap grows upwards and that
 * the heap is on a lower address than the stack in the process' virtual address space.
 *
 * @return uintptr_t The calculated address, or 0 on failure.
 */
static uintptr_t
calculate_mid_stack_heap_address(void)
{
    void *heap_base, *stack_base;
    struct rlimit stack_limits;
    uintptr_t midpoint_address;
    const int page_size = getpagesize();

    /* get the current heap break address and page align it */
    heap_base = sbrk(0);
    if (heap_base == (void *)-1) {
        fprintf(stderr, "sbrk(0) failed: %s\n", strerror(errno));
        return 0;
    }
    heap_base = PAGE_ALIGNED_ADDR(heap_base);

    /* get the current stack limits */
    if (getrlimit(RLIMIT_STACK, &stack_limits)) {
        fprintf(stderr, "getrlimit failed: %s\n", strerror(errno));
        return 0;
    }

    /* approximate the stack base address by subtracting the size of the stack from
     * an address of a variable allocated on the stack and page align it (assuming stack grows down) */
    stack_base = (void*)((uintptr_t)&stack_limits - stack_limits.rlim_cur);
    stack_base = PAGE_ALIGNED_ADDR(stack_base);

    /* calculate the midpoint address and page align it */
    midpoint_address = ((uintptr_t)stack_base + (uintptr_t)heap_base) / 2;
    midpoint_address = (uintptr_t)PAGE_ALIGNED_ADDR(midpoint_address);

    return midpoint_address;
}

int
main(void)
{
    uintptr_t address;

    /* calculate the address */
    address = calculate_mid_stack_heap_address();
    if (!address) {
        return 1;
    }

    /* print the address to stdout for the cmake module to collect it */
    printf("0x%" PRIxPTR "\n", address);

    return 0;
}
