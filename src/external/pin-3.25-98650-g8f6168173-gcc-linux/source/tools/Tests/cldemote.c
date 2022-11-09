/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

static unsigned int buff[16];

void cldemote()
{
    /* encode the cldemote instruction in .byte to avoid dependency on the compiler version */
    asm volatile("lea %0, %%rax" : "=m"(buff) : : "%rax");           /* lea rax, [buff] */
    asm volatile(".byte 0x0F; .byte 0x1C; .byte 0x00" ::: "memory"); /* cldemote [rax] */
}

int main()
{
    cldemote();
    return 0;
}
