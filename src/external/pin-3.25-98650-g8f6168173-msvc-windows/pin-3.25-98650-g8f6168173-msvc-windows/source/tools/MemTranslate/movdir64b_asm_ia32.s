/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include<asm_macros.h>

.text

// Movdir64bWrap0(char *dst, char *src)
DECLARE_FUNCTION_AS(Movdir64bWrap0)

Movdir64bWrap0:

    BEGIN_STACK_FRAME

    mov $0x1, %ecx
    mov PARAM1, %eax
    mov PARAM2, %edx
    movdir64b (%edx, %ecx, 1),%eax
    
    END_STACK_FRAME

    ret

// Movdir64bWrap1(char *dst, char *src)
DECLARE_FUNCTION_AS(Movdir64bWrap1)

Movdir64bWrap1:

    BEGIN_STACK_FRAME

    mov $0x1, %ecx
    mov PARAM1, %eax
    mov PARAM2, %edx
    movdir64b (%edx, %ecx, 1),%eax
    
    END_STACK_FRAME

    ret

// Movdir64bWrap2(char *dst, char *src)
DECLARE_FUNCTION_AS(Movdir64bWrap2)

Movdir64bWrap2:

    BEGIN_STACK_FRAME

    mov $0x1, %ecx
    mov PARAM1, %eax
    mov PARAM2, %edx
    movdir64b (%edx, %ecx, 1),%eax
    
    END_STACK_FRAME

    ret
