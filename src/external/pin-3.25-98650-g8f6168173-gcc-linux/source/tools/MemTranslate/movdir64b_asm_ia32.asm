;
; Copyright (C) 2022-2022 Intel Corporation.
; SPDX-License-Identifier: MIT
;

include asm_macros.inc

PROLOGUE

PUBLIC Movdir64bWrap0
PUBLIC Movdir64bWrap1
PUBLIC Movdir64bWrap2

.CODE

; Movdir64bWrap0(char *dst, char *src)
Movdir64bWrap0 PROC

    BEGIN_STACK_FRAME

    mov SCRATCH_REG1, 1 
	mov SCRATCH_REG2, PARAM1
	mov SCRATCH_REG3, PARAM2
    movdir64b SCRATCH_REG2, zmmword ptr [SCRATCH_REG3 + 1*SCRATCH_REG1]

    END_STACK_FRAME

    ret

Movdir64bWrap0 ENDP

; Movdir64bWrap1(char *dst, char *src)
Movdir64bWrap1 PROC

    BEGIN_STACK_FRAME

    mov SCRATCH_REG1, 1  
	mov SCRATCH_REG2, PARAM1
	mov SCRATCH_REG3, PARAM2
    movdir64b SCRATCH_REG2, zmmword ptr [SCRATCH_REG3 + 1*SCRATCH_REG1]

    END_STACK_FRAME

    ret

Movdir64bWrap1 ENDP

; Movdir64bWrap2(char *dst, char *src)
Movdir64bWrap2 PROC

    BEGIN_STACK_FRAME


    mov SCRATCH_REG1, 1 
	mov SCRATCH_REG2, PARAM1
	mov SCRATCH_REG3, PARAM2 
    movdir64b SCRATCH_REG2, zmmword ptr [SCRATCH_REG3 + 1*SCRATCH_REG1]

    END_STACK_FRAME

    ret

Movdir64bWrap2 ENDP

END