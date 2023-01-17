bits 64

default rel

segment .data
    msg db "Hello world! This is just to have some writable memory :)", 0xd, 0xa, 0
    msg0 db "Some more scratch memory", 0xd, 0xa, 0
    msg1 db "Some more scratch memory", 0xd, 0xa, 0
    msg2 db "Some more scratch memory", 0xd, 0xa, 0
    msg3 db "Some more scratch memory", 0xd, 0xa, 0

section .text
global main
extern ExitProcess
extern _CRT_INIT

main:
    and rcx, rax ;rcx=1: 1, 1
    and rdx, rbx ;rdx=1: 2, 2
    and rdx, rax ;rdx=3: 2, 1
    and rcx, rbx ;rcx=3: 1, 2
    and rdx, rax ;rdx=4: 3, 1
    and rcx, rbx ;rcx=5: 3, 2
    ;and rcx, rdx ;rcx=
    

    ret