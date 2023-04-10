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
    xor rax, rax
    xor rbx, rbx
    add rbx, 1
    cmp rax, 0
    cmp rbx, 0
    add rax, rbx
    cmp rbx, rax

    

    ret