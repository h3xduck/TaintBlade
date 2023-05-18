bits 64

default rel

segment .data
    msg db "AABBCCDD This is just to have some writable memory :)", 0xd, 0xa, 0
    msg0 db "Some more scratch memory", 0xd, 0xa, 0
    msg1 db "Some more scratch memory", 0xd, 0xa, 0
    msg2 db "Some more scratch memory", 0xd, 0xa, 0
    msg3 db "Some more scratch memory", 0xd, 0xa, 0

section .text
global main
extern ExitProcess
extern _CRT_INIT

main:
    mov rcx, [msg]
    mov rax, 0x41
    cmp al, cl
    je equal
    ret

equal:
    mov rcx, 10

    

    ret