bits 64

default rel

segment .data
    msg db "Hello world!", 0xd, 0xa, 0

section .text
global main
extern ExitProcess
extern _CRT_INIT

main:
    xor rax, rax
    and [msg], rax
    ret