
.intel_syntax noprefix
.globl _start

.section .text

_start:
    .rept 0x10
        nop
    .endr
    mov rax, 0x10
    mov rbx, 0x20
    mov rcx, 0x30
    mov rdx, 0x40
