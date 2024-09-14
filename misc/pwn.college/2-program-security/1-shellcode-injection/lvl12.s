.intel_syntax noprefix
.globl _start

_start:
    mov ebx, 0x61652f2e # "./ea"
    push rbx
    mov al, 90              # SYS_chmod
    mov rdi, rsp            # address of ./ea
    mov si, 0x1ff           # mode 0777
    syscall                 # chmod("./ea", 0777)
