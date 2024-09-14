.intel_syntax noprefix
.globl _start

_start:
    mov al, 90      # SYS_chmod
    push rax        # Z
    mov rdi, rsp    # Point to ./Z
    mov si, 511     # permissions for chmod
    syscall         # chmod('Z', 0777)
