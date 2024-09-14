.intel_syntax noprefix
.globl _start

_start:
    mov rax, 59             # SYS_execve
    lea rdi, [rip+binsh]    # address of /bin/sh
    mov rsi, 0              # argv
    mov rdx, 0              # envp
    syscall                 # execve("/bin/sh", NULL, NULL)
    binsh:
    .string "/bin/sh"

