#include <fcntl.h>
#include <stdio.h>

int main() {
    int fd = open("/home/james/flag", O_CREAT|O_WRONLY);
}
