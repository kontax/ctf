#include <fcntl.h>
#include <stdio.h>

int main() {
    printf("O_CREAT | O_WRONLY = %d\n", O_CREAT | O_WRONLY);
    return 0;
}
