#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    int a = open("/home/james/ctf/test_file", O_WRONLY|O_CREAT);
}
