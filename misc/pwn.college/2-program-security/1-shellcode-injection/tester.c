#include <unistd.h>
#include <sys/mman.h>

int main() {
    void* page = mmap((void*)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    read(0, page, 0x1000);
    ((void(*)())page)();
}
