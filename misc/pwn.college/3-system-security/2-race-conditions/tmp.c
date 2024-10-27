#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

int main() {
  int res = -1;

  // Create the "aaa" directory
  res = mkdirat(AT_FDCWD, "aaa", 0755);
  if (res == -1) {
    perror("mkdirat aaa");
    return 1;
  }

  // Move "aaa" to "maze" using renameat2
  res = renameat2(AT_FDCWD, "aaa", AT_FDCWD, "maze", RENAME_NOREPLACE);
  if (res == -1) {
    perror("renameat2 aaa to maze");
    return 1;
  }

  printf("Successfully moved 'aaa' to 'maze'\n");
  return 0;
}
