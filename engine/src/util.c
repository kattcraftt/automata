/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include <errno.h>
#include "automata/util.h"
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

uint16_t read_u16_le(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 2 > size) return 0;
    return (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
}

uint16_t read_u16_be(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 2 > size) return 0;
    return ((uint16_t)data[offset] << 8) | (uint16_t)data[offset + 1];
}

uint32_t read_u32_le(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 4 > size) return 0;
    return (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) |
           ((uint32_t)data[offset + 2] << 16) | ((uint32_t)data[offset + 3] << 24);
}

uint32_t read_u32_be(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 4 > size) return 0;
    return ((uint32_t)data[offset] << 24) | ((uint32_t)data[offset + 1] << 16) |
           ((uint32_t)data[offset + 2] << 8) | (uint32_t)data[offset + 3];
}

uint64_t read_u64_le(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 8 > size) return 0;
    uint64_t lo = read_u32_le(data, size, offset);
    uint64_t hi = read_u32_le(data, size, offset + 4);
    return lo | (hi << 32);
}

uint64_t read_u64_be(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset + 8 > size) return 0;
    uint64_t hi = read_u32_be(data, size, offset);
    uint64_t lo = read_u32_be(data, size, offset + 4);
    return (hi << 32) | lo;
}

int map_file(const char *path, mapped_file_t *out_mapped) {
    if (path == NULL || out_mapped == NULL) return -1;
    out_mapped->data = NULL;
    out_mapped->size = 0;
    out_mapped->fd = -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    if (st.st_size == 0) {
        close(fd);
        return 0; // Empty file is successfully "mapped"
    }

    void *ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        // Fallback to malloc/read if mmap fails (unlikely, but safe)
        uint8_t *buf = malloc(st.st_size);
        if (buf == NULL) {
            close(fd);
            return -1;
        }
        if (read(fd, buf, st.st_size) != st.st_size) {
            free(buf);
            close(fd);
            return -1;
        }
        out_mapped->data = buf;
        out_mapped->size = st.st_size;
        out_mapped->fd = -2; // Marker for malloc'd
        close(fd);
        return 0;
    }

    out_mapped->data = ptr;
    out_mapped->size = st.st_size;
    out_mapped->fd = fd;
    return 0;
}

void unmap_file(mapped_file_t *mapped) {
    if (mapped == NULL) return;
    if (mapped->data != NULL) {
        if (mapped->fd >= 0) {
            munmap(mapped->data, mapped->size);
            close(mapped->fd);
        } else if (mapped->fd == -2) {
            free(mapped->data);
        }
    }
    mapped->data = NULL;
    mapped->size = 0;
    mapped->fd = -1;
}

char *safe_strncpy(char *dest, const char *src, size_t n) {
    if (dest == NULL || src == NULL || n == 0) return dest;
    strncpy(dest, src, n - 1);
    dest[n - 1] = '\0';
    return dest;
}

int mkdirp(const char *path) {
    if (path == NULL || *path == '\0') return -1;
    char *tmp = strdup(path);          /* no fixed-size buffer: long paths must not be truncated */
    if (tmp == NULL) return -1;
    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';

    int rc = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { rc = -1; break; }
            *p = '/';
        }
    }
    if (rc == 0 && mkdir(tmp, 0755) != 0 && errno != EEXIST) rc = -1;
    free(tmp);
    if (rc == 0) {
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) rc = -1;   /* e.g. a file is in the way */
    }
    return rc;
}


#include <sys/wait.h>

int util_find_in_path(const char *prog, char *out, size_t out_sz) {
    const char *path = getenv("PATH");
    char all[4096];
    snprintf(all, sizeof(all), "%s:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin", (path && *path) ? path : "");
    char *save = NULL;
    for (char *dir = strtok_r(all, ":", &save); dir != NULL; dir = strtok_r(NULL, ":", &save)) {
        int n = snprintf(out, out_sz, "%s/%s", dir, prog);
        if (n < 0 || (size_t)n >= out_sz) continue;
        struct stat st;
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode) && access(out, X_OK) == 0) return 1;
    }
    return 0;
}

int util_run(const char *exe, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(exe, argv);
        _exit(127);
    }
    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    if (w < 0 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

int util_write_temp(const uint8_t *data, size_t len, char *path_out, size_t path_sz) {
    char tmpl[] = "/tmp/automata_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, data + done, len - done);
        if (w <= 0) { close(fd); unlink(tmpl); return -1; }
        done += (size_t)w;
    }
    close(fd);
    snprintf(path_out, path_sz, "%s", tmpl);
    return 0;
}
