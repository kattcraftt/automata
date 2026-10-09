/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
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
    if (path == NULL) return -1;
    char tmp[256];
    safe_strncpy(tmp, path, sizeof(tmp));
    char *p = NULL;
    size_t len = strlen(tmp);

    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    mkdir(tmp, 0755);
    return 0;
}
