/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_UTIL_H
#define AUTOMATA_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct {
    uint8_t *data;
    size_t size;
    int fd;
} mapped_file_t;

uint16_t read_u16_le(const uint8_t *data, size_t size, size_t offset);
uint16_t read_u16_be(const uint8_t *data, size_t size, size_t offset);
uint32_t read_u32_le(const uint8_t *data, size_t size, size_t offset);
uint32_t read_u32_be(const uint8_t *data, size_t size, size_t offset);
uint64_t read_u64_le(const uint8_t *data, size_t size, size_t offset);
uint64_t read_u64_be(const uint8_t *data, size_t size, size_t offset);

int map_file(const char *path, mapped_file_t *out_mapped);
void unmap_file(mapped_file_t *mapped);

char *safe_strncpy(char *dest, const char *src, size_t n);
int mkdirp(const char *path);

/* Run external tools without a shell. */
int util_find_in_path(const char *prog, char *out, size_t out_sz);   /* $PATH plus the sbin directories; 1 if found */
int util_run(const char *exe, char *const argv[]);                   /* fork/exec with stdout/stderr silenced; exit status or -1 */
int util_write_temp(const uint8_t *data, size_t len, char *path_out, size_t path_sz);   /* private temp file; 0 on success */

#endif /* AUTOMATA_UTIL_H */
