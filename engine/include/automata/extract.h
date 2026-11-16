/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_EXTRACT_H
#define AUTOMATA_EXTRACT_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char path[512];
    char type[64];
    size_t offset;
    size_t compressed;
    size_t decompressed;
} extract_result_t;

int extract_gzip(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res);
int extract_lzma(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res);
/* Optional codecs: compiled in only when libbz2 / libzstd / liblz4 were found at configure time.
 * The extract_* functions return -1 when their codec is missing; extract_have_* tell which ones exist. */
int extract_bzip2(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res);
int extract_zstd(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res);
int extract_lz4(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res);
int extract_have_bzip2(void);
int extract_have_zstd(void);
int extract_have_lz4(void);

int extract_all(const uint8_t *data, size_t size, const char *out_dir, extract_result_t *out_results, size_t max_results, size_t *out_count);

#endif /* AUTOMATA_EXTRACT_H */
