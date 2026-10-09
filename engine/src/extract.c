/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <lzma.h>
#include "automata/extract.h"
#include "automata/identify.h"
#include "automata/util.h"

#define MAX_DECOMP 268435456 // 256MB

int extract_gzip(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    mkdirp(out_dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/0x%zx_gzip.bin", out_dir, offset);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    z_stream strm = {0};
    strm.next_in = (Bytef *)(data + offset);
    strm.avail_in = (uInt)(size - offset);
    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        fclose(f);
        return -1;
    }

    uint8_t out[16384];
    size_t decompressed = 0;
    int ret;
    do {
        strm.avail_out = sizeof(out);
        strm.next_out = (Bytef *)out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR) {
            inflateEnd(&strm); fclose(f); return -1;
        }
        size_t have = sizeof(out) - strm.avail_out;
        if (have > 0) {
            decompressed += have;
            if (decompressed > MAX_DECOMP) {
                inflateEnd(&strm); fclose(f); return -1;
            }
            fwrite(out, 1, have, f);
        }
    } while (ret != Z_STREAM_END && ret != Z_DATA_ERROR && ret != Z_NEED_DICT);

    inflateEnd(&strm);
    fclose(f);

    if (out_res) {
        strncpy(out_res->path, path, sizeof(out_res->path) - 1);
        strncpy(out_res->type, "gzip", sizeof(out_res->type) - 1);
        out_res->offset = offset;
        out_res->compressed = strm.total_in;
        out_res->decompressed = decompressed;
    }
    return 0;
}

int extract_lzma(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    mkdirp(out_dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/0x%zx_lzma.bin", out_dir, offset);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_auto_decoder(&strm, -1, 0) != LZMA_OK) {
        fclose(f); return -1;
    }

    strm.next_in = data + offset;
    strm.avail_in = size - offset;
    uint8_t out[16384];
    size_t decompressed = 0;
    lzma_ret ret;
    do {
        strm.next_out = out;
        strm.avail_out = sizeof(out);
        ret = lzma_code(&strm, LZMA_RUN);
        size_t have = sizeof(out) - strm.avail_out;
        if (have > 0) {
            decompressed += have;
            if (decompressed > MAX_DECOMP) {
                lzma_end(&strm); fclose(f); return -1;
            }
            fwrite(out, 1, have, f);
        }
    } while (ret == LZMA_OK && strm.avail_in > 0);
    
    lzma_end(&strm);
    fclose(f);

    if (out_res) {
        strncpy(out_res->path, path, sizeof(out_res->path) - 1);
        strncpy(out_res->type, "lzma", sizeof(out_res->type) - 1);
        out_res->offset = offset;
        out_res->compressed = (size - offset) - strm.avail_in;
        out_res->decompressed = decompressed;
    }
    return 0;
}

int extract_all(const uint8_t *data, size_t size, const char *out_dir, extract_result_t *out_results, size_t max_results, size_t *out_count) {
    size_t count = 0;
    finding_t findings[64];
    size_t num_findings = 0;
    
    if (identify_scan(data, size, findings, 64, &num_findings) == 0) {
        for (size_t i = 0; i < num_findings && count < max_results; i++) {
            extract_result_t res;
            if (strcmp(findings[i].label, "gzip") == 0 || strcmp(findings[i].label, "GZIP") == 0) {
                if (extract_gzip(data, size, findings[i].offset, out_dir, &res) == 0) {
                    if (out_results) out_results[count] = res;
                    count++;
                }
            } else if (strcmp(findings[i].label, "lzma") == 0 || strcmp(findings[i].label, "LZMA") == 0 || strcmp(findings[i].label, "xz") == 0) {
                if (extract_lzma(data, size, findings[i].offset, out_dir, &res) == 0) {
                    if (out_results) out_results[count] = res;
                    count++;
                }
            }
        }
    }
    
    if (out_count) *out_count = count;
    return 0;
}
