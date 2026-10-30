/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <lzma.h>
#include "automata/extract.h"
#include "automata/identify.h"
#include "automata/squashfs.h"
#include "automata/util.h"

#define MAX_DECOMP 268435456 // 256MB
#define EXTRACT_MAX_FINDINGS 16384

static void fill_result(extract_result_t *res, const char *path, const char *type,
                        size_t offset, size_t compressed, size_t decompressed) {
    if (!res) return;
    memset(res, 0, sizeof(*res));
    safe_strncpy(res->path, path, sizeof(res->path));
    safe_strncpy(res->type, type, sizeof(res->type));
    res->offset = offset;
    res->compressed = compressed;
    res->decompressed = decompressed;
}

int extract_gzip(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    mkdirp(out_dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/0x%zx_gzip.bin", out_dir, offset);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    z_stream strm = {0};
    strm.next_in = (Bytef *)(data + offset);
    size_t avail = size - offset;
    strm.avail_in = (uInt)(avail > 0xFFFFFFFFu ? 0xFFFFFFFFu : avail);
    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        fclose(f);
        unlink(path);
        return -1;
    }

    uint8_t out[16384];
    size_t decompressed = 0;
    int ret;
    do {
        strm.avail_out = sizeof(out);
        strm.next_out = (Bytef *)out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm); fclose(f); unlink(path); return -1;
        }
        size_t have = sizeof(out) - strm.avail_out;
        if (have > 0) {
            decompressed += have;
            if (decompressed > MAX_DECOMP) {
                inflateEnd(&strm); fclose(f); unlink(path); return -1;
            }
            fwrite(out, 1, have, f);
        }
        /* Z_BUF_ERROR means a truncated stream with no input left: stop instead of spinning. */
    } while (ret == Z_OK);

    size_t consumed = strm.total_in;
    inflateEnd(&strm);
    fclose(f);

    if (decompressed == 0) {
        unlink(path);
        return -1;
    }
    fill_result(out_res, path, "gzip", offset, consumed, decompressed);
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
    if (lzma_auto_decoder(&strm, UINT64_MAX, 0) != LZMA_OK) {
        fclose(f); unlink(path); return -1;
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
                lzma_end(&strm); fclose(f); unlink(path); return -1;
            }
            fwrite(out, 1, have, f);
        }
    } while (ret == LZMA_OK && strm.avail_in > 0);

    size_t consumed = (size - offset) - strm.avail_in;
    lzma_end(&strm);
    fclose(f);

    if (decompressed == 0) {
        unlink(path);
        return -1;
    }
    fill_result(out_res, path, "lzma", offset, consumed, decompressed);
    return 0;
}

int extract_all(const uint8_t *data, size_t size, const char *out_dir, extract_result_t *out_results, size_t max_results, size_t *out_count) {
    size_t count = 0;
    size_t num_findings = 0;
    finding_t *findings = malloc(sizeof(finding_t) * EXTRACT_MAX_FINDINGS);
    if (!findings) return -1;

    if (identify_scan(data, size, findings, EXTRACT_MAX_FINDINGS, &num_findings) == 0) {
        size_t skip_until = 0;   /* do not re-extract matches inside a region already unpacked */
        for (size_t i = 0; i < num_findings && count < max_results; i++) {
            const finding_t *fd = &findings[i];
            if (fd->confidence < IDENTIFY_MIN_CONFIDENCE) continue;
            if (fd->offset < skip_until) continue;

            extract_result_t res;
            int ok = -1;
            switch (fd->type) {
                case SIG_GZIP:
                    ok = extract_gzip(data, size, fd->offset, out_dir, &res);
                    break;
                case SIG_XZ:
                case SIG_LZMA:
                    ok = extract_lzma(data, size, fd->offset, out_dir, &res);
                    break;
                case SIG_SQUASHFS_LE:
                case SIG_SQUASHFS_BE: {
                    size_t used = squashfs_superblock_size(data, size, fd->offset);
                    if (used == 0) break;
                    char sub[512];
                    snprintf(sub, sizeof(sub), "%s/squashfs-0x%zx", out_dir, fd->offset);
                    if (squashfs_extract(data, size, fd->offset, sub) == 0) {
                        fill_result(&res, sub, "squashfs", fd->offset, used, 0);
                        ok = 0;
                    }
                    break;
                }
                default:
                    break;
            }
            if (ok == 0) {
                if (out_results) out_results[count] = res;
                count++;
                if (res.compressed > 0) skip_until = fd->offset + res.compressed;
            }
        }
    }

    free(findings);
    if (out_count) *out_count = count;
    return 0;
}
