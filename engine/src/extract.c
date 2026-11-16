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
#include "automata/fsextract.h"
#ifdef HAVE_BZIP2
#include <bzlib.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif
#ifdef HAVE_LZ4
#include <lz4frame.h>
#endif
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

/* Open the output file for a codec and return it, or NULL. */
static FILE *open_out(const char *out_dir, size_t offset, const char *suffix, char *path, size_t path_sz) {
    if (offset == 0 && 0) return NULL;
    if (mkdirp(out_dir) != 0) return NULL;
    snprintf(path, path_sz, "%s/0x%zx_%s.bin", out_dir, offset, suffix);
    return fopen(path, "wb");
}

#ifdef HAVE_BZIP2
int extract_have_bzip2(void) { return 1; }
int extract_bzip2(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    char path[512];
    FILE *f = open_out(out_dir, offset, "bzip2", path, sizeof(path));
    if (!f) return -1;
    bz_stream s;
    memset(&s, 0, sizeof(s));
    if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK) { fclose(f); unlink(path); return -1; }
    size_t avail = size - offset;
    s.next_in = (char *)(data + offset);
    s.avail_in = (unsigned int)(avail > 0xFFFFFFFFu ? 0xFFFFFFFFu : avail);
    char out[16384];
    size_t total = 0;
    int r;
    do {
        s.next_out = out;
        s.avail_out = sizeof(out);
        r = BZ2_bzDecompress(&s);
        size_t have = sizeof(out) - s.avail_out;
        if (have) {
            total += have;
            if (total > MAX_DECOMP) { BZ2_bzDecompressEnd(&s); fclose(f); unlink(path); return -1; }
            fwrite(out, 1, have, f);
        }
        if (r == BZ_OK && s.avail_in == 0 && have == 0) break;      /* truncated stream */
    } while (r == BZ_OK);
    size_t consumed = ((size_t)s.total_in_hi32 << 32) | s.total_in_lo32;
    BZ2_bzDecompressEnd(&s);
    fclose(f);
    if (total == 0) { unlink(path); return -1; }
    fill_result(out_res, path, "bzip2", offset, consumed, total);
    return 0;
}
#else
int extract_have_bzip2(void) { return 0; }
int extract_bzip2(const uint8_t *d, size_t s, size_t o, const char *dir, extract_result_t *r) { (void)d; (void)s; (void)o; (void)dir; (void)r; return -1; }
#endif

#ifdef HAVE_ZSTD
int extract_have_zstd(void) { return 1; }
int extract_zstd(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    char path[512];
    FILE *f = open_out(out_dir, offset, "zstd", path, sizeof(path));
    if (!f) return -1;
    ZSTD_DCtx *ctx = ZSTD_createDCtx();
    if (!ctx) { fclose(f); unlink(path); return -1; }
    ZSTD_inBuffer in = { data + offset, size - offset, 0 };
    uint8_t out[16384];
    size_t total = 0;
    for (;;) {
        ZSTD_outBuffer ob = { out, sizeof(out), 0 };
        size_t r = ZSTD_decompressStream(ctx, &ob, &in);
        if (ZSTD_isError(r)) break;
        if (ob.pos) {
            total += ob.pos;
            if (total > MAX_DECOMP) { ZSTD_freeDCtx(ctx); fclose(f); unlink(path); return -1; }
            fwrite(out, 1, ob.pos, f);
        }
        if (r == 0) break;                                              /* frame complete */
        if (in.pos == in.size && ob.pos == 0) break;                    /* truncated */
    }
    size_t consumed = in.pos;
    ZSTD_freeDCtx(ctx);
    fclose(f);
    if (total == 0) { unlink(path); return -1; }
    fill_result(out_res, path, "zstd", offset, consumed, total);
    return 0;
}
#else
int extract_have_zstd(void) { return 0; }
int extract_zstd(const uint8_t *d, size_t s, size_t o, const char *dir, extract_result_t *r) { (void)d; (void)s; (void)o; (void)dir; (void)r; return -1; }
#endif

#ifdef HAVE_LZ4
int extract_have_lz4(void) { return 1; }
int extract_lz4(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res) {
    if (offset >= size) return -1;
    char path[512];
    FILE *f = open_out(out_dir, offset, "lz4", path, sizeof(path));
    if (!f) return -1;
    LZ4F_dctx *ctx = NULL;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION))) { fclose(f); unlink(path); return -1; }
    const uint8_t *src = data + offset;
    size_t remaining = size - offset, consumed = 0, total = 0;
    uint8_t out[65536];
    while (remaining > 0) {
        size_t src_size = remaining, dst_size = sizeof(out);
        size_t r = LZ4F_decompress(ctx, out, &dst_size, src, &src_size, NULL);
        if (LZ4F_isError(r)) break;
        src += src_size; remaining -= src_size; consumed += src_size;
        if (dst_size) {
            total += dst_size;
            if (total > MAX_DECOMP) { LZ4F_freeDecompressionContext(ctx); fclose(f); unlink(path); return -1; }
            fwrite(out, 1, dst_size, f);
        }
        if (r == 0) break;                                              /* frame complete */
        if (src_size == 0 && dst_size == 0) break;
    }
    LZ4F_freeDecompressionContext(ctx);
    fclose(f);
    if (total == 0) { unlink(path); return -1; }
    fill_result(out_res, path, "lz4", offset, consumed, total);
    return 0;
}
#else
int extract_have_lz4(void) { return 0; }
int extract_lz4(const uint8_t *d, size_t s, size_t o, const char *dir, extract_result_t *r) { (void)d; (void)s; (void)o; (void)dir; (void)r; return -1; }
#endif

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
                case SIG_BZIP2:
                    ok = extract_bzip2(data, size, fd->offset, out_dir, &res);
                    break;
                case SIG_ZSTD:
                    ok = extract_zstd(data, size, fd->offset, out_dir, &res);
                    break;
                case SIG_LZ4:
                    ok = extract_lz4(data, size, fd->offset, out_dir, &res);
                    break;
                case SIG_CRAMFS: {
                    size_t used = cramfs_size(data, size, fd->offset);
                    if (used == 0) break;
                    char sub[512];
                    snprintf(sub, sizeof(sub), "%s/cramfs-0x%zx", out_dir, fd->offset);
                    if (cramfs_extract(data, size, fd->offset, sub) == 0) {
                        fill_result(&res, sub, "cramfs", fd->offset, used, 0);
                        ok = 0;
                    }
                    break;
                }
                case SIG_JFFS2_LE:
                case SIG_JFFS2_BE: {
                    char sub[512];
                    snprintf(sub, sizeof(sub), "%s/jffs2-0x%zx", out_dir, fd->offset);
                    size_t span = 0, nfiles = 0, unsup = 0;
                    if (jffs2_extract(data, size, fd->offset, fd->type == SIG_JFFS2_BE, sub, &span, &nfiles, &unsup) == 0) {
                        fill_result(&res, sub, "jffs2", fd->offset, span, 0);
                        ok = 0;
                    }
                    break;
                }
                case SIG_UBI: {
                    char sub[512];
                    snprintf(sub, sizeof(sub), "%s/ubi-0x%zx", out_dir, fd->offset);
                    if (ubi_extract(data, size, fd->offset, sub) == 0) {
                        fill_result(&res, sub, "ubi", fd->offset, size - fd->offset, 0);
                        ok = 0;
                    }
                    break;
                }
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
