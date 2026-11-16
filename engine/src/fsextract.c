/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/fsextract.h"
#include "automata/util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

/* ═══════════════════════════ JFFS2 ═══════════════════════════ */

#define JFFS2_MAGIC          0x1985
#define JFFS2_NODE_DIRENT    0xE001
#define JFFS2_NODE_INODE     0xE002
#define JFFS2_COMPR_NONE     0
#define JFFS2_COMPR_ZERO     1
#define JFFS2_COMPR_RTIME    2
#define JFFS2_COMPR_COPY     4
#define JFFS2_COMPR_ZLIB     6
#define JFFS2_MAX_NODES      2000000u
#define JFFS2_MAX_FILE       ((size_t)256 * 1024 * 1024)
#define JFFS2_MAX_TOTAL      ((size_t)1024 * 1024 * 1024)
#define DT_DIR_ 4
#define DT_REG_ 8
#define DT_LNK_ 10

typedef struct { uint32_t pino, ino, version; uint8_t type; char name[256]; } j_dirent_t;
typedef struct {
    uint32_t ino, version, mode, isize, offset, csize, dsize;
    uint8_t compr;
    size_t data_off;
} j_inode_t;

static uint16_t jr16(const uint8_t *p, int be) { return be ? (uint16_t)(p[0] << 8 | p[1]) : (uint16_t)(p[0] | p[1] << 8); }
static uint32_t jr32(const uint8_t *p, int be) {
    return be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
              : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
}
/* JFFS2 uses a raw CRC32 (init 0, no final xor); zlib's crc32 inverts both ends. */
static uint32_t jcrc(const uint8_t *p, size_t n) { return ~(uint32_t)crc32(0xFFFFFFFFUL, p, (uInt)n); }

static int rtime_decompress(const uint8_t *in, size_t clen, uint8_t *out, size_t dlen) {
    size_t positions[256] = {0};
    size_t pos = 0, outpos = 0;
    while (outpos < dlen) {
        if (pos + 2 > clen) return -1;
        uint8_t value = in[pos++];
        out[outpos++] = value;
        size_t repeat = in[pos++];
        size_t backoffs = positions[value];
        positions[value] = outpos;
        if (repeat) {
            if (outpos + repeat > dlen) return -1;
            while (repeat--) out[outpos++] = out[backoffs++];
        }
    }
    return 0;
}

static int j_decompress(const uint8_t *in, size_t clen, uint8_t compr, uint8_t *out, size_t dlen) {
    switch (compr) {
        case JFFS2_COMPR_NONE:
        case JFFS2_COMPR_COPY:
            if (clen < dlen) return -1;
            memcpy(out, in, dlen);
            return 0;
        case JFFS2_COMPR_ZERO:
            memset(out, 0, dlen);
            return 0;
        case JFFS2_COMPR_RTIME:
            return rtime_decompress(in, clen, out, dlen);
        case JFFS2_COMPR_ZLIB: {
            /* JFFS2 writes a zlib header but ends each node with a sync flush: no end-of-stream and no
             * adler32. Like the kernel, skip the header and inflate raw. */
            int wbits = 15;
            const uint8_t *src = in;
            size_t sl = clen;
            if (clen > 2 && !(in[1] & 0x20) && (in[0] & 0x0f) == 8 && ((in[0] << 8) + in[1]) % 31 == 0) {
                wbits = -((in[0] >> 4) + 8);
                src += 2;
                sl -= 2;
            }
            z_stream z;
            memset(&z, 0, sizeof(z));
            if (inflateInit2(&z, wbits) != Z_OK) return -1;
            z.next_in = (Bytef *)src; z.avail_in = (uInt)sl;
            z.next_out = out; z.avail_out = (uInt)dlen;
            int r = inflate(&z, Z_SYNC_FLUSH);
            size_t got = z.total_out;
            inflateEnd(&z);
            return ((r == Z_OK || r == Z_STREAM_END) && got == dlen) ? 0 : -1;
        }
        default:
            return -2;                 /* lzo, dynrubin, ...: not supported */
    }
}

static int cmp_dirent(const void *a, const void *b) {
    const j_dirent_t *x = a, *y = b;
    if (x->pino != y->pino) return x->pino < y->pino ? -1 : 1;
    int c = strcmp(x->name, y->name);
    if (c) return c;
    if (x->version != y->version) return x->version < y->version ? -1 : 1;
    return 0;
}
static int cmp_inode(const void *a, const void *b) {
    const j_inode_t *x = a, *y = b;
    if (x->ino != y->ino) return x->ino < y->ino ? -1 : 1;
    if (x->version != y->version) return x->version < y->version ? -1 : 1;
    return 0;
}
static int cmp_dirent_ino(const void *a, const void *b) {
    const j_dirent_t *x = *(const j_dirent_t *const *)a, *y = *(const j_dirent_t *const *)b;
    return x->ino < y->ino ? -1 : (x->ino > y->ino ? 1 : 0);
}

static int safe_name(const char *n) {
    if (n[0] == '\0' || strcmp(n, ".") == 0 || strcmp(n, "..") == 0) return 0;
    for (const char *c = n; *c; c++) if (*c == '/' || *c == '\\') return 0;
    return 1;
}

/* Build "dir/sub/name" for a directory entry by walking up through directory entries only. */
static int build_path(j_dirent_t **by_ino, size_t n_by_ino, const j_dirent_t *e, char *out, size_t out_sz) {
    const j_dirent_t *chain[64];
    size_t depth = 0;
    const j_dirent_t *cur = e;
    while (depth < 64) {
        chain[depth++] = cur;
        if (cur->pino == 1) break;                       /* root inode */
        j_dirent_t key = { 0 };
        key.ino = cur->pino;
        j_dirent_t *kp = &key;
        j_dirent_t **hit = bsearch(&kp, by_ino, n_by_ino, sizeof(*by_ino), cmp_dirent_ino);
        if (!hit || (*hit)->type != DT_DIR_) return -1;  /* parent must exist and be a real directory (never a symlink) */
        cur = *hit;
    }
    if (depth >= 64) return -1;
    size_t len = 0;
    out[0] = '\0';
    for (size_t i = depth; i-- > 0; ) {
        int w = snprintf(out + len, out_sz - len, "%s%s", len ? "/" : "", chain[i]->name);
        if (w < 0 || (size_t)w >= out_sz - len) return -1;
        len += (size_t)w;
    }
    return 0;
}

int jffs2_extract(const uint8_t *data, size_t size, size_t offset, int be, const char *out_dir,
                  size_t *out_span, size_t *out_files, size_t *out_unsupported) {
    if (!data || offset >= size || !out_dir) return -1;
    const uint8_t *base = data + offset;
    size_t n = size - offset;

    size_t dcap = 256, ncap = 256, nd = 0, ni = 0;
    j_dirent_t *dirents = malloc(dcap * sizeof(*dirents));
    j_inode_t *inodes = malloc(ncap * sizeof(*inodes));
    if (!dirents || !inodes) { free(dirents); free(inodes); return -1; }

    size_t pos = 0, last_end = 0;
    while (pos + 12 <= n && nd + ni < JFFS2_MAX_NODES) {
        if (jr16(base + pos, be) != JFFS2_MAGIC) { pos += 4; continue; }
        uint16_t type = jr16(base + pos + 2, be);
        uint32_t totlen = jr32(base + pos + 4, be);
        if (jcrc(base + pos, 8) != jr32(base + pos + 8, be) || totlen < 12 || pos + totlen > n) { pos += 4; continue; }
        const uint8_t *nd_p = base + pos;

        if (type == JFFS2_NODE_DIRENT && totlen >= 40) {
            uint8_t nsize = nd_p[28];
            if (40u + nsize <= totlen && jcrc(nd_p, 32) == jr32(nd_p + 32, be) && jcrc(nd_p + 40, nsize) == jr32(nd_p + 36, be)) {
                if (nd == dcap) { dcap *= 2; j_dirent_t *t = realloc(dirents, dcap * sizeof(*dirents)); if (!t) break; dirents = t; }
                j_dirent_t *d = &dirents[nd++];
                d->pino = jr32(nd_p + 12, be);
                d->version = jr32(nd_p + 16, be);
                d->ino = jr32(nd_p + 20, be);
                d->type = nd_p[29];
                memcpy(d->name, nd_p + 40, nsize);
                d->name[nsize] = '\0';
                last_end = pos + totlen;
            }
        } else if (type == JFFS2_NODE_INODE && totlen >= 68) {
            uint32_t csize = jr32(nd_p + 48, be);
            if (68u + csize <= totlen && jcrc(nd_p, 60) == jr32(nd_p + 64, be) && jcrc(nd_p + 68, csize) == jr32(nd_p + 60, be)) {
                if (ni == ncap) { ncap *= 2; j_inode_t *t = realloc(inodes, ncap * sizeof(*inodes)); if (!t) break; inodes = t; }
                j_inode_t *in = &inodes[ni++];
                in->ino = jr32(nd_p + 12, be);
                in->version = jr32(nd_p + 16, be);
                in->mode = jr32(nd_p + 20, be);
                in->isize = jr32(nd_p + 28, be);
                in->offset = jr32(nd_p + 44, be);
                in->csize = csize;
                in->dsize = jr32(nd_p + 52, be);
                in->compr = nd_p[56];
                in->data_off = pos + 68;
                last_end = pos + totlen;
            }
        }
        pos += (totlen + 3u) & ~3u;
    }

    int rc = -1;
    size_t files = 0, unsupported = 0, total_out = 0;
    if (nd == 0) goto done;

    /* newest dirent per (parent, name) wins; ino 0 means the entry was deleted */
    qsort(dirents, nd, sizeof(*dirents), cmp_dirent);
    j_dirent_t **live = malloc(nd * sizeof(*live));
    j_dirent_t **by_ino = malloc(nd * sizeof(*by_ino));
    if (!live || !by_ino) { free(live); free(by_ino); goto done; }
    size_t nlive = 0;
    for (size_t i = 0; i < nd; i++) {
        int newest = (i + 1 == nd) || dirents[i + 1].pino != dirents[i].pino || strcmp(dirents[i + 1].name, dirents[i].name) != 0;
        if (newest && dirents[i].ino != 0 && safe_name(dirents[i].name)) live[nlive++] = &dirents[i];
    }
    memcpy(by_ino, live, nlive * sizeof(*live));
    qsort(by_ino, nlive, sizeof(*by_ino), cmp_dirent_ino);
    qsort(inodes, ni, sizeof(*inodes), cmp_inode);

    mkdirp(out_dir);
    for (size_t pass = 0; pass < 2; pass++) {              /* pass 0: directories, pass 1: files and symlinks */
        for (size_t i = 0; i < nlive; i++) {
            j_dirent_t *e = live[i];
            if ((pass == 0) != (e->type == DT_DIR_)) continue;
            if (e->type != DT_DIR_ && e->type != DT_REG_ && e->type != DT_LNK_) continue;     /* devices, fifos, sockets */

            char rel[1024], full[2048];
            if (build_path(by_ino, nlive, e, rel, sizeof(rel)) != 0) continue;
            if (snprintf(full, sizeof(full), "%s/%s", out_dir, rel) >= (int)sizeof(full)) continue;

            if (e->type == DT_DIR_) { mkdir(full, 0755); continue; }

            /* this inode's data nodes, oldest to newest */
            j_inode_t key = { .ino = e->ino };
            size_t lo = 0, hi = ni;
            while (lo < hi) { size_t mid = (lo + hi) / 2; if (inodes[mid].ino < key.ino) lo = mid + 1; else hi = mid; }
            size_t first = lo, last = lo;
            while (last < ni && inodes[last].ino == e->ino) last++;
            if (first == last) continue;
            size_t isize = inodes[last - 1].isize;
            uint32_t mode = inodes[last - 1].mode;
            if (isize > JFFS2_MAX_FILE || total_out + isize > JFFS2_MAX_TOTAL) continue;

            uint8_t *buf = calloc(isize ? isize : 1, 1);
            if (!buf) continue;
            for (size_t k = first; k < last; k++) {
                const j_inode_t *in = &inodes[k];
                if (in->dsize == 0 || in->dsize > JFFS2_MAX_FILE || (size_t)in->offset + in->dsize < in->offset) continue;
                uint8_t *tmp = malloc(in->dsize);
                if (!tmp) continue;
                int r = j_decompress(base + in->data_off, in->csize, in->compr, tmp, in->dsize);
                if (r == 0) {
                    if (in->offset < isize) {
                        size_t cl = in->dsize;
                        if (in->offset + cl > isize) cl = isize - in->offset;
                        memcpy(buf + in->offset, tmp, cl);
                    }
                } else if (r == -2) {
                    unsupported++;
                }
                free(tmp);
            }

            if (e->type == DT_LNK_) {
                char target[1024];
                size_t tl = isize < sizeof(target) - 1 ? isize : sizeof(target) - 1;
                memcpy(target, buf, tl);
                target[tl] = '\0';
                unlink(full);
                if (symlink(target, full) == 0) files++;
            } else {
                int fd = open(full, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
                if (fd >= 0) {
                    size_t w = 0;
                    while (w < isize) { ssize_t r = write(fd, buf + w, isize - w); if (r <= 0) break; w += (size_t)r; }
                    fchmod(fd, (mode_t)(mode & 0777));
                    close(fd);
                    files++;
                    total_out += isize;
                }
            }
            free(buf);
        }
    }
    free(live);
    free(by_ino);
    rc = files > 0 ? 0 : -1;
done:
    free(dirents);
    free(inodes);
    if (rc == 0) {
        if (out_span) *out_span = last_end;
        if (out_files) *out_files = files;
        if (out_unsupported) *out_unsupported = unsupported;
    }
    return rc;
}

/* ═══════════════════════════ CramFS ═══════════════════════════ */

size_t cramfs_size(const uint8_t *data, size_t size, size_t offset) {
    if (!data || offset >= size || size - offset < 76) return 0;
    const uint8_t *p = data + offset;
    if (memcmp(p, "\x45\x3d\xcd\x28", 4) != 0 || memcmp(p + 16, "Compressed ROMFS", 16) != 0) return 0;
    uint32_t sz = jr32(p + 4, 0);
    if (sz < 76 || sz > size - offset) return 0;
    return sz;
}

static int find_cramfs_tool(char *out, size_t sz) {
    return util_find_in_path("fsck.cramfs", out, sz) || util_find_in_path("cramfsck", out, sz);
}
int cramfs_available(void) { char t[1024]; return find_cramfs_tool(t, sizeof(t)); }

int cramfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir) {
    size_t len = cramfs_size(data, size, offset);
    char tool[1024], tmp[256];
    if (len == 0 || !find_cramfs_tool(tool, sizeof(tool))) return -1;
    if (util_write_temp(data + offset, len, tmp, sizeof(tmp)) != 0) return -1;

    /* the tool wants to create the destination itself */
    char parent[2048];
    snprintf(parent, sizeof(parent), "%s", out_dir);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdirp(parent); }
    char opt[2100];
    snprintf(opt, sizeof(opt), "--extract=%s", out_dir);
    char *argv[] = { "fsck.cramfs", opt, tmp, NULL };
    int rc = util_run(tool, argv);
    unlink(tmp);

    struct stat st;
    if (stat(out_dir, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    return rc == 0 || rc == 4 ? 0 : -1;       /* fsck exit 4 = uncorrected errors but files were still written */
}

/* ═══════════════════════════ UBI / UBIFS ═══════════════════════════ */

int ubi_available(void) { char t[1024]; return util_find_in_path("ubireader_extract_files", t, sizeof(t)); }

int ubi_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir) {
    char tool[1024], tmp[256];
    if (!data || offset >= size || !util_find_in_path("ubireader_extract_files", tool, sizeof(tool))) return -1;
    if (util_write_temp(data + offset, size - offset, tmp, sizeof(tmp)) != 0) return -1;

    char parent[2048];
    snprintf(parent, sizeof(parent), "%s", out_dir);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdirp(parent); }
    char *argv[] = { "ubireader_extract_files", "-o", (char *)out_dir, tmp, NULL };
    int rc = util_run(tool, argv);
    unlink(tmp);

    struct stat st;
    if (stat(out_dir, &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    return rc == 0 ? 0 : -1;
}
