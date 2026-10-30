/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/tree.h"
#include "automata/identify.h"
#include "automata/extract.h"
#include "automata/util.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define TREE_MAX_DIR_DEPTH 64
#define NESTED_SUFFIX ".nested"
#define PER_FILE_SECRETS 64
#define PER_FILE_COMPONENTS 16
#define NESTED_MAX_RESULTS 32

typedef struct {
    const char *base;
    const tree_limits_t *lim;
    tree_results_t *out;
} tree_ctx_t;

void tree_limits_default(tree_limits_t *lim) {
    if (!lim) return;
    lim->analyze = 1;
    lim->recursive = 0;
    lim->max_depth = 4;
    lim->max_file_size = (size_t)64 * 1024 * 1024;
    lim->max_files = 200000;
    lim->max_total_bytes = (uint64_t)4 * 1024 * 1024 * 1024;
}

static const char *label_for(const tree_ctx_t *c, const char *path) {
    size_t n = c->base ? strlen(c->base) : 0;
    if (n > 0 && strncmp(path, c->base, n) == 0 && (path[n] == '/' || path[n] == '\0')) {
        const char *p = path + n;
        while (*p == '/') p++;
        if (*p != '\0') return p;
    }
    return path;
}

static int is_container(sig_type_t t) {
    return t == SIG_GZIP || t == SIG_XZ || t == SIG_LZMA ||
           t == SIG_SQUASHFS_LE || t == SIG_SQUASHFS_BE;
}

static void add_component(tree_results_t *o, const component_t *c, const char *label) {
    for (size_t i = 0; i < o->num_components; i++) {
        if (strcasecmp(o->components[i].name, c->name) == 0 &&
            strcmp(o->components[i].version, c->version) == 0) return;
    }
    if (o->num_components >= o->max_components) { o->truncated = 1; return; }
    component_t *d = &o->components[o->num_components++];
    *d = *c;
    safe_strncpy(d->location, label, sizeof(d->location));
}

static void walk(tree_ctx_t *c, const char *dir, int depth, int dir_depth);

static void process_file(tree_ctx_t *c, const char *path, const struct stat *st, int depth) {
    tree_results_t *o = c->out;
    const tree_limits_t *lim = c->lim;

    if (st->st_size <= 0) return;
    size_t size = (size_t)st->st_size;
    if (o->files_scanned + o->files_skipped >= lim->max_files) { o->truncated = 1; return; }
    if (size > lim->max_file_size) { o->files_skipped++; return; }
    if (o->bytes_total + size > lim->max_total_bytes) { o->truncated = 1; o->files_skipped++; return; }

    mapped_file_t mf;
    if (map_file(path, &mf) != 0) { o->files_skipped++; return; }
    o->files_scanned++;
    o->bytes_total += size;
    const char *label = label_for(c, path);

    int unpacked = 0;   /* container whose contents were scanned instead: skip its raw (compressed) bytes */
    if (lim->recursive && depth < lim->max_depth && o->bytes_total < lim->max_total_bytes) {
        finding_t hdr;
        if (identify_header(mf.data, mf.size, &hdr) && is_container(hdr.type)) {
            char nested[4096];
            int n = snprintf(nested, sizeof(nested), "%s%s", path, NESTED_SUFFIX);
            if (n > 0 && (size_t)n < sizeof(nested)) {
                extract_result_t res[NESTED_MAX_RESULTS];
                size_t nres = 0;
                extract_all(mf.data, mf.size, nested, res, NESTED_MAX_RESULTS, &nres);
                for (size_t i = 0; i < nres; i++) o->bytes_total += res[i].decompressed;
                if (nres > 0) {
                    o->nested_extractions += nres;
                    unpacked = 1;
                    walk(c, nested, depth + 1, 0);
                }
            }
        }
    }
    if (lim->analyze && !unpacked) {
        if (elf_header_valid(mf.data, mf.size)) {
            if (o->num_elfs < o->max_elfs) {
                elf_info_t *e = &o->elfs[o->num_elfs];
                if (elf_parse_buf(mf.data, mf.size, e) == 0) {
                    safe_strncpy(e->path, label, sizeof(e->path));
                    o->num_elfs++;
                }
            } else {
                o->truncated = 1;
            }
        }

        secret_finding_t sec[PER_FILE_SECRETS];
        size_t nsec = 0;
        if (secrets_scan(mf.data, mf.size, sec, PER_FILE_SECRETS, &nsec) == 0) {
            for (size_t i = 0; i < nsec; i++) {
                if (o->num_secrets >= o->max_secrets) { o->truncated = 1; break; }
                secret_finding_t *d = &o->secrets[o->num_secrets++];
                *d = sec[i];
                safe_strncpy(d->source, label, sizeof(d->source));
            }
        }

        component_t comps[PER_FILE_COMPONENTS];
        size_t ncomp = 0;
        if (sbom_scan(mf.data, mf.size, comps, PER_FILE_COMPONENTS, &ncomp) == 0) {
            for (size_t i = 0; i < ncomp; i++) add_component(o, &comps[i], label);
        }
    }

    unmap_file(&mf);
}

static void walk(tree_ctx_t *c, const char *dir, int depth, int dir_depth) {
    if (dir_depth > TREE_MAX_DIR_DEPTH) { c->out->truncated = 1; return; }

    struct dirent **list = NULL;
    int n = scandir(dir, &list, NULL, alphasort);     /* sorted: reproducible reports */
    if (n < 0) return;

    for (int i = 0; i < n; i++) {
        const char *name = list[i]->d_name;
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            int len = snprintf(path, sizeof(path), "%s/%s", dir, name);
            struct stat st;
            if (len > 0 && (size_t)len < sizeof(path) && lstat(path, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    size_t nl = strlen(name), sl = strlen(NESTED_SUFFIX);
                    /* *.nested directories are produced by (and walked from) their parent archive */
                    if (!(nl >= sl && strcmp(name + nl - sl, NESTED_SUFFIX) == 0))
                        walk(c, path, depth, dir_depth + 1);
                } else if (S_ISREG(st.st_mode)) {
                    process_file(c, path, &st, depth);
                }
                /* symlinks, devices, fifos, sockets: skipped, never followed */
            }
        }
        free(list[i]);
    }
    free(list);
}

int tree_scan(const char *label_base, const char *path, const tree_limits_t *lim, tree_results_t *out) {
    if (!path || !out) return -1;
    tree_limits_t defaults;
    if (!lim) { tree_limits_default(&defaults); lim = &defaults; }

    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    tree_ctx_t c = { label_base, lim, out };
    if (S_ISDIR(st.st_mode)) walk(&c, path, 0, 0);
    else if (S_ISREG(st.st_mode)) process_file(&c, path, &st, 0);
    else return -1;
    return 0;
}
