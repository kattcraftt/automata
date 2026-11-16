/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_ELF_H
#define AUTOMATA_ELF_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t ei_class;
    uint8_t ei_data;
    uint16_t e_type;
    uint16_t e_machine;
    int has_nx;
    int has_relro;
    int has_bind_now;
    int is_pie;
    int is_stripped;
    int has_gnu_stack;  /* PT_GNU_STACK present: NX can only be judged when it is */
    int has_interp;     /* PT_INTERP present */
    int kind;           /* elf_kind_t */
    uint32_t caps;      /* ELFCAP_* bits from imports/strings (executables only) */
    int risk;           /* 0 none, 1 low, 2 medium, 3 high */
    char risk_note[220];
    char path[256];     /* file inside an extracted tree; empty = raw image */
} elf_info_t;

/* Capabilities inferred from the dynamic symbol names an executable imports */
#define ELFCAP_EXEC     0x001   /* exec*, posix_spawn */
#define ELFCAP_SYSTEM   0x002   /* system, popen: a shell command string */
#define ELFCAP_LISTEN   0x004
#define ELFCAP_ACCEPT   0x008
#define ELFCAP_BIND     0x010
#define ELFCAP_DUP      0x020   /* dup2, dup3: redirect stdio to a socket */
#define ELFCAP_CONNECT  0x040
#define ELFCAP_UNSAFE   0x080   /* gets, strcpy, strcat, sprintf, vsprintf */
#define ELFCAP_SHELLSTR 0x100   /* contains "/bin/sh" and friends */
#define ELFCAP_SOCKET   0x200

typedef enum {
    ELF_KIND_UNKNOWN = 0,
    ELF_KIND_RELOCATABLE,   /* .o / kernel modules: NX, PIE and RELRO do not apply */
    ELF_KIND_EXEC,          /* non-PIE executable */
    ELF_KIND_PIE,           /* ET_DYN with an interpreter */
    ELF_KIND_SHARED,        /* shared library: PIE does not apply */
    ELF_KIND_CORE
} elf_kind_t;

int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info);
int elf_parse_file(const char *path, elf_info_t *out_info);
const char *elf_arch_string(uint16_t e_machine);

/* Strict ELF header sanity check (class, endianness, version, type, machine,
 * program header entry size). Rejects stray "\x7fELF" byte sequences that are
 * not real headers. Returns 1 if the header looks genuine. */
int elf_header_valid(const uint8_t *data, size_t size);

/* "Full" (RELRO + BIND_NOW), "Partial" (RELRO only) or "None". */
const char *elf_relro_string(const elf_info_t *info);

/* Inspect imports and strings of an executable and set info->caps / risk / risk_note.
 * info->path should already be set (the base name is used to recognise expected remote-access services). */
void elf_review(const uint8_t *data, size_t size, elf_info_t *info);
const char *elf_risk_string(int risk);
const char *elf_kind_string(const elf_info_t *info);   /* "executable", "PIE executable", "shared object", "relocatable" */
const char *elf_pie_string(const elf_info_t *info);    /* "yes", "no", "n/a" */
const char *elf_nx_string(const elf_info_t *info);     /* "yes", "no", "unknown" (no PT_GNU_STACK), "n/a" */

#endif /* AUTOMATA_ELF_H */
