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
    char path[256]; /* file inside an extracted tree; empty = raw image */
} elf_info_t;

int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info);
int elf_parse_file(const char *path, elf_info_t *out_info);
const char *elf_arch_string(uint16_t e_machine);

/* Strict ELF header sanity check (class, endianness, version, type, machine,
 * program header entry size). Rejects stray "\x7fELF" byte sequences that are
 * not real headers. Returns 1 if the header looks genuine. */
int elf_header_valid(const uint8_t *data, size_t size);

/* "Full" (RELRO + BIND_NOW), "Partial" (RELRO only) or "None". */
const char *elf_relro_string(const elf_info_t *info);

#endif /* AUTOMATA_ELF_H */
