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
} elf_info_t;

int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info);
int elf_parse_file(const char *path, elf_info_t *out_info);
const char *elf_arch_string(uint16_t e_machine);

#endif /* AUTOMATA_ELF_H */
