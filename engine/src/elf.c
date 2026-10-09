/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/elf.h"
#include "automata/util.h"
#include <string.h>

#define EI_CLASS 4
#define EI_DATA 5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2
#define PT_GNU_STACK 0x6474e551
#define PT_GNU_RELRO 0x6474e552

int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info) {
    if (data == NULL || out_info == NULL || size < 64) return -1;
    
    // Check magic
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        return -1;
    }

    memset(out_info, 0, sizeof(elf_info_t));
    out_info->ei_class = data[EI_CLASS];
    out_info->ei_data = data[EI_DATA];
    
    int is_le = (out_info->ei_data == ELFDATA2LSB);
    
    uint16_t (*read_u16)(const uint8_t *, size_t, size_t) = is_le ? read_u16_le : read_u16_be;
    uint32_t (*read_u32)(const uint8_t *, size_t, size_t) = is_le ? read_u32_le : read_u32_be;
    uint64_t (*read_u64)(const uint8_t *, size_t, size_t) = is_le ? read_u64_le : read_u64_be;

    out_info->e_type = read_u16(data, size, 16);
    out_info->e_machine = read_u16(data, size, 18);
    out_info->is_pie = (out_info->e_type == 3); // ET_DYN

    size_t phoff = 0;
    size_t phentsize = 0;
    size_t phnum = 0;
    
    size_t shoff = 0;
    size_t shentsize = 0;
    size_t shnum = 0;

    if (out_info->ei_class == ELFCLASS32) {
        phoff = read_u32(data, size, 28);
        phentsize = read_u16(data, size, 42);
        phnum = read_u16(data, size, 44);
        shoff = read_u32(data, size, 32);
        shentsize = read_u16(data, size, 46);
        shnum = read_u16(data, size, 48);
    } else if (out_info->ei_class == ELFCLASS64) {
        phoff = read_u64(data, size, 32);
        phentsize = read_u16(data, size, 54);
        phnum = read_u16(data, size, 56);
        shoff = read_u64(data, size, 40);
        shentsize = read_u16(data, size, 58);
        shnum = read_u16(data, size, 60);
    } else {
        return -1;
    }

    out_info->has_nx = 0;
    for (size_t i = 0; i < phnum; i++) {
        size_t poff = phoff + i * phentsize;
        if (poff + phentsize > size) break;
        uint32_t p_type = read_u32(data, size, poff);
        if (p_type == PT_GNU_STACK) {
            uint32_t p_flags = 0;
            if (out_info->ei_class == ELFCLASS32) {
                p_flags = read_u32(data, size, poff + 24);
            } else {
                p_flags = read_u32(data, size, poff + 4);
            }
            if ((p_flags & 1) == 0) {
                out_info->has_nx = 1;
            }
        } else if (p_type == PT_GNU_RELRO) {
            out_info->has_relro = 1;
        }
    }

    out_info->is_stripped = 1;
    for (size_t i = 0; i < shnum; i++) {
        size_t soff = shoff + i * shentsize;
        if (soff + shentsize > size) break;
        uint32_t sh_type = read_u32(data, size, soff + 4);
        if (sh_type == 2) {
            out_info->is_stripped = 0;
            break;
        }
    }
    
    return 0;
}

int elf_parse_file(const char *path, elf_info_t *out_info) {
    if (path == NULL || out_info == NULL) return -1;
    mapped_file_t mapped;
    if (map_file(path, &mapped) < 0) return -1;
    int res = elf_parse_buf(mapped.data, mapped.size, out_info);
    unmap_file(&mapped);
    return res;
}

const char *elf_arch_string(uint16_t e_machine) {
    switch (e_machine) {
        case 3: return "x86";
        case 8: return "MIPS";
        case 40: return "ARM";
        case 62: return "x86_64";
        case 183: return "AArch64";
        default: return "Unknown";
    }
}
