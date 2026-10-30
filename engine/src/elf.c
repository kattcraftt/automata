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
#define PT_DYNAMIC 2
#define DT_NULL 0
#define DT_BIND_NOW 24
#define DT_FLAGS 30
#define DT_FLAGS_1 0x6ffffffbULL
#define DF_BIND_NOW 0x8
#define DF_1_NOW 0x1

int elf_header_valid(const uint8_t *data, size_t size) {
    if (data == NULL || size < 52) return 0;
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') return 0;

    uint8_t cls = data[EI_CLASS];
    uint8_t enc = data[EI_DATA];
    if (cls != ELFCLASS32 && cls != ELFCLASS64) return 0;
    if (enc != ELFDATA2LSB && enc != ELFDATA2MSB) return 0;
    if (data[6] != 1) return 0;                         /* EI_VERSION */
    if (cls == ELFCLASS64 && size < 64) return 0;

    int le = (enc == ELFDATA2LSB);
    uint16_t e_type = le ? read_u16_le(data, size, 16) : read_u16_be(data, size, 16);
    uint16_t e_machine = le ? read_u16_le(data, size, 18) : read_u16_be(data, size, 18);
    uint32_t e_version = le ? read_u32_le(data, size, 20) : read_u32_be(data, size, 20);
    if (e_type < 1 || e_type > 4) return 0;             /* REL, EXEC, DYN, CORE */
    if (e_version != 1) return 0;
    if (strcmp(elf_arch_string(e_machine), "Unknown") == 0) return 0;

    uint16_t phentsize, phnum;
    if (cls == ELFCLASS32) {
        phentsize = le ? read_u16_le(data, size, 42) : read_u16_be(data, size, 42);
        phnum = le ? read_u16_le(data, size, 44) : read_u16_be(data, size, 44);
        if (phnum != 0 && phentsize != 32) return 0;
    } else {
        phentsize = le ? read_u16_le(data, size, 54) : read_u16_be(data, size, 54);
        phnum = le ? read_u16_le(data, size, 56) : read_u16_be(data, size, 56);
        if (phnum != 0 && phentsize != 56) return 0;
    }
    return 1;
}

int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info) {
    if (data == NULL || out_info == NULL || size < 64) return -1;
    if (!elf_header_valid(data, size)) return -1;

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
    size_t dyn_off = 0, dyn_sz = 0;
    if (phoff > size) phnum = 0;
    for (size_t i = 0; i < phnum; i++) {
        size_t poff = phoff + i * phentsize;
        if (poff + phentsize > size) break;
        uint32_t p_type = read_u32(data, size, poff);
        if (p_type == PT_DYNAMIC) {
            if (out_info->ei_class == ELFCLASS32) {
                dyn_off = read_u32(data, size, poff + 4);
                dyn_sz = read_u32(data, size, poff + 16);
            } else {
                dyn_off = (size_t)read_u64(data, size, poff + 8);
                dyn_sz = (size_t)read_u64(data, size, poff + 32);
            }
        }
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

    /* BIND_NOW lives in the dynamic section: DT_BIND_NOW, DT_FLAGS & DF_BIND_NOW, DT_FLAGS_1 & DF_1_NOW. */
    if (dyn_sz > 0 && dyn_off < size) {
        size_t ent = (out_info->ei_class == ELFCLASS32) ? 8 : 16;
        for (size_t o = 0; o + ent <= dyn_sz && dyn_off + o + ent <= size; o += ent) {
            uint64_t tag, val;
            if (out_info->ei_class == ELFCLASS32) {
                tag = read_u32(data, size, dyn_off + o);
                val = read_u32(data, size, dyn_off + o + 4);
            } else {
                tag = read_u64(data, size, dyn_off + o);
                val = read_u64(data, size, dyn_off + o + 8);
            }
            if (tag == DT_NULL) break;
            if (tag == DT_BIND_NOW) out_info->has_bind_now = 1;
            else if (tag == DT_FLAGS && (val & DF_BIND_NOW)) out_info->has_bind_now = 1;
            else if (tag == DT_FLAGS_1 && (val & DF_1_NOW)) out_info->has_bind_now = 1;
        }
    }

    if (shoff > size) shnum = 0;
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
        case 2:   return "SPARC";
        case 3:   return "x86";
        case 4:   return "m68K";
        case 8:   return "MIPS";
        case 15:  return "PA-RISC";
        case 20:  return "PowerPC";
        case 21:  return "PowerPC64";
        case 22:  return "S390";
        case 40:  return "ARM";
        case 42:  return "SuperH";
        case 43:  return "SPARC V9";
        case 50:  return "IA-64";
        case 62:  return "x86_64";
        case 92:  return "OpenRISC";
        case 94:  return "Xtensa";
        case 113: return "Nios II";
        case 164: return "Hexagon";
        case 183: return "AArch64";
        case 243: return "RISC-V";
        case 258: return "LoongArch";
        default:  return "Unknown";
    }
}

const char *elf_relro_string(const elf_info_t *info) {
    if (info == NULL || !info->has_relro) return "None";
    return info->has_bind_now ? "Full" : "Partial";
}
