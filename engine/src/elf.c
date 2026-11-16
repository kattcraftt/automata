/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/elf.h"
#include "automata/util.h"
#include <string.h>
#include <stdio.h>
#include <strings.h>

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
        if (p_type == 3) out_info->has_interp = 1;      /* PT_INTERP */
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
            out_info->has_gnu_stack = 1;
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

    switch (out_info->e_type) {
        case 1:  out_info->kind = ELF_KIND_RELOCATABLE; break;
        case 2:  out_info->kind = ELF_KIND_EXEC; break;
        case 3:  out_info->kind = out_info->has_interp ? ELF_KIND_PIE : ELF_KIND_SHARED; break;
        case 4:  out_info->kind = ELF_KIND_CORE; break;
        default: out_info->kind = ELF_KIND_UNKNOWN;
    }
    out_info->is_pie = (out_info->kind == ELF_KIND_PIE);

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
        case 4:   return "m68k";
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

const char *elf_kind_string(const elf_info_t *info) {
    if (!info) return "unknown";
    switch (info->kind) {
        case ELF_KIND_RELOCATABLE: return "relocatable";
        case ELF_KIND_EXEC:        return "executable";
        case ELF_KIND_PIE:         return "PIE executable";
        case ELF_KIND_SHARED:      return "shared object";
        case ELF_KIND_CORE:        return "core dump";
        default:                   return "unknown";
    }
}

const char *elf_pie_string(const elf_info_t *info) {
    if (!info) return "n/a";
    if (info->kind == ELF_KIND_PIE) return "yes";
    if (info->kind == ELF_KIND_EXEC) return "no";
    return "n/a";
}

const char *elf_nx_string(const elf_info_t *info) {
    if (!info || info->kind == ELF_KIND_RELOCATABLE || info->kind == ELF_KIND_CORE ||
        info->kind == ELF_KIND_UNKNOWN) return "n/a";
    if (!info->has_gnu_stack) return "unknown";
    return info->has_nx ? "yes" : "no";
}

const char *elf_relro_string(const elf_info_t *info) {
    if (info != NULL && (info->kind == ELF_KIND_RELOCATABLE || info->kind == ELF_KIND_CORE)) return "n/a";
    if (info == NULL || !info->has_relro) return "None";
    return info->has_bind_now ? "Full" : "Partial";
}

/* ── Binary review: imports and strings ── */

static uint32_t rv32(const uint8_t *d, size_t n, size_t o, int le) {
    if (o + 4 > n) return 0;
    return le ? ((uint32_t)d[o] | (uint32_t)d[o+1] << 8 | (uint32_t)d[o+2] << 16 | (uint32_t)d[o+3] << 24)
              : ((uint32_t)d[o] << 24 | (uint32_t)d[o+1] << 16 | (uint32_t)d[o+2] << 8 | (uint32_t)d[o+3]);
}
static uint64_t rv64(const uint8_t *d, size_t n, size_t o, int le) {
    uint64_t lo = rv32(d, n, o, le), hi = rv32(d, n, o + 4, le);
    return le ? (lo | hi << 32) : (lo << 32 | hi);
}
static uint16_t rv16(const uint8_t *d, size_t n, size_t o, int le) {
    if (o + 2 > n) return 0;
    return le ? (uint16_t)(d[o] | d[o+1] << 8) : (uint16_t)(d[o] << 8 | d[o+1]);
}

/* Locate .dynstr through PT_DYNAMIC (DT_STRTAB/DT_STRSZ), which survives stripped section headers. */
static int find_dynstr(const uint8_t *d, size_t n, size_t *off_out, size_t *len_out) {
    int is64 = d[4] == 2, le = d[5] == 1;
    size_t phoff = is64 ? (size_t)rv64(d, n, 32, le) : rv32(d, n, 28, le);
    size_t phentsize = rv16(d, n, is64 ? 54 : 42, le), phnum = rv16(d, n, is64 ? 56 : 44, le);
    if (phoff == 0 || phoff > n || phnum == 0 || phnum > 128 || phentsize < (is64 ? 56u : 32u)) return 0;

    struct { uint64_t off, vaddr, filesz; } load[16];
    size_t nload = 0;
    uint64_t dyn_off = 0, dyn_sz = 0;
    int have_dyn = 0;
    for (size_t i = 0; i < phnum; i++) {
        size_t p = phoff + i * phentsize;
        if (p + phentsize > n) break;
        uint32_t type = rv32(d, n, p, le);
        uint64_t off, vaddr, filesz;
        if (is64) { off = rv64(d, n, p + 8, le); vaddr = rv64(d, n, p + 16, le); filesz = rv64(d, n, p + 32, le); }
        else      { off = rv32(d, n, p + 4, le); vaddr = rv32(d, n, p + 8, le);  filesz = rv32(d, n, p + 16, le); }
        if (type == 1 && nload < 16) { load[nload].off = off; load[nload].vaddr = vaddr; load[nload].filesz = filesz; nload++; }
        if (type == 2) { dyn_off = off; dyn_sz = filesz; have_dyn = 1; }
    }
    if (!have_dyn || dyn_off >= n) return 0;

    uint64_t strtab = 0, strsz = 0;
    size_t ent = is64 ? 16 : 8;
    for (uint64_t o = 0; o + ent <= dyn_sz && dyn_off + o + ent <= n; o += ent) {
        uint64_t tag = is64 ? rv64(d, n, dyn_off + o, le) : rv32(d, n, dyn_off + o, le);
        uint64_t val = is64 ? rv64(d, n, dyn_off + o + 8, le) : rv32(d, n, dyn_off + o + 4, le);
        if (tag == 0) break;
        if (tag == 5) strtab = val;
        if (tag == 10) strsz = val;
    }
    if (strtab == 0 || strsz == 0) return 0;
    for (size_t i = 0; i < nload; i++) {
        if (strtab >= load[i].vaddr && strtab < load[i].vaddr + load[i].filesz) {
            uint64_t off = load[i].off + (strtab - load[i].vaddr);
            if (off >= n) return 0;
            if (off + strsz > n) strsz = n - off;
            *off_out = (size_t)off;
            *len_out = (size_t)strsz;
            return 1;
        }
    }
    return 0;
}

static const struct { const char *name; uint32_t cap; } cap_names[] = {
    { "system", ELFCAP_SYSTEM }, { "popen", ELFCAP_SYSTEM },
    { "execl", ELFCAP_EXEC }, { "execle", ELFCAP_EXEC }, { "execlp", ELFCAP_EXEC }, { "execv", ELFCAP_EXEC },
    { "execve", ELFCAP_EXEC }, { "execvp", ELFCAP_EXEC }, { "execvpe", ELFCAP_EXEC },
    { "posix_spawn", ELFCAP_EXEC }, { "posix_spawnp", ELFCAP_EXEC },
    { "socket", ELFCAP_SOCKET }, { "bind", ELFCAP_BIND }, { "listen", ELFCAP_LISTEN },
    { "accept", ELFCAP_ACCEPT }, { "accept4", ELFCAP_ACCEPT },
    { "dup2", ELFCAP_DUP }, { "dup3", ELFCAP_DUP },
    { "connect", ELFCAP_CONNECT }, { "getaddrinfo", ELFCAP_CONNECT }, { "gethostbyname", ELFCAP_CONNECT },
    { "gets", ELFCAP_UNSAFE }, { "strcpy", ELFCAP_UNSAFE }, { "strcat", ELFCAP_UNSAFE },
    { "sprintf", ELFCAP_UNSAFE }, { "vsprintf", ELFCAP_UNSAFE }
};

static int memfind(const uint8_t *h, size_t hn, const char *needle) {
    size_t nn = strlen(needle);
    if (nn == 0 || hn < nn) return 0;
    const uint8_t *p = h, *end = h + hn - nn + 1;
    while (p < end && (p = memchr(p, needle[0], (size_t)(end - p))) != NULL) {
        if (memcmp(p, needle, nn) == 0) return 1;
        p++;
    }
    return 0;
}

const char *elf_risk_string(int risk) {
    switch (risk) { case 3: return "HIGH"; case 2: return "MEDIUM"; case 1: return "LOW"; default: return "none"; }
}

void elf_review(const uint8_t *data, size_t size, elf_info_t *info) {
    if (!data || !info) return;
    info->caps = 0;
    info->risk = 0;
    info->risk_note[0] = '\0';
    if (info->kind != ELF_KIND_EXEC && info->kind != ELF_KIND_PIE) return;     /* libraries export these functions, they do not call them for us */

    const char *base = strrchr(info->path, '/');
    base = base ? base + 1 : info->path;
    if (strcmp(base, "busybox") == 0) return;                                   /* multi-call binary: every applet is linked in */

    char imports[160] = "";
    size_t doff = 0, dlen = 0, nsyms = 0;
    if (find_dynstr(data, size, &doff, &dlen)) {
        size_t i = 0;
        while (i < dlen) {
            const char *s = (const char *)data + doff + i;
            size_t maxl = dlen - i;
            size_t l = strnlen(s, maxl);
            if (l > 0) nsyms++;
            if (l > 0 && l < 24) {
                for (size_t k = 0; k < sizeof(cap_names) / sizeof(cap_names[0]); k++) {
                    if (strcmp(s, cap_names[k].name) == 0) {
                        if (!(info->caps & cap_names[k].cap) || cap_names[k].cap == ELFCAP_SYSTEM || cap_names[k].cap == ELFCAP_EXEC) {
                            size_t cur = strlen(imports);
                            if (cur + l + 3 < sizeof(imports) && !strstr(imports, s))
                                snprintf(imports + cur, sizeof(imports) - cur, "%s%s", cur ? ", " : "", s);
                        }
                        info->caps |= cap_names[k].cap;
                        break;
                    }
                }
            }
            i += l + 1;
        }
    }
    if (memfind(data, size, "/bin/sh") || memfind(data, size, "/bin/ash") || memfind(data, size, "/bin/bash") || memfind(data, size, "sh -c"))
        info->caps |= ELFCAP_SHELLSTR;

    uint32_t c = info->caps;
    int server = (c & ELFCAP_LISTEN) && (c & ELFCAP_ACCEPT);
    int runs = (c & (ELFCAP_EXEC | ELFCAP_SYSTEM)) != 0;

    static const char *remote_access[] = { "dropbear", "sshd", "telnetd", "utelnetd", "in.telnetd", "ftpd", "vsftpd", "proftpd", "pure-ftpd", "bftpd" };
    static const char *clients[] = { "wget", "curl", "ftp", "tftp", "ping", "ping6", "traceroute", "nc", "ssh", "scp", "rsync" };
    int known = 0, client = 0;
    for (size_t i = 0; i < sizeof(remote_access) / sizeof(remote_access[0]); i++)
        if (strcmp(base, remote_access[i]) == 0) known = 1;
    for (size_t i = 0; i < sizeof(clients) / sizeof(clients[0]); i++)
        if (strcmp(base, clients[i]) == 0) client = 1;       /* clients import bind/listen/accept for active-mode FTP, source addresses, ... */

    /* A backdoor is typically small and links few functions; a full-size daemon that also redirects stdio is just a daemon. */
    int tiny = size < 100 * 1024 && nsyms > 0 && nsyms < 48;

    const char *why = NULL;
    if (server && !client) {
        if ((c & ELFCAP_DUP) && runs && known) {
            info->risk = 2; why = "remote access service: accepts connections, redirects stdio and executes programs (confirm it is meant to be enabled)";
        } else if ((c & ELFCAP_DUP) && runs && tiny) {
            info->risk = 3; why = "bind-shell shape in a small, unrecognised binary: accepts connections, redirects stdio and executes programs";
        } else if (c & ELFCAP_SYSTEM) {
            info->risk = 2; why = "network service that runs shell command strings (system/popen): command-injection surface";
        } else if ((c & ELFCAP_SHELLSTR) && runs) {
            info->risk = 2; why = "network service that can start a shell";
        } else if (c & ELFCAP_UNSAFE) {
            info->risk = 1; why = "network service using unbounded string functions";
        }
    } else if (c & ELFCAP_SYSTEM) {
        info->risk = 1; why = "runs shell command strings (system/popen)";
    }
    if (why) snprintf(info->risk_note, sizeof(info->risk_note), "%s [%s]", why, imports);
}
