/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_HASH_H
#define AUTOMATA_HASH_H

#include <stdint.h>
#include <stddef.h>

uint32_t hash_fnv1a(const uint8_t *data, size_t size);
size_t mem_diff_count(const uint8_t *a, const uint8_t *b, size_t size);
void sha256_hash(const uint8_t *data, size_t size, uint8_t out[32]);

#endif /* AUTOMATA_HASH_H */
