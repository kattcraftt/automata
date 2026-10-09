/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_ENTROPY_H
#define AUTOMATA_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

double entropy_calculate(const uint8_t *data, size_t size);
void entropy_sliding_window(const uint8_t *data, size_t size, size_t window_size, double *out_entropies, size_t *out_count);
void entropy_byte_histogram(const uint8_t *data, size_t size, size_t histogram[256]);

#endif /* AUTOMATA_ENTROPY_H */
