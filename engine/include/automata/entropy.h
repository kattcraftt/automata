/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_ENTROPY_H
#define AUTOMATA_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

double entropy_calculate(const uint8_t *data, size_t size);
void entropy_sliding_window(const uint8_t *data, size_t size, size_t window_size, double *out_entropies, size_t *out_count);
void entropy_byte_histogram(const uint8_t *data, size_t size, size_t histogram[256]);

typedef struct {
    double *values;
    size_t count;
    size_t window_size;
    size_t step_size;
} entropy_map_t;

int entropy_sliding_map(const uint8_t *data, size_t size,
                        size_t window_size, size_t step_size,
                        entropy_map_t *out);
void entropy_map_free(entropy_map_t *map);

#endif /* AUTOMATA_ENTROPY_H */
