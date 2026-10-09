/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/entropy.h"
#include <math.h>

double entropy_calculate(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) return 0.0;
    size_t counts[256] = {0};
    entropy_byte_histogram(data, size, counts);
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void entropy_sliding_window(const uint8_t *data, size_t size, size_t window_size, double *out_entropies, size_t *out_count) {
    if (data == NULL || size == 0 || window_size == 0 || out_entropies == NULL || out_count == NULL) return;
    size_t count = 0;
    for (size_t i = 0; i + window_size <= size; i += window_size / 2) {
        out_entropies[count++] = entropy_calculate(data + i, window_size);
    }
    *out_count = count;
}

void entropy_byte_histogram(const uint8_t *data, size_t size, size_t histogram[256]) {
    if (data == NULL || histogram == NULL) return;
    for (int i = 0; i < 256; i++) histogram[i] = 0;
    for (size_t i = 0; i < size; i++) {
        histogram[data[i]]++;
    }
}
