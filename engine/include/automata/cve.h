/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_CVE_H
#define AUTOMATA_CVE_H

#include "automata/sbom.h"

typedef struct {
    char cve_id[20];
    char component[128];
    char introduced_version[64]; /* first vulnerable version (inclusive); empty = no lower bound */
    char affected_version[64];
    char fixed_version[64];
    char severity[16];      /* CRITICAL, HIGH, MEDIUM, LOW */
    char description[256];
} cve_entry_t;

/* Check detected components against known CVE database.
 * Returns 0 on success. */
int cve_check(const component_t *components, size_t num_components,
              cve_entry_t *out, size_t max, size_t *out_count);

#endif /* AUTOMATA_CVE_H */
