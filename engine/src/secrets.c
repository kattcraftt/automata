/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/secrets.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

const char *secret_type_string(secret_type_t type) {
    switch (type) {
        case PRIVATE_KEY: return "PRIVATE_KEY";
        case CERTIFICATE: return "CERTIFICATE";
        case PASSWORD: return "PASSWORD";
        case API_KEY: return "API_KEY";
        case SSH_KEY: return "SSH_KEY";
        case AWS_KEY: return "AWS_KEY";
        case GENERIC_TOKEN: return "GENERIC_TOKEN";
        case HARDCODED_CRED: return "HARDCODED_CRED";
        default: return "UNKNOWN";
    }
}

typedef struct {
    const char *pattern;
    size_t len;
    secret_type_t type;
    float confidence;
    const char *description;
    int case_insensitive;    /* 1 = use tolower comparison */
    int needs_alnum_check;   /* 1 = verify N alnum chars follow */
    int alnum_count;         /* how many alnum chars to verify */
    int text_only;           /* 1 = keyword pattern: ignored in compiled binaries and web UI files */
    int value_check;         /* 1 = a literal value must follow (not "$var", "%s", "{x}", "a.b.c", label text) */
    int pem_body;            /* 1 = a base64 body must follow the BEGIN line */
    int special;             /* 1 = admin: credential logic, 2 = AWS key boundaries */
} secret_pattern_t;

static const secret_pattern_t patterns[] = {
    { "-----BEGIN RSA PRIVATE KEY-----", 31, PRIVATE_KEY, 1.0f, "RSA Private Key", 0, 0, 0, 0, 0, 1, 0 },
    { "-----BEGIN EC PRIVATE KEY-----", 30, PRIVATE_KEY, 1.0f, "EC Private Key", 0, 0, 0, 0, 0, 1, 0 },
    { "-----BEGIN PRIVATE KEY-----", 27, PRIVATE_KEY, 1.0f, "PEM Private Key", 0, 0, 0, 0, 0, 1, 0 },
    { "-----BEGIN DSA PRIVATE KEY-----", 31, PRIVATE_KEY, 1.0f, "DSA Private Key", 0, 0, 0, 0, 0, 1, 0 },
    { "-----BEGIN CERTIFICATE-----", 27, CERTIFICATE, 0.9f, "X.509 Certificate", 0, 0, 0, 0, 0, 1, 0 },
    { "-----BEGIN SSH", 14, SSH_KEY, 1.0f, "SSH Key", 0, 0, 0, 0, 0, 1, 0 },
    { "ssh-rsa AAAA", 12, SSH_KEY, 0.9f, "SSH RSA Public Key", 0, 0, 0, 0, 0, 0, 0 },
    { "ssh-ed25519 AAAA", 16, SSH_KEY, 0.9f, "SSH Ed25519 Public Key", 0, 0, 0, 0, 0, 0, 0 },
    { "AKIA", 4, AWS_KEY, 0.8f, "AWS Access Key", 0, 0, 0, 1, 0, 0, 2 },
    { "password=", 9, PASSWORD, 0.6f, "Hardcoded password", 1, 0, 0, 1, 1, 0, 0 },
    { "passwd=", 7, PASSWORD, 0.6f, "Hardcoded password", 1, 0, 0, 1, 1, 0, 0 },
    { "secret_key=", 11, GENERIC_TOKEN, 0.7f, "Secret key assignment", 0, 0, 0, 1, 1, 0, 0 },
    { "api_key=", 8, API_KEY, 0.7f, "API key assignment", 0, 0, 0, 1, 1, 0, 0 },
    { "token=", 6, GENERIC_TOKEN, 0.5f, "Token assignment", 0, 0, 0, 1, 1, 0, 0 },
    { "Authorization: Bearer ", 22, GENERIC_TOKEN, 0.7f, "Bearer token", 0, 0, 0, 1, 1, 0, 0 },
    { "root:$", 6, HARDCODED_CRED, 0.9f, "Root shadow entry", 0, 0, 0, 1, 0, 0, 0 },
    { "admin:", 6, HARDCODED_CRED, 0.5f, "Admin credential", 0, 0, 0, 1, 0, 0, 1 }
};

static const size_t num_patterns = sizeof(patterns) / sizeof(patterns[0]);

static int is_b64(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

/* A real PEM block has a base64 body after the BEGIN line. Libraries such as mbedTLS carry the
 * header text as a parser constant with nothing after it. `pos` is just after the matched text. */
static int pem_has_body(const uint8_t *d, size_t size, size_t pos) {
    size_t i = pos;
    /* finish the BEGIN line (the SSH pattern stops mid-line) */
    size_t limit = (i + 80 < size) ? i + 80 : size;
    while (i < limit && d[i] != '\n') i++;
    if (i >= size) return 0;
    i++;
    size_t b64 = 0;
    size_t end = (i + 8192 < size) ? i + 8192 : size;
    while (i < end) {
        /* skip header lines such as "Proc-Type: 4,ENCRYPTED" and blank lines */
        size_t ls = i;
        size_t le = ls;
        int has_colon = 0;
        while (le < end && d[le] != '\n') { if (d[le] == ':') has_colon = 1; le++; }
        if (le < end && d[le] == '\n') { /* complete line */ } else if (le >= end && le < size) { break; }
        if (has_colon) { i = le + 1; continue; }
        size_t line_b64 = 0;
        for (size_t k = ls; k < le; k++) {
            if (d[k] == '\r' || d[k] == ' ') continue;
            if (!is_b64(d[k])) { return b64 >= 40; }   /* "-----END", NUL, anything else ends the body */
            line_b64++;
        }
        b64 += line_b64;
        if (b64 >= 40) return 1;
        i = le + 1;
    }
    return b64 >= 40;
}

/* Locate the value after "key=". Returns its length (0 = nothing usable). */
static size_t value_span(const uint8_t *d, size_t size, size_t pos, size_t *start_out, int *quoted_out) {
    if (pos >= size) return 0;
    uint8_t q = 0;
    if (d[pos] == '"' || d[pos] == '\'') { q = d[pos]; pos++; }
    size_t start = pos, n = 0;
    if (q) {
        while (pos + n < size && n < 128 && d[pos + n] >= 0x20 && d[pos + n] < 0x7f && d[pos + n] != q) n++;
        if (pos + n >= size || d[pos + n] != q) return 0;       /* unterminated: not a literal */
    } else {
        while (pos + n < size) {
            uint8_t c = d[pos + n];
            if (c <= 0x20 || c > 0x7e || c == '"' || c == '\'' || c == '&' || c == ';' || c == '|' || c == ',' || c == ')') break;
            n++;
        }
    }
    *start_out = start;
    *quoted_out = q != 0;
    return n;
}

/* A hard-coded value is a literal: not empty, not a variable/format reference, not code such as
 * "cf.pwd.value", and not a multi-word UI label such as "Nuova password". */
static int value_is_literal(const uint8_t *v, size_t n, int quoted) {
    if (n < 4) return 0;
    if (v[0] == '$' || v[0] == '%' || v[0] == '{' || v[0] == '<' || v[0] == '(' || v[0] == '@' || v[0] == '[') return 0;
    int has_dot = 0, ident_chain = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = v[i];
        if (quoted && (c == ' ' || c == '\t')) return 0;         /* label text */
        if (c == '(' || c == '[') return 0;                       /* function call / index: code */
        if (c == '.') {
            has_dot = 1;
            if (i + 1 >= n || !(isalpha(v[i + 1]) || v[i + 1] == '_')) ident_chain = 0;
        } else if (!(isalnum(c) || c == '_')) {
            ident_chain = 0;
        }
    }
    if (has_dot && ident_chain && (isalpha(v[0]) || v[0] == '_')) return 0;   /* member access */
    return 1;
}

static int is_hex_str(const uint8_t *v, size_t n) {
    for (size_t i = 0; i < n; i++) if (!isxdigit(v[i])) return 0;
    return n > 0;
}

/* Turn a password value into something more precise when it is a hash, or a hash of a well-known default. */
static void classify_password_value(const uint8_t *v, size_t n, secret_type_t *type, float *conf, char *desc, size_t desc_sz) {
    static const struct { const char *md5; const char *plain; } known[] = {
        { "5f4dcc3b5aa765d61d8327deb882cf99", "password" },
        { "21232f297a57a5a743894a0e4a801fc3", "admin" },
        { "81dc9bdb52d04dc20036dbd8313ed055", "1234" },
        { "e10adc3949ba59abbe56e057f20f883e", "123456" },
        { "827ccb0eea8a706c4c34a16891f84e7b", "12345" },
        { "d41d8cd98f00b204e9800998ecf8427e", "" }
    };
    if (n == 32 && is_hex_str(v, n)) {
        char low[33];
        for (size_t i = 0; i < 32; i++) low[i] = (char)tolower(v[i]);
        low[32] = '\0';
        for (size_t k = 0; k < sizeof(known) / sizeof(known[0]); k++) {
            if (strcmp(low, known[k].md5) == 0) {
                *type = HARDCODED_CRED;
                *conf = 0.95f;
                snprintf(desc, desc_sz, "Default password hash (MD5 of \"%s\")", known[k].plain);
                return;
            }
        }
        *conf = 0.8f;
        snprintf(desc, desc_sz, "Unsalted MD5 password hash");
        return;
    }
    if (n >= 20 && v[0] == '$' ) return;   /* value_is_literal already rejects '$'; kept for clarity */
}

static int looks_binary(const uint8_t *d, size_t size) {
    size_t n = size < 4096 ? size : 4096;
    return n > 0 && memchr(d, 0, n) != NULL;
}

int secrets_scan(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count) {
    return secrets_scan_ex(data, size, out_findings, max_findings, out_count, 0);
}

int secrets_scan_ex(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count, unsigned flags) {
    if (data == NULL || out_findings == NULL || out_count == NULL) return -1;
    size_t count = 0;
    int binary = (flags & SECRETS_F_BINARY) != 0 || ((flags & SECRETS_F_AUTODETECT) && looks_binary(data, size));
    int webui = (flags & SECRETS_F_WEBUI) != 0;

    /* First-byte buckets: one table lookup per input byte instead of one compare per pattern */
    uint8_t bucket[256][16];
    uint8_t nb[256];
    memset(nb, 0, sizeof(nb));
    for (size_t p = 0; p < num_patterns; p++) {
        unsigned char c = (unsigned char)patterns[p].pattern[0];
        unsigned char lo = (unsigned char)tolower(c), up = (unsigned char)toupper(c);
        if (nb[c] < 16) bucket[c][nb[c]++] = (uint8_t)p;
        if (patterns[p].case_insensitive) {
            if (lo != c && nb[lo] < 16) bucket[lo][nb[lo]++] = (uint8_t)p;
            if (up != c && up != lo && nb[up] < 16) bucket[up][nb[up]++] = (uint8_t)p;
        }
    }

    for (size_t i = 0; i < size && count < max_findings; ) {
        uint8_t b0 = data[i];
        if (nb[b0] == 0) { i++; continue; }

        int matched = 0;
        size_t match_len = 0;
        for (uint8_t bi = 0; bi < nb[b0] && !matched; bi++) {
            const secret_pattern_t *pat = &patterns[bucket[b0][bi]];
            if (size - i < pat->len) continue;
            int match = 1;
            if (pat->case_insensitive) {
                for (size_t k = 0; k < pat->len; k++)
                    if (tolower((unsigned char)data[i + k]) != tolower((unsigned char)pat->pattern[k])) { match = 0; break; }
            } else if (memcmp(data + i, pat->pattern, pat->len) != 0) {
                match = 0;
            }
            if (!match) continue;

            if (pat->text_only && (binary || webui)) continue;
            size_t after = i + pat->len;
            if (pat->pem_body && !pem_has_body(data, size, after)) continue;

            secret_type_t type = pat->type;
            float conf = pat->confidence;
            char desc[128];
            snprintf(desc, sizeof(desc), "%s", pat->description);

            if (pat->value_check) {
                size_t vs = 0;
                int quoted = 0;
                size_t vn = value_span(data, size, after, &vs, &quoted);
                if (!value_is_literal(data + vs, vn, quoted)) continue;
                if (pat->type == PASSWORD) classify_password_value(data + vs, vn, &type, &conf, desc, sizeof(desc));
            }

            if (pat->special == 2) {                       /* AWS access key id: AKIA + 16 of [A-Z2-7], on word boundaries */
                if (i > 0 && isalnum(data[i - 1])) continue;
                if (size - after < 16) continue;
                int ok = 1;
                for (int k = 0; k < 16; k++) {
                    uint8_t c = data[after + k];
                    if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'))) { ok = 0; break; }
                }
                if (!ok) continue;
                if (after + 16 < size && isalnum(data[after + 16])) continue;
            }
            if (pat->special == 1) {                       /* "admin:" is a credential only when a password or hash follows */
                if (after >= size) continue;
                uint8_t c = data[after];
                if (c == ':' || c == '*' || c == '!' || (c == 'x' && after + 1 < size && data[after + 1] == ':')) continue; /* passwd/group entry */
                if (c == '$') {
                    conf = 0.9f;
                    snprintf(desc, sizeof(desc), "Admin password hash");
                } else {
                    size_t vs = 0;
                    int quoted = 0;
                    size_t vn = value_span(data, size, after, &vs, &quoted);
                    if (!value_is_literal(data + vs, vn, quoted)) continue;
                }
            }

            secret_finding_t *f = &out_findings[count];
            f->offset = i;
            f->type = type;
            f->confidence = conf;
            snprintf(f->description, sizeof(f->description), "%s", desc);
            f->source[0] = '\0';

            size_t ctx_start = (i >= 32) ? (i - 32) : 0;
            size_t ctx_end = (i + 32 <= size) ? (i + 32) : size;
            size_t ctx_len = ctx_end - ctx_start;
            if (ctx_len >= sizeof(f->context)) ctx_len = sizeof(f->context) - 1;
            for (size_t c = 0; c < ctx_len; c++) {
                uint8_t byte = data[ctx_start + c];
                f->context[c] = (byte < 0x20 || byte > 0x7e) ? '.' : (char)byte;
            }
            f->context[ctx_len] = '\0';

            count++;
            matched = 1;
            match_len = pat->len;
        }

        i += matched ? match_len : 1;
    }

    *out_count = count;
    return 0;
}
