/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/cve.h"
#include "automata/sbom.h"
#include <string.h>
#include <stdlib.h>

int version_compare(const char *a, const char *b) {
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;

    const char *pa = a;
    const char *pb = b;

    /* Skip leading comparison or version prefix symbols */
    while (*pa != '\0' && (*pa == '<' || *pa == '=' || *pa == '>' || *pa == 'v' || *pa == 'V' || *pa == ' ')) {
        pa++;
    }
    while (*pb != '\0' && (*pb == '<' || *pb == '=' || *pb == '>' || *pb == 'v' || *pb == 'V' || *pb == ' ')) {
        pb++;
    }

    while (*pa != '\0' || *pb != '\0') {
        long num_a = 0;
        long num_b = 0;
        char *end_a = (char *)pa;
        char *end_b = (char *)pb;

        if (*pa != '\0') {
            num_a = strtol(pa, &end_a, 10);
        }
        if (*pb != '\0') {
            num_b = strtol(pb, &end_b, 10);
        }

        if (num_a < num_b) return -1;
        if (num_a > num_b) return 1;

        /* Compare suffix letters within current segment (e.g. 'g' vs 'h' in 1.0.1g) */
        const char *sa = end_a;
        const char *sb = end_b;
        while (*sa != '\0' && *sa != '.' && *sb != '\0' && *sb != '.') {
            if (*sa < *sb) return -1;
            if (*sa > *sb) return 1;
            sa++;
            sb++;
        }
        int sa_rem = (*sa != '\0' && *sa != '.');
        int sb_rem = (*sb != '\0' && *sb != '.');
        if (sa_rem && !sb_rem) return 1;
        if (!sa_rem && sb_rem) return -1;

        /* Advance pa to next '.' or end */
        while (*pa != '\0' && *pa != '.') pa++;
        if (*pa == '.') pa++;

        /* Advance pb to next '.' or end */
        while (*pb != '\0' && *pb != '.') pb++;
        if (*pb == '.') pb++;
    }

    return 0;
}

static const cve_entry_t known_cves[] = {
    /* openssl */
    {
        .cve_id = "CVE-2014-0160",
        .component = "openssl",
        .affected_version = "<1.0.1g",
        .fixed_version = "1.0.1g",
        .severity = "CRITICAL",
        .description = "TLS heartbeat read overrun (Heartbleed)"
    },
    {
        .cve_id = "CVE-2014-0224",
        .component = "openssl",
        .affected_version = "<1.0.1h",
        .fixed_version = "1.0.1h",
        .severity = "HIGH",
        .description = "SSL/TLS MITM ChangeCipherSpec injection"
    },
    {
        .cve_id = "CVE-2016-2107",
        .component = "openssl",
        .affected_version = "<1.0.2h",
        .fixed_version = "1.0.2h",
        .severity = "HIGH",
        .description = "Padding oracle in AES-NI CBC MAC check"
    },
    {
        .cve_id = "CVE-2022-0778",
        .component = "openssl",
        .affected_version = "<1.1.1n",
        .fixed_version = "1.1.1n",
        .severity = "HIGH",
        .description = "BN_mod_sqrt() infinite loop via crafted certificate"
    },
    {
        .cve_id = "CVE-2015-0204",
        .component = "openssl",
        .affected_version = "<1.0.1k",
        .fixed_version = "1.0.1k",
        .severity = "HIGH",
        .description = "RSA downgrade vulnerability (FREAK)"
    },

    /* busybox */
    {
        .cve_id = "CVE-2021-42373",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "man applet heap out-of-bounds read"
    },
    {
        .cve_id = "CVE-2021-42374",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "unlzma applet out-of-bounds heap access"
    },
    {
        .cve_id = "CVE-2021-42378",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet use-after-free leading to code execution"
    },
    {
        .cve_id = "CVE-2021-42379",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet next statement use-after-free"
    },
    {
        .cve_id = "CVE-2021-42380",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet clrvar use-after-free"
    },
    {
        .cve_id = "CVE-2021-42381",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet hashpipe use-after-free"
    },
    {
        .cve_id = "CVE-2021-42382",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet getvar_i use-after-free"
    },
    {
        .cve_id = "CVE-2021-42383",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet evaluate use-after-free"
    },
    {
        .cve_id = "CVE-2021-42384",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet handle_asgn use-after-free"
    },
    {
        .cve_id = "CVE-2021-42385",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet nvfree use-after-free"
    },
    {
        .cve_id = "CVE-2021-42386",
        .component = "busybox",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "HIGH",
        .description = "awk applet nvalloc out-of-bounds write"
    },
    {
        .cve_id = "CVE-2022-48174",
        .component = "busybox",
        .affected_version = "<1.36.1",
        .fixed_version = "1.36.1",
        .severity = "CRITICAL",
        .description = "ash shell stack overflow in arithmetic evaluation"
    },

    /* dropbear */
    {
        .cve_id = "CVE-2016-7406",
        .component = "dropbear",
        .affected_version = "<2016.74",
        .fixed_version = "2016.74",
        .severity = "CRITICAL",
        .description = "Format string vulnerability in dbclient and dropbear"
    },
    {
        .cve_id = "CVE-2018-15599",
        .component = "dropbear",
        .affected_version = "<2018.76",
        .fixed_version = "2018.76",
        .severity = "MEDIUM",
        .description = "User enumeration via delay in failed authentication"
    },
    {
        .cve_id = "CVE-2021-36369",
        .component = "dropbear",
        .affected_version = "<2022.82",
        .fixed_version = "2022.82",
        .severity = "HIGH",
        .description = "Improper verification of client requests during auth"
    },

    /* dnsmasq */
    {
        .cve_id = "CVE-2020-25681",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq heap buffer overflow in DNSSEC sort_rrset"
    },
    {
        .cve_id = "CVE-2020-25682",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq buffer overflow in extract_name"
    },
    {
        .cve_id = "CVE-2020-25683",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq heap overflow in get_data"
    },
    {
        .cve_id = "CVE-2020-25687",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq DNS cache poisoning via weak query validation"
    },
    {
        .cve_id = "CVE-2021-3448",
        .component = "dnsmasq",
        .affected_version = "<2.85",
        .fixed_version = "2.85",
        .severity = "MEDIUM",
        .description = "DNS rebind vulnerability with fixed port allocation"
    },

    /* lighttpd */
    {
        .cve_id = "CVE-2019-11072",
        .component = "lighttpd",
        .affected_version = "<1.4.54",
        .fixed_version = "1.4.54",
        .severity = "HIGH",
        .description = "Heap out-of-bounds write in HTTP request parser"
    },
    {
        .cve_id = "CVE-2022-22707",
        .component = "lighttpd",
        .affected_version = "<1.4.64",
        .fixed_version = "1.4.64",
        .severity = "HIGH",
        .description = "mod_extforward out-of-bounds write in IPv6 processing"
    },

    /* curl */
    {
        .cve_id = "CVE-2023-38545",
        .component = "curl",
        .affected_version = "<8.4.0",
        .fixed_version = "8.4.0",
        .severity = "CRITICAL",
        .description = "SOCKS5 heap buffer overflow during hostname resolution"
    },
    {
        .cve_id = "CVE-2022-32221",
        .component = "curl",
        .affected_version = "<7.86.0",
        .fixed_version = "7.86.0",
        .severity = "HIGH",
        .description = "POST-after-PUT data corruption and leak"
    },
    {
        .cve_id = "CVE-2021-22946",
        .component = "curl",
        .affected_version = "<7.79.0",
        .fixed_version = "7.79.0",
        .severity = "MEDIUM",
        .description = "TLS protocol downgrade bypass via plaintext response"
    },

    /* nginx */
    {
        .cve_id = "CVE-2021-23017",
        .component = "nginx",
        .affected_version = "<1.20.1",
        .fixed_version = "1.20.1",
        .severity = "HIGH",
        .description = "1-byte memory overwrite in resolver DNS response processing"
    },
    {
        .cve_id = "CVE-2018-16843",
        .component = "nginx",
        .affected_version = "<1.15.6",
        .fixed_version = "1.15.6",
        .severity = "MEDIUM",
        .description = "Excessive memory consumption in HTTP/2 module"
    },

    /* linux-kernel */
    {
        .cve_id = "CVE-2021-3156",
        .component = "linux-kernel",
        .affected_version = "<5.4.0",
        .fixed_version = "5.4.0",
        .severity = "CRITICAL",
        .description = "Heap buffer overflow in sudo Baron Samedit (embedded)"
    },
    {
        .cve_id = "CVE-2022-0847",
        .component = "linux-kernel",
        .affected_version = "<5.16.11",
        .fixed_version = "5.16.11",
        .severity = "HIGH",
        .description = "Dirty Pipe arbitrary file overwrite as unprivileged user"
    },
    {
        .cve_id = "CVE-2016-5195",
        .component = "linux-kernel",
        .affected_version = "<4.8.3",
        .fixed_version = "4.8.3",
        .severity = "HIGH",
        .description = "Dirty COW race condition in memory manager copy-on-write"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .affected_version = "<4.4.182",
        .fixed_version = "4.4.182",
        .severity = "HIGH",
        .description = "SACK Panic TCP denial of service / crash"
    },

    /* openssh */
    {
        .cve_id = "CVE-2024-6387",
        .component = "openssh",
        .affected_version = "<9.8",
        .fixed_version = "9.8",
        .severity = "CRITICAL",
        .description = "regreSSHion remote unauthenticated code execution in sshd"
    },
    {
        .cve_id = "CVE-2023-38408",
        .component = "openssh",
        .affected_version = "<9.3p2",
        .fixed_version = "9.3p2",
        .severity = "HIGH",
        .description = "PKCS#11 provider remote code execution in ssh-agent"
    },
    {
        .cve_id = "CVE-2020-15778",
        .component = "openssh",
        .affected_version = "<8.4",
        .fixed_version = "8.4",
        .severity = "MEDIUM",
        .description = "Command injection via scp path manipulation"
    },

    /* uclibc */
    {
        .cve_id = "CVE-2022-29503",
        .component = "uclibc",
        .affected_version = "<1.0.42",
        .fixed_version = "1.0.42",
        .severity = "HIGH",
        .description = "Predictable DNS transaction IDs enabling DNS cache poisoning"
    },

    /* mini_httpd */
    {
        .cve_id = "CVE-2018-18778",
        .component = "mini_httpd",
        .affected_version = "<1.30",
        .fixed_version = "1.30",
        .severity = "HIGH",
        .description = "Arbitrary file disclosure / path traversal via Host header"
    },

    /* iptables */
    {
        .cve_id = "CVE-2019-11360",
        .component = "iptables",
        .affected_version = "<1.8.3",
        .fixed_version = "1.8.3",
        .severity = "MEDIUM",
        .description = "Buffer overflow in iptables-restore via malformed rules"
    }
};

static const size_t num_cves = sizeof(known_cves) / sizeof(known_cves[0]);

int cve_check(const component_t *components, size_t num_components,
              cve_entry_t *out, size_t max, size_t *out_count) {
    if (components == NULL && num_components > 0) {
        return -1;
    }
    if (out_count == NULL) {
        return -1;
    }
    if (out == NULL && max > 0) {
        return -1;
    }

    *out_count = 0;
    size_t count = 0;

    for (size_t i = 0; i < num_components; i++) {
        const component_t *comp = &components[i];
        if (comp->name[0] == '\0' || comp->version[0] == '\0') {
            continue;
        }

        for (size_t j = 0; j < num_cves; j++) {
            const cve_entry_t *cve = &known_cves[j];
            if (strcmp(comp->name, cve->component) != 0) {
                continue;
            }

            int vulnerable = 0;
            if (cve->affected_version[0] != '\0') {
                if (version_compare(comp->version, cve->affected_version) <= 0) {
                    vulnerable = 1;
                }
            } else {
                vulnerable = 1;
            }

            if (vulnerable && cve->fixed_version[0] != '\0') {
                if (version_compare(comp->version, cve->fixed_version) >= 0) {
                    vulnerable = 0;
                }
            }

            if (vulnerable) {
                int duplicate = 0;
                for (size_t k = 0; k < count; k++) {
                    if (k < max && out != NULL) {
                        if (strcmp(out[k].cve_id, cve->cve_id) == 0 &&
                            strcmp(out[k].component, cve->component) == 0) {
                            duplicate = 1;
                            break;
                        }
                    }
                }

                if (!duplicate) {
                    if (count < max && out != NULL) {
                        out[count] = *cve;
                    }
                    count++;
                }
            }
        }
    }

    *out_count = count;
    return 0;
}
