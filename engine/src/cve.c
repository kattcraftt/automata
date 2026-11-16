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
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1g",
        .fixed_version = "1.0.1g",
        .severity = "CRITICAL",
        .description = "TLS heartbeat read overrun (Heartbleed)"
    },
    {
        .cve_id = "CVE-2014-0224",
        .component = "openssl",
        .introduced_version = "0.9.8",
        .affected_version = "<0.9.8za",
        .fixed_version = "0.9.8za",
        .severity = "HIGH",
        .description = "SSL/TLS MITM ChangeCipherSpec injection"
    },
    {
        .cve_id = "CVE-2014-0224",
        .component = "openssl",
        .introduced_version = "1.0.0",
        .affected_version = "<1.0.0m",
        .fixed_version = "1.0.0m",
        .severity = "HIGH",
        .description = "SSL/TLS MITM ChangeCipherSpec injection"
    },
    {
        .cve_id = "CVE-2014-0224",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1h",
        .fixed_version = "1.0.1h",
        .severity = "HIGH",
        .description = "SSL/TLS MITM ChangeCipherSpec injection"
    },
    {
        .cve_id = "CVE-2016-2107",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1t",
        .fixed_version = "1.0.1t",
        .severity = "HIGH",
        .description = "Padding oracle in AES-NI CBC MAC check"
    },
    {
        .cve_id = "CVE-2016-2107",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2h",
        .fixed_version = "1.0.2h",
        .severity = "HIGH",
        .description = "Padding oracle in AES-NI CBC MAC check"
    },
    {
        .cve_id = "CVE-2022-0778",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2zd",
        .fixed_version = "1.0.2zd",
        .severity = "HIGH",
        .description = "BN_mod_sqrt() infinite loop via crafted certificate"
    },
    {
        .cve_id = "CVE-2022-0778",
        .component = "openssl",
        .introduced_version = "1.1.1",
        .affected_version = "<1.1.1n",
        .fixed_version = "1.1.1n",
        .severity = "HIGH",
        .description = "BN_mod_sqrt() infinite loop via crafted certificate"
    },
    {
        .cve_id = "CVE-2022-0778",
        .component = "openssl",
        .introduced_version = "3.0.0",
        .affected_version = "<3.0.2",
        .fixed_version = "3.0.2",
        .severity = "HIGH",
        .description = "BN_mod_sqrt() infinite loop via crafted certificate"
    },
    {
        .cve_id = "CVE-2015-0204",
        .component = "openssl",
        .introduced_version = "0.9.8",
        .affected_version = "<0.9.8zd",
        .fixed_version = "0.9.8zd",
        .severity = "HIGH",
        .description = "RSA downgrade vulnerability (FREAK)"
    },
    {
        .cve_id = "CVE-2015-0204",
        .component = "openssl",
        .introduced_version = "1.0.0",
        .affected_version = "<1.0.0p",
        .fixed_version = "1.0.0p",
        .severity = "HIGH",
        .description = "RSA downgrade vulnerability (FREAK)"
    },
    {
        .cve_id = "CVE-2015-0204",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1k",
        .fixed_version = "1.0.1k",
        .severity = "HIGH",
        .description = "RSA downgrade vulnerability (FREAK)"
    },

    /* busybox */
    {
        .cve_id = "CVE-2022-48174",
        .component = "busybox",
        .affected_version = "<1.36.1",
        .fixed_version = "1.36.1",
        .severity = "CRITICAL",
        .description = "ash shell stack overflow in arithmetic evaluation",
        .condition = "ash applet"
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
        .description = "DNSpooq heap buffer overflow in DNSSEC sort_rrset",
        .condition = "DNSSEC enabled (--dnssec)"
    },
    {
        .cve_id = "CVE-2020-25682",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq buffer overflow in extract_name",
        .condition = "DNSSEC enabled (--dnssec)"
    },
    {
        .cve_id = "CVE-2020-25683",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq heap overflow in get_data",
        .condition = "DNSSEC enabled (--dnssec)"
    },
    {
        .cve_id = "CVE-2020-25687",
        .component = "dnsmasq",
        .affected_version = "<2.83",
        .fixed_version = "2.83",
        .severity = "HIGH",
        .description = "DNSpooq DNS cache poisoning via weak query validation",
        .condition = "DNSSEC enabled (--dnssec)"
    },
    {
        .cve_id = "CVE-2021-3448",
        .component = "dnsmasq",
        .affected_version = "<2.85",
        .fixed_version = "2.85",
        .severity = "MEDIUM",
        .description = "DNS rebind vulnerability with fixed port allocation",
        .condition = "fixed upstream query port (--query-port)"
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
        .introduced_version = "7.69.0",
        .affected_version = "<8.4.0",
        .fixed_version = "8.4.0",
        .severity = "CRITICAL",
        .description = "SOCKS5 heap buffer overflow during hostname resolution"
    },
    {
        .cve_id = "CVE-2022-32221",
        .component = "curl",
        .introduced_version = "7.7",
        .affected_version = "<7.86.0",
        .fixed_version = "7.86.0",
        .severity = "HIGH",
        .description = "POST-after-PUT data corruption and leak"
    },
    {
        .cve_id = "CVE-2021-22946",
        .component = "curl",
        .introduced_version = "7.20.0",
        .affected_version = "<7.79.0",
        .fixed_version = "7.79.0",
        .severity = "MEDIUM",
        .description = "TLS protocol downgrade bypass via plaintext response"
    },

    /* nginx */
    {
        .cve_id = "CVE-2021-23017",
        .component = "nginx",
        .introduced_version = "0.6.18",
        .affected_version = "<1.20.1",
        .fixed_version = "1.20.1",
        .severity = "HIGH",
        .description = "1-byte memory overwrite in resolver DNS response processing"
    },
    {
        .cve_id = "CVE-2018-16843",
        .component = "nginx",
        .introduced_version = "1.9.5",
        .affected_version = "<1.14.1",
        .fixed_version = "1.14.1",
        .severity = "MEDIUM",
        .description = "Excessive memory consumption in HTTP/2 module"
    },
    {
        .cve_id = "CVE-2018-16843",
        .component = "nginx",
        .introduced_version = "1.15.0",
        .affected_version = "<1.15.6",
        .fixed_version = "1.15.6",
        .severity = "MEDIUM",
        .description = "Excessive memory consumption in HTTP/2 module"
    },

    /* linux-kernel */
    {
        .cve_id = "CVE-2022-0847",
        .component = "linux-kernel",
        .introduced_version = "5.8",
        .affected_version = "<5.10.102",
        .fixed_version = "5.10.102",
        .severity = "HIGH",
        .description = "Dirty Pipe arbitrary file overwrite as unprivileged user"
    },
    {
        .cve_id = "CVE-2022-0847",
        .component = "linux-kernel",
        .introduced_version = "5.11",
        .affected_version = "<5.15.25",
        .fixed_version = "5.15.25",
        .severity = "HIGH",
        .description = "Dirty Pipe arbitrary file overwrite as unprivileged user"
    },
    {
        .cve_id = "CVE-2022-0847",
        .component = "linux-kernel",
        .introduced_version = "5.16",
        .affected_version = "<5.16.11",
        .fixed_version = "5.16.11",
        .severity = "HIGH",
        .description = "Dirty Pipe arbitrary file overwrite as unprivileged user"
    },
    {
        .cve_id = "CVE-2016-5195",
        .component = "linux-kernel",
        .introduced_version = "2.6.22",
        .affected_version = "<4.4.26",
        .fixed_version = "4.4.26",
        .severity = "HIGH",
        .description = "Dirty COW race condition in memory manager copy-on-write"
    },
    {
        .cve_id = "CVE-2016-5195",
        .component = "linux-kernel",
        .introduced_version = "4.5",
        .affected_version = "<4.7.9",
        .fixed_version = "4.7.9",
        .severity = "HIGH",
        .description = "Dirty COW race condition in memory manager copy-on-write"
    },
    {
        .cve_id = "CVE-2016-5195",
        .component = "linux-kernel",
        .introduced_version = "4.8",
        .affected_version = "<4.8.3",
        .fixed_version = "4.8.3",
        .severity = "HIGH",
        .description = "Dirty COW race condition in memory manager copy-on-write"
    },

    /* openssh */
    {
        .cve_id = "CVE-2024-6387",
        .component = "openssh",
        .introduced_version = "8.5",
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
    },

    /* busybox 4237x/4238x (JFrog/Claroty, fixed in 1.34.0). Version ranges are the published affected ranges. */
    {
        .cve_id = "CVE-2021-42373",
        .component = "busybox",
        .introduced_version = "1.33.0",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "man applet NULL pointer dereference (DoS) when a section is given without a page",
        .condition = "man applet"
    },
    {
        .cve_id = "CVE-2021-42374",
        .component = "busybox",
        .introduced_version = "1.27.0",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "unlzma out-of-bounds heap read (information leak, DoS); reachable from any applet handling LZMA",
        .condition = "unlzma/lzma applets"
    },
    {
        .cve_id = "CVE-2021-42375",
        .component = "busybox",
        .introduced_version = "1.33.1",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "ash mishandles a special element (DoS under rare filtered-input conditions)",
        .condition = "ash applet"
    },
    {
        .cve_id = "CVE-2021-42376",
        .component = "busybox",
        .introduced_version = "1.16",
        .affected_version = "<1.31.1",
        .fixed_version = "1.32.0",
        .severity = "MEDIUM",
        .description = "hush NULL pointer dereference after a 0x03 delimiter (DoS)",
        .condition = "hush applet"
    },
    {
        .cve_id = "CVE-2021-42377",
        .component = "busybox",
        .introduced_version = "1.33.0",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "hush attacker-controlled pointer free via \"&&&\" (DoS, possible code execution)",
        .condition = "hush applet"
    },
    {
        .cve_id = "CVE-2021-42378",
        .component = "busybox",
        .introduced_version = "1.16",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk getvar_i use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42379",
        .component = "busybox",
        .introduced_version = "1.18",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk next_input_file use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42380",
        .component = "busybox",
        .introduced_version = "1.28",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk clrvar use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42381",
        .component = "busybox",
        .introduced_version = "1.21",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk hash_init use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42382",
        .component = "busybox",
        .introduced_version = "1.26",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk getvar_s use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42383",
        .component = "busybox",
        .introduced_version = "1.33.1",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk evaluate use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42384",
        .component = "busybox",
        .introduced_version = "1.18",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk handle_special use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42385",
        .component = "busybox",
        .introduced_version = "1.16",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk evaluate use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },
    {
        .cve_id = "CVE-2021-42386",
        .component = "busybox",
        .introduced_version = "1.16",
        .affected_version = "<1.34.0",
        .fixed_version = "1.34.0",
        .severity = "MEDIUM",
        .description = "awk nvalloc use-after-free (DoS, possible code execution)",
        .condition = "awk applet"
    },

    /* linux-kernel: TCP SACK (CVE-2019-11477/11478). Per-branch ranges from OSV / kernel.org stable fixes. */
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "2.6.29",
        .affected_version = "<3.16.69",
        .fixed_version = "3.16.69",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "3.17",
        .affected_version = "<4.4.182",
        .fixed_version = "4.4.182",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "4.5",
        .affected_version = "<4.9.182",
        .fixed_version = "4.9.182",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "4.10",
        .affected_version = "<4.14.127",
        .fixed_version = "4.14.127",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "4.15",
        .affected_version = "<4.19.52",
        .fixed_version = "4.19.52",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11477",
        .component = "linux-kernel",
        .introduced_version = "4.20",
        .affected_version = "<5.1.11",
        .fixed_version = "5.1.11",
        .severity = "HIGH",
        .description = "SACK Panic: TCP SACK integer overflow, remote kernel panic"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "2.6.29",
        .affected_version = "<3.16.69",
        .fixed_version = "3.16.69",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "3.17",
        .affected_version = "<4.4.182",
        .fixed_version = "4.4.182",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "4.5",
        .affected_version = "<4.9.182",
        .fixed_version = "4.9.182",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "4.10",
        .affected_version = "<4.14.127",
        .fixed_version = "4.14.127",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "4.15",
        .affected_version = "<4.19.52",
        .fixed_version = "4.19.52",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },
    {
        .cve_id = "CVE-2019-11478",
        .component = "linux-kernel",
        .introduced_version = "4.20",
        .affected_version = "<5.1.11",
        .fixed_version = "5.1.11",
        .severity = "MEDIUM",
        .description = "SACK Slowness: fragmented TCP retransmission queue, excess resource usage"
    },

    /* dnsmasq before 2.78 (Google research set) */
    {
        .cve_id = "CVE-2017-14491",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "CRITICAL",
        .description = "DNS reply heap buffer overflow (remote code execution)"
    },
    {
        .cve_id = "CVE-2017-14492",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "CRITICAL",
        .description = "IPv6 router advertisement heap overflow (remote code execution)",
        .condition = "RA/DHCP service enabled"
    },
    {
        .cve_id = "CVE-2017-14493",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "CRITICAL",
        .description = "DHCPv6 stack buffer overflow (remote code execution)",
        .condition = "DHCPv6 enabled"
    },
    {
        .cve_id = "CVE-2017-14494",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "MEDIUM",
        .description = "DHCPv6 information leak (defeats ASLR)",
        .condition = "DHCPv6 enabled"
    },
    {
        .cve_id = "CVE-2017-14495",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "HIGH",
        .description = "memory exhaustion via crafted DNS requests (DoS)",
        .condition = "--add-mac, --add-cpe-id or --add-subnet"
    },
    {
        .cve_id = "CVE-2017-14496",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "HIGH",
        .description = "integer underflow with large memcpy in DNS proxy (DoS)"
    },
    {
        .cve_id = "CVE-2017-13704",
        .component = "dnsmasq",
        .affected_version = "<2.78",
        .fixed_version = "2.78",
        .severity = "HIGH",
        .description = "crash on oversized DNS query (DoS)"
    },

    /* miniupnpd through 2.1 (NVD: "through 2.1", upper bound inclusive) */
    {
        .cve_id = "CVE-2019-12107",
        .component = "miniupnpd",
        .affected_version = "<2.1",
        .severity = "HIGH",
        .description = "upnp_event_prepare heap information leak (snprintf return value)"
    },
    {
        .cve_id = "CVE-2019-12108",
        .component = "miniupnpd",
        .affected_version = "<2.1",
        .severity = "HIGH",
        .description = "GetOutboundPinholeTimeout NULL pointer dereference (DoS, int_port)"
    },
    {
        .cve_id = "CVE-2019-12109",
        .component = "miniupnpd",
        .affected_version = "<2.1",
        .severity = "HIGH",
        .description = "GetOutboundPinholeTimeout NULL pointer dereference (DoS, rem_port)"
    },
    {
        .cve_id = "CVE-2019-12110",
        .component = "miniupnpd",
        .affected_version = "<2.1",
        .severity = "HIGH",
        .description = "AddPortMapping NULL pointer dereference (DoS, upnpredirect.c)"
    },
    {
        .cve_id = "CVE-2019-12111",
        .component = "miniupnpd",
        .affected_version = "<2.1",
        .severity = "HIGH",
        .description = "PCP copyIPv6IfDifferent NULL pointer dereference (DoS)"
    },

    /* openssl 1.0.1 before 1.0.1u and 1.0.2 before 1.0.2i (OpenSSL advisory of 22 Sep 2016) */
    {
        .cve_id = "CVE-2016-2177",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "CRITICAL",
        .description = "pointer arithmetic undefined behaviour (out-of-bounds access)"
    },
    {
        .cve_id = "CVE-2016-2177",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "CRITICAL",
        .description = "pointer arithmetic undefined behaviour (out-of-bounds access)"
    },
    {
        .cve_id = "CVE-2016-2178",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "MEDIUM",
        .description = "DSA signing does not preserve the constant-time flag (key recovery via timing)",
        .condition = "DSA signing"
    },
    {
        .cve_id = "CVE-2016-2178",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "MEDIUM",
        .description = "DSA signing does not preserve the constant-time flag (key recovery via timing)",
        .condition = "DSA signing"
    },
    {
        .cve_id = "CVE-2016-2179",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "DTLS buffered message DoS",
        .condition = "DTLS in use"
    },
    {
        .cve_id = "CVE-2016-2179",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "DTLS buffered message DoS",
        .condition = "DTLS in use"
    },
    {
        .cve_id = "CVE-2016-2180",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "TS_OBJ_print_bio out-of-bounds read"
    },
    {
        .cve_id = "CVE-2016-2180",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "TS_OBJ_print_bio out-of-bounds read"
    },
    {
        .cve_id = "CVE-2016-2181",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "DTLS replay protection DoS",
        .condition = "DTLS in use"
    },
    {
        .cve_id = "CVE-2016-2181",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "DTLS replay protection DoS",
        .condition = "DTLS in use"
    },
    {
        .cve_id = "CVE-2016-2182",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "CRITICAL",
        .description = "BN_bn2dec out-of-bounds write"
    },
    {
        .cve_id = "CVE-2016-2182",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "CRITICAL",
        .description = "BN_bn2dec out-of-bounds write"
    },
    {
        .cve_id = "CVE-2016-2183",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "SWEET32: birthday attack on 64-bit block ciphers (3DES/DES)",
        .condition = "3DES/DES cipher suites enabled"
    },
    {
        .cve_id = "CVE-2016-2183",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "SWEET32: birthday attack on 64-bit block ciphers (3DES/DES)",
        .condition = "3DES/DES cipher suites enabled"
    },
    {
        .cve_id = "CVE-2016-6302",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "malformed SHA512 session ticket DoS"
    },
    {
        .cve_id = "CVE-2016-6302",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "malformed SHA512 session ticket DoS"
    },
    {
        .cve_id = "CVE-2016-6303",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "CRITICAL",
        .description = "MDC2_Update out-of-bounds write"
    },
    {
        .cve_id = "CVE-2016-6303",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "CRITICAL",
        .description = "MDC2_Update out-of-bounds write"
    },
    {
        .cve_id = "CVE-2016-6304",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "HIGH",
        .description = "OCSP Status Request extension unbounded memory growth (remote DoS)",
        .condition = "OCSP support built in (not no-ocsp)"
    },
    {
        .cve_id = "CVE-2016-6304",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "HIGH",
        .description = "OCSP Status Request extension unbounded memory growth (remote DoS)",
        .condition = "OCSP support built in (not no-ocsp)"
    },
    {
        .cve_id = "CVE-2016-6306",
        .component = "openssl",
        .introduced_version = "1.0.1",
        .affected_version = "<1.0.1u",
        .fixed_version = "1.0.1u",
        .severity = "MEDIUM",
        .description = "certificate message out-of-bounds reads"
    },
    {
        .cve_id = "CVE-2016-6306",
        .component = "openssl",
        .introduced_version = "1.0.2",
        .affected_version = "<1.0.2i",
        .fixed_version = "1.0.2i",
        .severity = "MEDIUM",
        .description = "certificate message out-of-bounds reads"
    },
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

            /* Lower bound: skip components older than the release that introduced the bug. */
            if (cve->introduced_version[0] != '\0' &&
                version_compare(comp->version, cve->introduced_version) < 0) {
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

    *out_count = (count > max) ? max : count;
    return 0;
}
