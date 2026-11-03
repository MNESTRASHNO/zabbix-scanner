# Component CVEs of the Zabbix stack (2016–2026) — research notes

Data: NVD API (cves/2.0, 47 records, 2026-10-28), CISA KEV, vendor advisories, PoC repositories.
`research/component_records.json` — 40 records in the contract schema (ids unique, JSON valid, verified with `python3 -m json.tool`).
Categories by the `component` field: php, php-fpm, apache, nginx, postgresql, mysql, mariadb, openssl, other.

## 1. Component version status in Zabbix images (confirmed vs presumed)

Data on the official docker images was obtained from the VersionDocker subagent (Dockerfiles of the `<branch>.0` tags + Zabbix documentation) — **confirmed at the major branch level**; the exact patch level = distro default (marked D, confirmed only by fact-checking on the target):

| Branch | PHP | Apache httpd | nginx (alpine) | OpenSSL (distro) | DB (compose/docs) |
|---|---|---|---|---|---|
| 3.0 (2016–2018) | 5.4.16 D (centos7), 5.5.9 D (trusty), 5.6 D (alpine) | 2.4.6 D (centos7), 2.4.7 D (trusty) | ~1.10 D | 1.0.1e/f D | MySQL 5.5/5.6/5.7, PG 9.2–9.6 |
| 4.0 (2018–2020) | 5.4.16 D (centos7), 7.2 D (bionic/alpine) | 2.4.6 D (centos7), 2.4.29 D (bionic) | 1.12–1.14 D | 1.0.2k+/1.1.1 D | MySQL 5.7/8.0, PG 10/11 |
| 5.0 (2020–2022) | 7.2 D (bionic/centos8), 7.3 D (alpine:3.11), later 7.4 D (focal/alpine 3.13) | 2.4.29 D (bionic), 2.4.37 D (centos8), later 2.4.41 D (focal) | 1.16–1.20 D | 1.1.1 D | MySQL 5.7/8.0, PG 10–13 |
| 6.0 (2022–2024) | 7.4 D (focal/alpine:3.15) | 2.4.41 D (focal) | 1.20–1.23 D | 1.1.1f D (focal) | MySQL 8.0, PG 13–15 |
| 6.4 (2023–2025) | 8.1 D (jammy/alpine:3.17) | 2.4.52 D (jammy) | 1.24+ D | 3.0.2 D (jammy) | MySQL 8.0, PG 13–16 |
| 7.0 (2024–2026) | 8.3 D (noble 8.3.6/alpine:3.20) | 2.4.58 D (noble) | 1.26+ D | 3.0.13 D (noble) | MySQL 8.0/9.x, PG 13–18 |

**'Confirmed'** — the major versions above. **'Presumed by era'** — patch levels (D) and everything in `applies_to_zabbix[].notes` marked 'nominally/conditionally'. DB versions in compose files are not pinned (parameterized via `MYSQL_IMAGE_TAG`/`POSTGRESQL_IMAGE_TAG` since 7.0; earlier compose files have no DB service at all) — DB ranges are taken from the Zabbix documentation on supported versions.

## 2. Records table: component | range | impact | Zabbix branches

| CVE | component | range | impact | Zabbix branches (status) |
|---|---|---|---|---|
| CVE-2012-1823 | php | php-cgi <5.3.12, 5.4<5.4.2 | RCE | 3.0/4.0 — **not applicable** (images: mod_php/php-fpm, not CGI) |
| CVE-2015-0273 | php | 5.4<5.4.38, 5.5<5.5.22, 5.6<5.6.6 | RCE (unserialize UAF) | 3.0, 4.0(centos7) — nominal; distro backport |
| CVE-2018-19518 | php | 5.6.0–5.6.38, 7.0–7.0.32, 7.1–7.1.24, 7.2–7.2.12 | RCE (imap_open) | 3.0–5.0 — conditional (php-imap + an imap_open call; Zabbix does not use it) |
| CVE-2019-11043 | php-fpm | 7.1<7.1.33, 7.2<7.2.24, 7.3<7.3.11 | RCE, KEV | **4.0 (alpine, PHP 7.2-fpm)**, early 5.0 (7.3) — affected; Zabbix nginx images = nginx+php-fpm |
| CVE-2019-11045 | php | 7.2<7.2.26, 7.3<7.3.13, 7.4.0 | path bypass (DirectoryIterator \0) | 5.0 — low significance |
| CVE-2019-11047 | php | 7.2<7.2.26, 7.3<7.3.13, 7.4.0 | info disclosure (EXIF overread) | 5.0 — conditional (exif extension) |
| CVE-2024-4577 | php | 8.1<8.1.29, 8.2<8.2.20, 8.3<8.3.8 (Windows+CGI) | RCE, KEV | 6.0/6.4/7.0 — **not applicable** (Linux images; Windows+PHP-CGI only) |
| CVE-2024-11233 | php | 8.1<8.1.31, 8.2<8.2.26, 8.3<8.3.14 | 1-byte overread | 6.4, 7.0 — nominal (backport) |
| CVE-2017-15715 | apache | 2.4.0–2.4.29 | FilesMatch bypass | 3.0, 4.0/5.0 (bionic 2.4.29) — nominal; no upload mechanism in Zabbix |
| CVE-2019-0211 | apache | 2.4.17–2.4.38 | local root, KEV | 4.0, early 5.0 (bionic 2.4.29) — affected; local vector |
| CVE-2021-41773 | apache | 2.4.49 | LFI→RCE, KEV | — (Zabbix images do not contain 2.4.49) |
| CVE-2021-42013 | apache | 2.4.49/2.4.50 | LFI→RCE, KEV | — (same) |
| CVE-2021-44790 | apache | 2.4.0–2.4.51 (mod_lua) | buffer overflow, pot. RCE | — (mod_lua not used) |
| CVE-2023-25690 | apache | 2.4.0–2.4.55 (mod_proxy+RewriteRule) | request smuggling | — conditional (Zabbix is not proxied through mod_proxy) |
| CVE-2024-38472 | apache | 2.4.0–2.4.59 (Windows) | SSRF/NTLM | — **not applicable** (Windows-only) |
| CVE-2024-38474 | apache | 2.4.0–2.4.59 (mod_rewrite) | RCE/source disclosure | 6.0, 6.4, 7.0 — nominal (httpd 2.4.41/2.4.52/2.4.58; backport) |
| CVE-2024-38475 | apache | 2.4.0–2.4.59 (mod_rewrite) | RCE/source disclosure, KEV | 6.0, 6.4, 7.0 — nominal; KEV — verification priority |
| CVE-2024-38476 | apache | 2.4.0–2.4.59 (core) | info disc./SSRF/local scripts | 6.0, 6.4, 7.0 — nominal |
| CVE-2017-7529 | nginx | 0.5.6–1.13.2 | integer overflow → info leak | 3.0, 4.0 (alpine nginx 1.10–1.14) — affected; 5.0+ no |
| CVE-2019-9511 | nginx | HTTP/2 before 1.17.3/1.16.1 | DoS (Data Dribble) | 4.0/5.0 — conditional (HTTP/2 only with TLS); DoS |
| CVE-2019-9513 | nginx | HTTP/2 before 1.17.3/1.16.1 | DoS (Resource Loop) | 4.0/5.0 — conditional; DoS |
| CVE-2021-23017 | nginx | 0.6.18–1.20.0 | off-by-one, DoS/pot. RCE | 4.0, 5.0/6.0 — nominal (resolver is not a typical config) |
| CVE-2018-1058 | postgresql | 9.3–11 (before 9.3.22/…/11.1) | search_path hijack → RCE (superuser) | 3.0, 4.0/5.0 — affected before the patch; requires a DB account with CREATE |
| CVE-2019-10164 | postgresql | 10.x<10.9, 11.x<11.4 | stack overflow (password) → DoS/pot. RCE | 4.0, 5.0 (PG 10/11) — affected; any authenticated user |
| CVE-2020-25695 | postgresql | before 13.1/12.5/11.10/10.15/9.6.20/9.5.24 | RCE (superuser) with CREATE on a schema | 3.0–5.0 — affected before the patch |
| CVE-2023-5868 | postgresql | before 16.1/15.5/14.10/13.13/12.17 | info disclosure (unknown types) | 5.0–7.0 — affected before the patch |
| CVE-2023-5869 | postgresql | before 16.2/15.5/14.10/13.13/12.17 | integer overflow → RCE (arrays) | 5.0–7.0 — affected before the patch |
| CVE-2024-0985 | postgresql | before 16.2/15.6/14.11/13.14/12.18 | REFRESH MATVIEW → SQL funcs as another user | 6.0/6.4/7.0 — nominal |
| CVE-2024-10979 | postgresql | before 17.2/16.6/15.10/14.15/13.18 | PL/Perl env → RCE | 6.0/6.4/7.0 — conditional (requires plperl) |
| CVE-2025-1094 | postgresql | libpq before 17.3/16.7/15.11/14.16/13.19 | SQLi via PQescape* | 6.4/7.0 — conditional (libpq clients; Zabbix uses parameterization) |
| CVE-2016-6662 | mysql | MySQL ≤5.5.52/5.6.33/5.7.15; MariaDB <5.5.51/10.0.27/10.1.17 | RCE (my.cnf) | 3.0, 4.0 — affected before the patch; requires FILE/admin privileges |
| CVE-2016-6663 | mysql | MySQL <5.5.52/5.6.33/5.7.15; MariaDB <5.5.52/10.0.28/10.1.18 | priv-esc (tmp files) | 3.0, 4.0 — affected before the patch; local vector |
| CVE-2014-0160 | openssl | 1.0.1–1.0.1f | Heartbleed, KEV | 3.0 — historical check (outside the window if the server was updated) |
| CVE-2016-2107 | openssl | 1.0.1<1.0.1t, 1.0.2<1.0.2h | padding oracle (decryption) | 3.0 — nominal; hard to exploit |
| CVE-2016-6309 | openssl | 1.1.0a (only) | UAF, DoS/pot. RCE | — practically not applicable (images on 1.0.1/1.0.2) |
| CVE-2017-3737 | openssl | 1.0.2b–1.0.2m, 1.1.0–1.1.0g | Montgomery carry → DoS | 3.0/4.0 — nominal; low significance |
| CVE-2022-3602 | openssl | 3.0.0–3.0.6 | X.509 overflow (4 bytes) | 6.4 (jammy 3.0.2) — nominal; noble 3.0.13 not affected |
| CVE-2022-3786 | openssl | 3.0.0–3.0.6 | X.509 buffer overrun | 6.4 — nominal |
| CVE-2023-0286 | openssl | 3.0<3.0.8, 1.1.1<1.1.1t, 1.0.2<1.0.2zg | X.400 type confusion | 5.0/6.0 (1.1.1), 6.4 (3.0.2) — nominal |
| CVE-2024-2961 | other (glibc) | glibc ≤2.39 (iconv) | RCE primitive (iconv) | 3.0–7.0 (glibc 2.17–2.39) — nominal; Alpine (musl) not affected |

## 3. What was checked and excluded from records (rationale)

- **CVE-2016-2049** — NOT MySQL: it is a bug in the JanRain PHP OpenID library (php-openid, `openid.realm` validation bypass) → excluded; the user-supplied candidate was mistaken.
- **CVE-2021-2022** (MySQL InnoDB) — DoS-only, 'difficult to exploit', high privileges → low value for the scanner, not included in records.
- **CVE-2016-6664** (MySQL tmp files DoS), **CVE-2012-2122** (MySQL auth bypass 5.1–5.5, outside the window — historical note), **CVE-2015-4024** (PHP multipart CPU DoS) — DoS/outside the window, in notes.
- **CVE-2024-10976 / 10978** (PG row security / SET ROLE) — require scenarios untypical for Zabbix (row security, SET ROLE); low value.
- **CVE-2024-10977** (PG libpq: MITM substitutes the error text, 3.7) — low value.
- **CVE-2023-5870** (PG pg_cancel_backend DoS, 2.2) — DoS.
- **CVE-2019-11044** (PHP 7.x int overflow, DoS/low impact) — not included.
- **CVE-2013-1899** (PG local RCE via socket) — outside the window (2013), fixes long present in distributions.
- **MariaDB**: no separate records — no public RCE/auth-bypass CVEs in the window; the 6662/6663 family covers MariaDB forks (recorded in the `component_version_range` of the mysql records); the rest are DoS series (CVE-2021-46661…, CVE-2022-32081…) out of scope.
- **HTTP/2 DoS family** of nginx (CVE-2018-16843/16844, etc.) — DoS, represented by two records (9511/9513).
- **PHPMailer (CVE-2016-10033)** — a library bundled in the Zabbix 3.x–5.x frontend (SMTP media type); a borderline case between 'Zabbix core' (another subagent) and components. Not included: the PHPMailer version cannot be fingerprinted, and the SMTP parameters in the frontend are admin-controlled (not the attacker). Flagged for a possible follow-up.
- **SWEET32 (CVE-2016-2183)** — 3DES ciphers, a configuration weakness rather than a version bug → note only.

## 4. Ambiguities / warnings for the scanner

1. **Distro backporting is the main source of false positives.** CentOS/Ubuntu/Alpine do not change the base package version (e.g., `php 5.4.16-*`, `httpd 2.4.6-*`, `openssl 3.0.2-*`) but backport fixes. The major version from an image ≠ vulnerability. Recommendation: flag only when 'base version < fix + the distribution has no known backport', or report 'likely' with an explanation.
2. **Image PHP version vs php-fpm vs mod_php vs CGI.** CVE-2019-11043 hits only nginx+php-fpm builds (alpine images of 4.0/early 5.0); CVE-2012-1823/2024-4577 — CGI only (absent from Zabbix images). The scanner needs to know the SAPI type.
3. **The Zabbix frontend gives the attacker no 'raw' inputs** for most PHP CVEs (unserialize, imap_open, iconv, EXIF, DirectoryIterator): applicability is marked 'conditional/low' — these are background risks rather than direct vectors against Zabbix.
4. **DB versions are not pinned** in compose: the target's actual PostgreSQL/MySQL version is determined only by fact-checking (banner/query); the ranges in the records are 'before the patch'.
5. **CVE-2024-38474/38475/38476** also affected the 'recent' branches (6.0/6.4/7.0, httpd 2.4.41–2.4.58 ≤ 2.4.59): these are the most relevant Apache records for the scanner; 38475 is in KEV.
6. **OpenSSL 3.0**: noble (3.0.13) is not affected by CVE-2022-3602/3786 (fix in 3.0.7) but is affected by 2023-0286 before the backport; jammy (3.0.2) — all three nominally.
7. CVE-2016-6309 (OpenSSL 1.1.0a) and CVE-2021-41773/42013 (httpd 2.4.49/2.4.50) practically never appear in Zabbix images — included for completeness and for custom builds.
8. KEV status (CISA, verified against the feed on 2026-10-28): CVE-2012-1823, CVE-2019-11043, CVE-2024-4577, CVE-2019-0211, CVE-2021-41773, CVE-2021-42013, CVE-2024-38475, CVE-2014-0160. Not in KEV (contrary to expectations): CVE-2021-23017, CVE-2024-2961, CVE-2016-6662/6663.

## 5. Sources

- NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` (47 records, 2026-10-28); severity/vector taken from NVD (v3.1 → v3.0 → v2).
- CISA KEV feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- Advisories: php.net ChangeLog-5/7/8, httpd.apache.org/security/vulnerabilities_24.html, nginx.org/en/security_advisories.html, postgresql.org/support/security, openssl.org/news/vulnerabilities.html, access.redhat.com (RHSB-2022-004, CVE-2024-38476, etc.), mariadb.com blog.
- Zabbix image versions: VersionDocker subagent (Dockerfiles of the `<branch>.0` tags), cross-checked against `research/versions.json` when it appears.
- PoCs: exploit-db (18834, 45914, 50383, 50406, 40360, 40678), metasploit (php_cgi_arg_injection, openssl_heartbleed, mysql_priv_esc), github (neex/phuip-fpizdam, Bo0oM/PHP_imap_open_exploit, dhmosfunk/CVE-2023-25690-POC), hackerone 159948, watchtowr CVE-2024-4577, ambionics CVE-2024-2961, X41 CVE-2021-23017, Tenable CVE-2019-0211, gist CVE-2017-7529.

The full list of links is in the `references` field of each record in `component_records.json`.
