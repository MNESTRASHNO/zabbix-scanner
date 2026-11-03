# Zabbix: versions, releases, Docker images, DB compatibility (2016–2026)

Notes for `research/versions.json`. Compiled 2026-10-28.

## 1. Branch timeline (release → full support → EOL)

| Branch | First release | Full support until | EOL (limited) | Last patch | LTS | Status |
|---|---|---|---|---|---|---|
| 2.2 | 2013-11-12 | 2017-08-31 | 2019-08-31 | 2.2.23 (2018-07-30) | yes | EOL |
| 2.4 | 2014-09-11 | unknown | unknown | 2.4.8 (2016-04-20) | no | EOL |
| 3.0 | 2016-02-15 | 2019-02-28 | 2021-02-28 | 3.0.32 (2021-03-08) | yes | EOL |
| 3.2 | 2016-09-13 | 2017-10-31 | 2017-11-30 | 3.2.11 | no | EOL |
| 3.4 | 2017-08-21 | 2018-05-31 | 2018-06-30 | 3.4.15 | no | EOL |
| 4.0 | 2018-10-01 | 2021-10-31 | 2023-10-31 | 4.0.50 (2023-10-30) | yes | EOL |
| 4.2 | 2019-03-29 | 2019-09-30 | 2019-10-31 | 4.2.8 | no | EOL |
| 4.4 | 2019-10-07 | 2020-05-31 | 2020-06-30 | 4.4.10 | no | EOL |
| 5.0 | 2020-05-11 | 2023-05-31 | 2025-05-31 | 5.0.47 (2025-05-20) | yes | EOL |
| 5.2 | 2020-10-26 | 2021-04-30 | 2021-05-31 | 5.2.7 | no | EOL |
| 5.4 | 2021-05-14 | 2022-01-30 | 2022-02-28 | 5.4.12 | no | EOL |
| 6.0 | 2022-02-14 | 2025-02-28 | 2027-02-28 | 6.0.49 (2026-10-20) | yes | in limited support |
| 6.2 | 2022-07-04 | 2023-01-31 | 2023-02-28 | 6.2.9 | no | EOL, preview |
| 6.4 | 2023-03-06 | 2024-06-30 | 2024-12-31 | 6.4.21 (2025-01-27) | no | EOL (extended) |
| 7.0 | 2024-06-04 | 2027-06-30 | 2029-06-30 | 7.0.32 (2026-10-20) | yes | in support |
| 7.2 | 2025-01-09 | 2025-06-30 | 2025-12-31 | 7.2.15 (2025-12-17) | no | EOL |
| 7.4 | 2025-06-30 | 'until 8.0 LTS' (planned Q4 2026) | Q1 2027 | 7.4.16 (2026-10-20) | no | in support |
| 8.0 LTS | planned Q4 2026 (not released) | Q4 2029 | Q4 2031 | — | yes | planned (8.0.0rc2 in git tags) |

Dates of the `.0` releases were taken from the official release notes (rn pages) as the primary source; where the lifecycle page (archive) gives a different date, the discrepancy is recorded in the branch notes and in §7.

## 2. Sources

### Life cycle (EOL)
- Current page: https://www.zabbix.com/life_cycle_and_release_policy (7.4, 7.0 LTS, 6.0 LTS, 8.0/8.2 plan).
- Archived snapshots of the same page (Wayback Machine):
  - 2016-10-30: http://web.archive.org/web/20161030122149/http://www.zabbix.com:80/life_cycle_and_release_policy (3.0, 2.2, 2.0; 2.4 already absent)
  - 2017-06-12: http://web.archive.org/web/20170612220207/http://www.zabbix.com/life_cycle_and_release_policy (3.2: full 10/2017, limited 11/2017; 3.4 plan)
  - 2018-06-05: http://web.archive.org/web/20180605021510/https://www.zabbix.com/life_cycle_and_release_policy (3.2/3.4 actual, 2.2)
  - 2019-03-27: http://web.archive.org/web/20190327200914/https://www.zabbix.com/life_cycle_and_release_policy (4.0, 3.0, 2.2)
  - 2019-12-18: http://web.archive.org/web/20191218203153/https://www.zabbix.com/life_cycle_and_release_policy (4.4, 4.2, 4.0, 3.0; 5.0 plan)
  - 2020-06-05: http://web.archive.org/web/20200605100808/https://www.zabbix.com/life_cycle_and_release_policy (5.0, 4.4 extended)
  - 2021-01-17 / 2021-05-18: 5.2, 5.0, 4.0, 3.0; 5.4 plan
  - 2022-01-22: http://web.archive.org/web/20220122233112/https://www.zabbix.com/life_cycle_and_release_policy (5.4 extended until 2022-02-28)
  - 2023-01-19: http://web.archive.org/web/20230119081850/https://www.zabbix.com/life_cycle_and_release_policy (6.2, 6.0 LTS; 6.4 plan)
  - 2024-01-01: http://web.archive.org/web/20240101020527/https://www.zabbix.com/life_cycle_and_release_policy (6.4: full 2023-12-31, limited 2024-06-30)
  - 2024-06-01: http://web.archive.org/web/20240601122905/https://www.zabbix.com/life_cycle_and_release_policy (6.4 EXTENDED: limited until 2024-12-31)
  - 2024-09-01: http://web.archive.org/web/20240901024007/https://www.zabbix.com/life_cycle_and_release_policy (7.0, 6.4)
  - 2025-01-14: http://web.archive.org/web/20250114130825/https://www.zabbix.com/life_cycle_and_release_policy (7.2, 7.0, 6.0, 5.0; 7.4/8.0 plan)
- EOL summary: https://endoflife.date/api/zabbix.json (9 branches; confirms 6.4→2024-12-31, 7.2→2025-12-31, 5.4→2022-03-31 — slightly different from the lifecycle archive: they give the 5.4 EOL as 2022-03-31, the archive as 2022-02-28; the JSON uses the archive value).

### Release dates of individual versions
- Release notes: https://www.zabbix.com/rn/rn<version> (date in `<time class="publication-date">`), for all 382 stable versions in the range.
- Tarball upload date: https://cdn.zabbix.com/zabbix/sources/stable|oldstable/<branch>/ (apache listing with dates; for 7.2 the dates are unreliable — see §7).
- Git tags: `git ls-remote --tags https://github.com/zabbix/zabbix.git` — tags exist ONLY from 6.0.0 on (6.0/7.0/7.4, including the 8.0 rc/beta/alpha). Older branches have no git tags.
- 6.0 LTS: press release https://www.zabbix.com/pr/pr385 ('February 15, 2022'); rn6.0.0 — 14 February 2022; lifecycle — 8 February 2022.
- 7.2: the blog https://blog.zabbix.com/see-whats-possible-in-zabbix-7-2/29373 is dated 11 December 2024.

### Full patch lists
- Source directory listings on the CDN (stable tarballs): https://cdn.zabbix.com/zabbix/sources/oldstable/2.2 … /7.2, https://cdn.zabbix.com/zabbix/sources/stable/6.0, /7.0, /7.4.
- Boundary versions were additionally verified with a HEAD request of the tarball and by the presence of an rn page:
  - 3.0.33 / 3.0.34 — **do not exist** (rn 404, tarball 404). The last 3.0 patch is **3.0.32** (2021-03-08). The task mentioned '3.0.34' — an error; it did not make it into the sources.
  - 5.0.48 — no; the last is 5.0.47. 6.0.50 — no; the last is 6.0.49. 7.4.17 — no; the last is 7.4.16. 2.2.24 — no; the last is 2.2.23. 7.2.16 — no; the last is 7.2.15. 7.0.33 — no; the last is 7.0.32. 6.4.22 — no; the last is 6.4.21.

## 3. Docker images

### Sources
- Full tag lists were obtained via the Docker Registry API (auth.docker.io token → `GET registry-1.docker.io/v2/zabbix/<repo>/tags/list?n=10000`) for the repositories: zabbix-server-pgsql, zabbix-server-mysql, zabbix-web-nginx-pgsql, zabbix-web-apache-pgsql, zabbix-web-nginx-mysql, zabbix-web-apache-mysql (2600+ tags each).
- **zabbix-server-sqlite3 does NOT exist on Docker Hub** (the zabbix organization has 20 repositories; sqlite3 exists only for `zabbix-proxy-sqlite3` and `zabbix-build-sqlite3`). In the 3.0.4 docker tree (zabbix-docker tag) there is no sqlite3 server either — only proxy-sqlite3. SQLite is supported for the proxy only (see the docs requirements).
- Dockerfiles and compose: https://github.com/zabbix/zabbix-docker (tarballs at the tags 3.0.4, 3.0.5, 4.0.0, 4.2.0, 4.4.0, 5.0.0, 5.0.10, 5.0.20, 5.0.30, 5.0.40, 5.2.0, 5.4.0, 6.0.0, 6.0.49, 6.2.0, 6.4.0, 6.4.21, 7.0.0, 7.0.32, 7.2.0, 7.4.0, 7.4.16).

### Tag naming
Two conventions (both live in the registry):
- `<flavor>-<version>` — old style: `alpine-3.0.4`, `ubuntu-4.4.10`, `centos-5.4.6`, `ol-6.0.16`.
- `<version>-<flavor>` — new style (mass adoption from ~3.0.32): `3.0.32-alpine`, `7.4.16-ubuntu`.
- Branch-latest (both forms): `3.0-alpine-latest` / `alpine-3.0-latest`, `7.4-ubuntu-latest` / `ubuntu-7.4-latest`.
- Flavors: alpine, ubuntu, centos (up to 5.x/6.x), ol (Oracle Linux, from 5.0), rhel (from 6.0, separate tags). centos images for the new branches (7.x) are built from `quay.io/centos/centos:stream9-minimal`.
- sha256 tags — immutable digests, not needed for verification.

### Versions WITHOUT official images (docker_missing in JSON)
- **2.2.x (all), 2.4.x (all)** — no official images were ever published in the current repositories (the zabbix/* registry has no 2.x tags at all). Verification of 2.x is only by building from source.
- 3.0.0, 3.0.1, 3.0.2, **3.0.3** — no images! **Important for CVE-2016-10134** (SQLi in 3.0.0–3.0.3): the vulnerable 3.0.3 cannot be raised in a container; the closest one with an image is 3.0.4 (already fixed). Options: build 3.0.3 from source or verify on 3.0.4 (does not reproduce) — see §8.
- 3.0.10, 3.0.11, 3.2.7, 3.2.8, 3.4.2, 4.0.8, 4.0.23, 5.0.23, 6.0.24 — gaps in the build matrix (no tags; no zabbix-docker tags for these versions either).
- The oldest versions with images per branch: 3.0.4, 3.2.0, 3.4.0, 4.0.0, 4.2.0, 4.4.0, 5.0.0, 5.2.0, 5.4.0, 6.0.0, 6.2.0, 6.4.0, 7.0.0, 7.2.0, 7.4.0.
- 3.0.4: no `zabbix-web-apache-pgsql` (appears from 3.0.5). 3.0.23: `web-nginx-mysql` ubuntu only.

## 4. DB compatibility per branch (db_compat)

Source: the 'Requirements' pages of the documentation https://www.zabbix.com/documentation/<branch>/manual/installation/requirements (old branches — frozen as of EOL, new ones — current; the JSON also lists versions added during patch releases).

| Branch | PostgreSQL | MySQL/Percona | MariaDB | Oracle | PHP (frontend) |
|---|---|---|---|---|---|
| 2.2/2.4 | 8.1+ (recommended ≥8.3) | 5.0.3+ (2.2: up to 5.7.x) | works | 10g+ | 5.3.0+ (no PHP 7) |
| 3.0/3.2/3.4 | 8.1+ (recommended ≥8.3) | 5.0.3–5.7.x (MySQL 8.0 NOT supported) | works | 10g+ | 5.4.0+ (no PHP 7) |
| 4.0/4.2/4.4 | 8.1+ (recommended ≥8.3) | 5.0.3–8.0.x | works | 10g+ | 5.4.0+ (no PHP 8.0) |
| 5.0 | 9.2.24–17.X | 5.7.X–9.0.X | 10.0.37–11.5.X | 11.2+ | 7.2.0+ (no PHP 8.0) |
| 5.2 | 9.2.24+ | 5.5.62–8.0.x | 10.0.37+ | 11.2+ | 7.2.5+ (no PHP 8.0) |
| 5.4 | 10.9–13.X | 5.7.28–8.0.X | — | 12.1.0.2–19c | 7.2.5+ (no PHP 8.0) |
| 6.0 | 13.0–18.X (15 from 6.0.10, 16 from 6.0.23, 17 from 6.0.36, 18 from 6.0.43) | 8.0.30–9.7.X | 10.5–12.3.X | 19c–21c | 7.2.5–8.3 (8.0/8.1 from 6.0.6, 8.2 from 6.0.14, 8.3 from 6.0.26) |
| 6.2 | 13.0–15.X (15 from 6.2.4) | 8.0.X | 10.5–10.11.X | 19c–21c | 7.4.0–8.2.X (8.2 from 6.2.8) |
| 6.4 | 13.0–17.X (16 from 6.4.8, 17 from 6.4.20) | 8.0.30–9.0.X | 10.5–11.5.X | 19c–21c | 7.4.0–8.3.X (8.3 from 6.4.11) |
| 7.0 | 13.0–18.X (17 from 7.0.6, 18 from 7.0.20) | 8.0.30–9.7.X | 10.5–12.3.X | 19c–21c (deprecated) | 8.0.0–8.5.X (8.4 from 7.0.10, 8.5 from 7.0.25) |
| 7.2 | 13.0–18.X | 8.0.30–9.5.X | 10.5–12.0.X | — | 8.0.0–8.4.X (8.4 from 7.2.4) |
| 7.4 | 13.0–18.X | 8.0.30–9.7.X | 10.5–12.3.X | — | 8.0.0–8.5.X (8.5 from 7.4.9) |

Notes:
- 'PostgreSQL 8.1 or later' — the literal wording of the official 3.0/4.0 documentation (inherited from 2.x). For container verification a practical range is: 3.x → PG 9.2–9.6 (e.g., postgres:9.6), 4.x → PG 9.2–12 (postgres:11); otherwise modern postgres images may fail.
- MySQL: for 3.x do NOT use mysql:8.x (not supported) — use mysql:5.5/5.6/5.7. For 4.x — mysql:5.7 or 8.0.
- MariaDB for 3.x/4.x 'works with Zabbix' (official wording without exact versions for that period).

## 5. Components in the official images (components)

Source: zabbix-docker Dockerfiles at the tags (FROM base, php packages, nginx/apache); the exact patch versions of PHP/nginx/openssl are NOT pinned in the Dockerfiles — they are installed from the base distribution repositories at build time (marked 'distro default' in the JSON; this is an estimate, not a confirmation).

| Branch | PHP (default image) | httpd | Base | DB image from compose |
|---|---|---|---|---|
| 3.0 | PHP 5.x (alpine php5-fpm ~5.6; ubuntu trusty 5.5.9; centos 5.4.16) | nginx (alpine) / apache 2.4 (ubuntu) | alpine:latest (unpinned), ubuntu:trusty, centos (from 3.0.14) | not set |
| 4.0 | PHP 7.2 (alpine 3.7, ubuntu bionic); centos7 = PHP 5.4.16! | nginx / apache 2.4.29 / httpd 2.4.6 | alpine:3.7, ubuntu:bionic, centos:7 | postgres:latest (~PG11), mysql:5.7 |
| 5.0 | PHP 7.3 (alpine 3.11) → 7.4 (alpine 3.12+ from 5.0.10); ubuntu bionic 7.2 → focal 7.4 by 5.0.10; centos8 7.2 | nginx / apache 2.4.29 / 2.4.37 | alpine 3.11→3.14, ubuntu bionic→focal, centos:8 | postgres:latest (~PG12), mysql:8.0 |
| 5.4 | PHP 7.4 (alpine 3.13, ubuntu focal) | nginx / apache 2.4 | alpine:3.13, ubuntu:focal, centos:8 | not set |
| 6.0 | PHP 7.4 (alpine 3.15, ubuntu focal) → PHP 8.3 (php83 by 6.0.49) | nginx / apache 2.4.41 | alpine:3.15+, ubuntu:focal, centos:8 | postgres:13-alpine, mysql:8.0 |
| 6.2 | PHP 8.1 (alpine 3.16, ubuntu jammy) | nginx / apache 2.4 | alpine:3.16, ubuntu:jammy, stream8 | not set |
| 6.4 | PHP 8.1 (alpine 3.17, ubuntu jammy) → php83 by 6.4.21 | nginx / apache 2.4.52 | alpine:3.17+, ubuntu:jammy, stream9 | postgres:14-alpine, mysql:8.0-oracle |
| 7.0 | PHP 8.3 (alpine 3.20, ubuntu noble) → php85 by 7.0.32 | nginx / apache 2.4.58 | alpine:3.20, ubuntu:noble, stream9-minimal | postgres:16-alpine, mysql:8.0-oracle |
| 7.2 | PHP 8.3 (alpine 3.21, ubuntu noble) | nginx / apache 2.4.58 | alpine:3.21, ubuntu:noble, stream9-minimal | not set |
| 7.4 | PHP 8.4 (alpine php84) / 8.3 (ubuntu php8.3) → php85 by 7.4.16 | nginx / apache 2.4 | OS_BASE_IMAGE (build.json), ubuntu ~noble | postgres:17-alpine, mysql:8.4-oracle |

Exact minor versions (PHP 5.4.16, 7.2.x, openssl, etc.) are the package versions of the base distributions (centos7 → PHP 5.4.16, httpd 2.4.6, OpenSSL 1.0.1e; ubuntu trusty → PHP 5.5.9, Apache 2.4.7; bionic → PHP 7.2, Apache 2.4.29; focal → PHP 7.4, Apache 2.4.41; jammy → PHP 8.1, Apache 2.4.52; noble → PHP 8.3, Apache 2.4.58; alpine 3.15 → PHP 7.4, nginx 1.20.x; alpine 3.20 → PHP 8.3). These are estimates based on known distro package versions, not values read from the images — exact numbers require pulling the image (verification phase).

## 6. Minimal verification stacks (stacks)

Format: `[zabbix-server-pgsql:<tag>, <DB>:<tag>, zabbix-web-nginx-pgsql:<tag>]` — 'verify' = the oldest patch of the branch that has an image (ideal for testing vulnerable versions); 'latest' = the branch's rolling tag.

| Branch | verify (oldest image) | latest |
|---|---|---|
| 2.2/2.4 | no images — build from source only | — |
| 3.0 | 3.0.4: `zabbix/zabbix-server-pgsql:alpine-3.0.4`, `postgres:9.6`, `zabbix/zabbix-web-nginx-pgsql:alpine-3.0.4` | `zabbix/zabbix-server-pgsql:3.0-alpine-latest` |
| 3.2 | 3.2.0: `...:alpine-3.2.0`, `postgres:9.6`, `...web...:alpine-3.2.0` | `3.2-alpine-latest` |
| 3.4 | 3.4.0: `...:alpine-3.4.0`, `postgres:9.6`, `...` | `3.4-alpine-latest` |
| 4.0 | 4.0.0: `...:alpine-4.0.0`, `postgres:11`, `...` | `4.0-alpine-latest` |
| 4.2 | 4.2.0: `...:alpine-4.2.0`, `postgres:11`, `...` | `4.2-alpine-latest` |
| 4.4 | 4.4.0: `...:alpine-4.4.0`, `postgres:11`, `...` | `4.4-alpine-latest` |
| 5.0 | 5.0.0: `...:alpine-5.0.0`, `postgres:12`, `...` | `5.0-alpine-latest` |
| 5.2 | 5.2.0: `...:alpine-5.2.0`, `postgres:12`, `...` | `5.2-alpine-latest` |
| 5.4 | 5.4.0: `...:alpine-5.4.0`, `postgres:13`, `...` | `5.4-alpine-latest` |
| 6.0 | 6.0.0: `...:alpine-6.0.0`, `postgres:13-alpine`, `...` | `6.0-alpine-latest` |
| 6.2 | 6.2.0: `...:alpine-6.2.0`, `postgres:14-alpine`, `...` | `6.2-alpine-latest` |
| 6.4 | 6.4.0: `...:alpine-6.4.0`, `postgres:14-alpine`, `...` | `6.4-alpine-latest` |
| 7.0 | 7.0.0: `...:7.0.0-alpine`, `postgres:16-alpine`, `...` | `7.0-alpine-latest` |
| 7.2 | 7.2.0: `...:7.2.0-alpine`, `postgres:16-alpine`, `...` | `7.2-alpine-latest` |
| 7.4 | 7.4.0: `...:7.4.0-alpine`, `postgres:17-alpine`, `...` | `7.4-alpine-latest` |

The full set of tags per version is in the `docker` section of the JSON (all repositories and flavors). DB images in the official compose files: 4.0 → `postgres:latest`/`mysql:5.7`; 5.0 → `postgres:latest`/`mysql:8.0`; 6.0 → `postgres:13-alpine`/`mysql:8.0`; 6.4 → `postgres:14-alpine`/`mysql:8.0-oracle`; 7.0 (env) → `postgres:16-alpine`/`mysql:8.0-oracle`; 7.4 (env) → `postgres:17-alpine`/`mysql:8.4-oracle`.

## 7. Ambiguities and caveats

1. **7.2.0 release date**: rn page → 9 Jan 2025; lifecycle (2025-01-14 archive) and endoflife.date → 10 Dec 2024; blog → 11 Dec 2024; CDN tarball → 2024-12-10; moreover, the CDN dates for 7.2.1 (2024-12-20) and 7.2.2 (2025-01-06) contradict the rn (all three 9 Jan 2025). The JSON uses 2025-01-09 (rn as the primary source); the discrepancy is documented. Recommendation: for verification rely on the actual images/sources, not the date.
2. **6.0.0 date**: rn 2022-02-14, lifecycle 2022-02-08, press release 2022-02-15. In the JSON — 2022-02-14.
3. **4.2.0**: rn 2019-03-29, lifecycle 2019-04-02. 5.4.0: rn 2021-05-14, lifecycle 2021-05-17. 6.4.0: rn 2023-03-06, lifecycle 2023-03-07. 3.0.0: rn 2016-02-15, lifecycle 2016-02-16. 7.4.0: rn 2025-06-30, lifecycle 2025-07-01. 6.2.0: rn 2022-07-04, lifecycle 2022-07-05.
4. **6.2 'R&D preview'**: a short-lived standard release (8 months of support), positioned as a preview of the 6.4 features. The exact 'R&D preview' wording was not found in the checked official pages (rn6.2.0, lifecycle, blog) — the JSON marks it `special: "preview"` with a note. Formally it is a regular standard release with a shortened cycle.
5. **CDN tarball upload dates** are shifted 1–2 days from the official ones in places (file upload ≠ announcement) and are unreliable for 7.2. Release dates were taken from the rn pages; the CDN served as a cross-check.
6. **'PostgreSQL 8.1 or later'** for 3.0/4.0 is verbatim from the frozen documentation; in fact, in those years Zabbix was tested on PG 9.x (3.0 era). For container verification of 3.x use PG 9.2–9.6.
7. **MySQL 8.0 with 3.x** — officially unsupported; supported from 4.0. MariaDB for 3.x/4.x is officially 'works'; version ranges are not specified.
8. **Exact component versions** (PHP/nginx/openssl patch) are not pinned in the Dockerfiles — the values in components are estimates based on the base distributions (see §5). Component CVEs (CVE-2021-32610 nginx, etc.) require pulling the image in the verification phase.
9. **3.0.3 for CVE-2016-10134**: no image. The closest image, 3.0.4, is already fixed (the CVE-2016-10134 fix is in 3.0.4). To reproduce the SQLi (CVE-2016-10134) you will have to build 3.0.3 from source (the tarball is on the CDN: https://cdn.zabbix.com/zabbix/sources/oldstable/3.0/zabbix-3.0.3.tar.gz) or verify statically.
10. **Git tags**: https://github.com/zabbix/zabbix has no tags before 6.0.0 (verified with `git ls-remote --tags`); versions 2.2–5.4 exist only as tarballs + rn pages.
11. **8.0** is not yet released (8.0.0rc2 is the newest tag; no stable 8.0 tarball on the CDN); not included in the table; the lifecycle page lists a Q4 2026 plan.

## 8. Recommendations for the verification phase

- For each branch use `stacks[branch].verify` (the oldest patch with an image) — maximum coverage of vulnerable versions out of the box.
- For subversions without images (the §3 list + docker_missing in the JSON): either build from source (CDN tarball) or pick the closest patch with an image and verify statically (diff).
- Choose PG/MySQL containers per db_compat: 3.x → postgres:9.6/mysql:5.7; 4.x → postgres:11/mysql:5.7; 5.x → postgres:12/13/mysql:8.0; 6.x → postgres:13/14-alpine/mysql:8.0; 7.x → postgres:16/17-alpine/mysql:8.0-8.4.
- Frontend: for 3.x do NOT run on PHP 7 (the frontend does not work) — the 3.0.x images already contain the correct PHP 5; the 4.x/5.x images contain PHP 7; 6.x — PHP 7.4→8.x; 7.x — 8.3/8.4/8.5.
