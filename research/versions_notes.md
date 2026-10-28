# Zabbix: версии, релизы, Docker-образы, совместимость БД (2016–2026)

Конспект к `research/versions.json`. Собран 2026-10-28.

## 1. Таймлайн веток (release → full support → EOL)

| Ветка | Первый релиз | Full support до | EOL (limited) | Последний патч | LTS | Статус |
|---|---|---|---|---|---|---|
| 2.2 | 2013-11-12 | 2017-08-31 | 2019-08-31 | 2.2.23 (2018-07-30) | да | EOL |
| 2.4 | 2014-09-11 | unknown | unknown | 2.4.8 (2016-04-20) | нет | EOL |
| 3.0 | 2016-02-15 | 2019-02-28 | 2021-02-28 | 3.0.32 (2021-03-08) | да | EOL |
| 3.2 | 2016-09-13 | 2017-10-31 | 2017-11-30 | 3.2.11 | нет | EOL |
| 3.4 | 2017-08-21 | 2018-05-31 | 2018-06-30 | 3.4.15 | нет | EOL |
| 4.0 | 2018-10-01 | 2021-10-31 | 2023-10-31 | 4.0.50 (2023-10-30) | да | EOL |
| 4.2 | 2019-03-29 | 2019-09-30 | 2019-10-31 | 4.2.8 | нет | EOL |
| 4.4 | 2019-10-07 | 2020-05-31 | 2020-06-30 | 4.4.10 | нет | EOL |
| 5.0 | 2020-05-11 | 2023-05-31 | 2025-05-31 | 5.0.47 (2025-05-20) | да | EOL |
| 5.2 | 2020-10-26 | 2021-04-30 | 2021-05-31 | 5.2.7 | нет | EOL |
| 5.4 | 2021-05-14 | 2022-01-30 | 2022-02-28 | 5.4.12 | нет | EOL |
| 6.0 | 2022-02-14 | 2025-02-28 | 2027-02-28 | 6.0.49 (2026-10-20) | да | в limited support |
| 6.2 | 2022-07-04 | 2023-01-31 | 2023-02-28 | 6.2.9 | нет | EOL, preview |
| 6.4 | 2023-03-06 | 2024-06-30 | 2024-12-31 | 6.4.21 (2025-01-27) | нет | EOL (продлён) |
| 7.0 | 2024-06-04 | 2027-06-30 | 2029-06-30 | 7.0.32 (2026-10-20) | да | в поддержке |
| 7.2 | 2025-01-09 | 2025-06-30 | 2025-12-31 | 7.2.15 (2025-12-17) | нет | EOL |
| 7.4 | 2025-06-30 | «до 8.0 LTS» (план Q4 2026) | Q1 2027 | 7.4.16 (2026-10-20) | нет | в поддержке |
| 8.0 LTS | план Q4 2026 (не вышел) | Q4 2029 | Q4 2031 | — | да | запланирован (8.0.0rc2 в тегах git) |

Даты `.0`-релизов взяты из официальных release notes (rn-страниц) как первичный источник; где
lifecycle-страница (архив) даёт другую дату — расхождение зафиксировано в notes у ветки и в §7.

## 2. Источники

### Жизненный цикл (EOL)
- Текущая страница: https://www.zabbix.com/life_cycle_and_release_policy (7.4, 7.0 LTS, 6.0 LTS, план 8.0/8.2).
- Архивные снапшоты той же страницы (Wayback Machine):
  - 2016-10-30: http://web.archive.org/web/20161030122149/http://www.zabbix.com:80/life_cycle_and_release_policy (3.0, 2.2, 2.0; 2.4 уже отсутствует)
  - 2017-06-12: http://web.archive.org/web/20170612220207/http://www.zabbix.com/life_cycle_and_release_policy (3.2: full 10/2017, limited 11/2017; 3.4 план)
  - 2018-06-05: http://web.archive.org/web/20180605021510/https://www.zabbix.com/life_cycle_and_release_policy (3.2/3.4 фактич., 2.2)
  - 2019-03-27: http://web.archive.org/web/20190327200914/https://www.zabbix.com/life_cycle_and_release_policy (4.0, 3.0, 2.2)
  - 2019-12-18: http://web.archive.org/web/20191218203153/https://www.zabbix.com/life_cycle_and_release_policy (4.4, 4.2, 4.0, 3.0; план 5.0)
  - 2020-06-05: http://web.archive.org/web/20200605100808/https://www.zabbix.com/life_cycle_and_release_policy (5.0, 4.4 продлён)
  - 2021-01-17 / 2021-05-18: 5.2, 5.0, 4.0, 3.0; план 5.4
  - 2022-01-22: http://web.archive.org/web/20220122233112/https://www.zabbix.com/life_cycle_and_release_policy (5.4 продлён до 2022-02-28)
  - 2023-01-19: http://web.archive.org/web/20230119081850/https://www.zabbix.com/life_cycle_and_release_policy (6.2, 6.0 LTS; план 6.4)
  - 2024-01-01: http://web.archive.org/web/20240101020527/https://www.zabbix.com/life_cycle_and_release_policy (6.4: full 2023-12-31, limited 2024-06-30)
  - 2024-06-01: http://web.archive.org/web/20240601122905/https://www.zabbix.com/life_cycle_and_release_policy (6.4 ПРОДЛЁН: limited до 2024-12-31)
  - 2024-09-01: http://web.archive.org/web/20240901024007/https://www.zabbix.com/life_cycle_and_release_policy (7.0, 6.4)
  - 2025-01-14: http://web.archive.org/web/20250114130825/https://www.zabbix.com/life_cycle_and_release_policy (7.2, 7.0, 6.0, 5.0; план 7.4/8.0)
- Сводка EOL: https://endoflife.date/api/zabbix.json (9 веток; подтверждает 6.4→2024-12-31, 7.2→2025-12-31, 5.4→2022-03-31 — у них чуть иначе, чем архив lifecycle: 5.4 EOL они пишут 2022-03-31, архив — 2022-02-28; в JSON взято из архива).

### Даты релизов отдельных версий
- Release notes: https://www.zabbix.com/rn/rn<версия> (дата в `<time class="publication-date">`), для всех 382 стабильных версий из диапазона.
- Дата заливки tarball: https://cdn.zabbix.com/zabbix/sources/stable|oldstable/<ветка>/ (apache-listing с датами; для 7.2 даты недостоверны — см. §7).
- Git-теги: `git ls-remote --tags https://github.com/zabbix/zabbix.git` — теги существуют ТОЛЬКО с 6.0.0 (6.0/7.0/7.4, включая rc/beta/alpha 8.0). Для старых веток тегов в git нет.
- 6.0 LTS: press release https://www.zabbix.com/pr/pr385 («February 15, 2022»); rn6.0.0 — 14 February 2022; lifecycle — 8 February 2022.
- 7.2: блог https://blog.zabbix.com/see-whats-possible-in-zabbix-7-2/29373 датирован 11 December 2024.

### Полные списки патчей
- Листинги каталога исходников на CDN (стабильные tarball'ы): https://cdn.zabbix.com/zabbix/sources/oldstable/2.2 … /7.2, https://cdn.zabbix.com/zabbix/sources/stable/6.0, /7.0, /7.4.
- Граничные версии дополнительно проверены HEAD-запросом tarball и наличием rn-страницы:
  - 3.0.33 / 3.0.34 — **не существуют** (rn 404, tarball 404). Последний патч 3.0 — **3.0.32** (2021-03-08). В задании упоминался «3.0.34» — это ошибка, в источники не попало.
  - 5.0.48 — нет; последний 5.0.47. 6.0.50 — нет; последний 6.0.49. 7.4.17 — нет; последний 7.4.16. 2.2.24 — нет; последний 2.2.23. 7.2.16 — нет; последний 7.2.15. 7.0.33 — нет; последний 7.0.32. 6.4.22 — нет; последний 6.4.21.

## 3. Docker-образы

### Источники
- Полные списки тегов получены из Docker Registry API (токен auth.docker.io → `GET registry-1.docker.io/v2/zabbix/<repo>/tags/list?n=10000`) для репозиториев: zabbix-server-pgsql, zabbix-server-mysql, zabbix-web-nginx-pgsql, zabbix-web-apache-pgsql, zabbix-web-nginx-mysql, zabbix-web-apache-mysql (по 2600+ тегов в каждом).
- **zabbix-server-sqlite3 на Docker Hub НЕ существует** (в организации zabbix 20 репозиториев, sqlite3 есть только у `zabbix-proxy-sqlite3` и `zabbix-build-sqlite3`). В docker-дереве 3.0.4 (zabbix-docker tag) сервера sqlite3 тоже нет — только proxy-sqlite3. SQLite поддерживается только для прокси (см. docs requirements).
- Dockerfile-ы и compose: https://github.com/zabbix/zabbix-docker (tarball'ы по тегам 3.0.4, 3.0.5, 4.0.0, 4.2.0, 4.4.0, 5.0.0, 5.0.10, 5.0.20, 5.0.30, 5.0.40, 5.2.0, 5.4.0, 6.0.0, 6.0.49, 6.2.0, 6.4.0, 6.4.21, 7.0.0, 7.0.32, 7.2.0, 7.4.0, 7.4.16).

### Именование тегов
Две конвенции (обе актуальны в реестре):
- `<flavor>-<version>` — старая: `alpine-3.0.4`, `ubuntu-4.4.10`, `centos-5.4.6`, `ol-6.0.16`.
- `<version>-<flavor>` — новая (массово с ~3.0.32): `3.0.32-alpine`, `7.4.16-ubuntu`.
- Branch-latest (обе формы): `3.0-alpine-latest` / `alpine-3.0-latest`, `7.4-ubuntu-latest` / `ubuntu-7.4-latest`.
- Флейворы: alpine, ubuntu, centos (до 5.x/6.x), ol (Oracle Linux, с 5.0), rhel (с 6.0, отдельные теги). centos-образы для новых веток (7.x) собираются из `quay.io/centos/centos:stream9-minimal`.
- sha256-теги — immutable digests, для верификации не нужны.

### Версии БЕЗ официальных образов (docker_missing в JSON)
- **2.2.x (все), 2.4.x (все)** — официальных образов никогда не публиковалось в текущих репозиториях (в реестре zabbix/* нет ни одного тега 2.x). Верификация 2.x — только сборкой из исходников.
- 3.0.0, 3.0.1, 3.0.2, **3.0.3** — образов нет! **Важно для CVE-2016-10134** (SQLi в 3.0.0–3.0.3): уязвимую 3.0.3 в контейнере не поднять, ближайший с образом — 3.0.4 (уже исправленная). Варианты: собрать 3.0.3 из исходников или верифицировать на 3.0.4 (не воспроизведётся) — см. §8.
- 3.0.10, 3.0.11, 3.2.7, 3.2.8, 3.4.2, 4.0.8, 4.0.23, 5.0.23, 6.0.24 — пропуски в матрице сборки (тегов нет; zabbix-docker тегов для этих версий тоже нет).
- Самые старые версии с образами по веткам: 3.0.4, 3.2.0, 3.4.0, 4.0.0, 4.2.0, 4.4.0, 5.0.0, 5.2.0, 5.4.0, 6.0.0, 6.2.0, 6.4.0, 7.0.0, 7.2.0, 7.4.0.
- 3.0.4: нет `zabbix-web-apache-pgsql` (появляется с 3.0.5). 3.0.23: `web-nginx-mysql` только ubuntu.

## 4. Совместимость БД по веткам (db_compat)

Источник: страницы «Requirements» документации https://www.zabbix.com/documentation/<ветка>/manual/installation/requirements (старые ветки — замороженные на момент EOL, новые — актуальные; в JSON указаны и версии, добавленные по ходу патчей).

| Ветка | PostgreSQL | MySQL/Percona | MariaDB | Oracle | PHP (фронтенд) |
|---|---|---|---|---|---|
| 2.2/2.4 | 8.1+ (рекоменд. ≥8.3) | 5.0.3+ (2.2: до 5.7.x) | работает | 10g+ | 5.3.0+ (PHP 7 нет) |
| 3.0/3.2/3.4 | 8.1+ (рекоменд. ≥8.3) | 5.0.3–5.7.x (MySQL 8.0 НЕ поддерживается) | работает | 10g+ | 5.4.0+ (PHP 7 нет) |
| 4.0/4.2/4.4 | 8.1+ (рекоменд. ≥8.3) | 5.0.3–8.0.x | работает | 10g+ | 5.4.0+ (PHP 8.0 нет) |
| 5.0 | 9.2.24–17.X | 5.7.X–9.0.X | 10.0.37–11.5.X | 11.2+ | 7.2.0+ (PHP 8.0 нет) |
| 5.2 | 9.2.24+ | 5.5.62–8.0.x | 10.0.37+ | 11.2+ | 7.2.5+ (PHP 8.0 нет) |
| 5.4 | 10.9–13.X | 5.7.28–8.0.X | — | 12.1.0.2–19c | 7.2.5+ (PHP 8.0 нет) |
| 6.0 | 13.0–18.X (15 с 6.0.10, 16 с 6.0.23, 17 с 6.0.36, 18 с 6.0.43) | 8.0.30–9.7.X | 10.5–12.3.X | 19c–21c | 7.2.5–8.3 (8.0/8.1 с 6.0.6, 8.2 с 6.0.14, 8.3 с 6.0.26) |
| 6.2 | 13.0–15.X (15 с 6.2.4) | 8.0.X | 10.5–10.11.X | 19c–21c | 7.4.0–8.2.X (8.2 с 6.2.8) |
| 6.4 | 13.0–17.X (16 с 6.4.8, 17 с 6.4.20) | 8.0.30–9.0.X | 10.5–11.5.X | 19c–21c | 7.4.0–8.3.X (8.3 с 6.4.11) |
| 7.0 | 13.0–18.X (17 с 7.0.6, 18 с 7.0.20) | 8.0.30–9.7.X | 10.5–12.3.X | 19c–21c (deprecated) | 8.0.0–8.5.X (8.4 с 7.0.10, 8.5 с 7.0.25) |
| 7.2 | 13.0–18.X | 8.0.30–9.5.X | 10.5–12.0.X | — | 8.0.0–8.4.X (8.4 с 7.2.4) |
| 7.4 | 13.0–18.X | 8.0.30–9.7.X | 10.5–12.3.X | — | 8.0.0–8.5.X (8.5 с 7.4.9) |

Примечания:
- «PostgreSQL 8.1 or later» — дословная формулировка официальной документации 3.0/4.0 (унаследована от 2.x). Для контейнерной верификации практичный диапазон: 3.x → PG 9.2–9.6 (напр. postgres:9.6), 4.x → PG 9.2–12 (postgres:11), иначе современные postgres-образы могут не пройти.
- MySQL: для 3.x НЕ использовать mysql:8.x (не поддерживается) — mysql:5.5/5.6/5.7. Для 4.x — mysql:5.7 или 8.0.
- MariaDB для 3.x/4.x «works with Zabbix» (официальная формулировка без точных версий на тот период).

## 5. Компоненты в официальных образах (components)

Источник: Dockerfile-ы zabbix-docker по тегам (FROM-база, php-пакеты, nginx/apache); точные patch-версии PHP/nginx/openssl в Dockerfile НЕ зафиксированы — ставятся из репозиториев базового дистрибутива на момент сборки (в JSON помечено «distro default», это оценка, не подтверждение).

| Ветка | PHP (образ по умолчанию) | httpd | База | БД-образ из compose |
|---|---|---|---|---|
| 3.0 | PHP 5.x (alpine php5-fpm ~5.6; ubuntu trusty 5.5.9; centos 5.4.16) | nginx (alpine) / apache 2.4 (ubuntu) | alpine:latest (непинн.), ubuntu:trusty, centos (с 3.0.14) | не задан |
| 4.0 | PHP 7.2 (alpine 3.7, ubuntu bionic); centos7 = PHP 5.4.16! | nginx / apache 2.4.29 / httpd 2.4.6 | alpine:3.7, ubuntu:bionic, centos:7 | postgres:latest (~PG11), mysql:5.7 |
| 5.0 | PHP 7.3 (alpine 3.11) → 7.4 (alpine 3.12+ с 5.0.10); ubuntu bionic 7.2 → focal 7.4 к 5.0.10; centos8 7.2 | nginx / apache 2.4.29 / 2.4.37 | alpine 3.11→3.14, ubuntu bionic→focal, centos:8 | postgres:latest (~PG12), mysql:8.0 |
| 5.4 | PHP 7.4 (alpine 3.13, ubuntu focal) | nginx / apache 2.4 | alpine:3.13, ubuntu:focal, centos:8 | не задан |
| 6.0 | PHP 7.4 (alpine 3.15, ubuntu focal) → PHP 8.3 (php83 к 6.0.49) | nginx / apache 2.4.41 | alpine:3.15+, ubuntu:focal, centos:8 | postgres:13-alpine, mysql:8.0 |
| 6.2 | PHP 8.1 (alpine 3.16, ubuntu jammy) | nginx / apache 2.4 | alpine:3.16, ubuntu:jammy, stream8 | не задан |
| 6.4 | PHP 8.1 (alpine 3.17, ubuntu jammy) → php83 к 6.4.21 | nginx / apache 2.4.52 | alpine:3.17+, ubuntu:jammy, stream9 | postgres:14-alpine, mysql:8.0-oracle |
| 7.0 | PHP 8.3 (alpine 3.20, ubuntu noble) → php85 к 7.0.32 | nginx / apache 2.4.58 | alpine:3.20, ubuntu:noble, stream9-minimal | postgres:16-alpine, mysql:8.0-oracle |
| 7.2 | PHP 8.3 (alpine 3.21, ubuntu noble) | nginx / apache 2.4.58 | alpine:3.21, ubuntu:noble, stream9-minimal | не задан |
| 7.4 | PHP 8.4 (alpine php84) / 8.3 (ubuntu php8.3) → php85 к 7.4.16 | nginx / apache 2.4 | OS_BASE_IMAGE (build.json), ubuntu ~noble | postgres:17-alpine, mysql:8.4-oracle |

Точные минорные версии (PHP 5.4.16, 7.2.x, openssl и т.п.) — это версии пакетов базовых дистрибутивов (centos7 → PHP 5.4.16, httpd 2.4.6, OpenSSL 1.0.1e; ubuntu trusty → PHP 5.5.9, Apache 2.4.7; bionic → PHP 7.2, Apache 2.4.29; focal → PHP 7.4, Apache 2.4.41; jammy → PHP 8.1, Apache 2.4.52; noble → PHP 8.3, Apache 2.4.58; alpine 3.15 → PHP 7.4, nginx 1.20.x; alpine 3.20 → PHP 8.3). Это оценки по известным версиям пакетов дистрибутивов, а не прочитанные из образов значения — для точных номеров нужен pull образа (фаза верификации).

## 6. Минимальные стеки для верификации (stacks)

Формат: `[zabbix-server-pgsql:<tag>, <БД>:<tag>, zabbix-web-nginx-pgsql:<tag>]` — «verify» = самый старый патч ветки, для которого есть образ (идеален для проверки уязвимых версий); «latest» = rolling-тег ветки.

| Ветка | verify (старейший образ) | latest |
|---|---|---|
| 2.2/2.4 | нет образов — только сборка из исходников | — |
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

Полный набор тегов на версию — в `docker`-секции JSON (все репозитории и флейворы). БД-образы в официальных compose-файлах: 4.0 → `postgres:latest`/`mysql:5.7`; 5.0 → `postgres:latest`/`mysql:8.0`; 6.0 → `postgres:13-alpine`/`mysql:8.0`; 6.4 → `postgres:14-alpine`/`mysql:8.0-oracle`; 7.0 (env) → `postgres:16-alpine`/`mysql:8.0-oracle`; 7.4 (env) → `postgres:17-alpine`/`mysql:8.4-oracle`.

## 7. Неоднозначности и оговорки

1. **7.2.0 дата релиза**: rn-страница → 9 Jan 2025; lifecycle (архив 2025-01-14) и endoflife.date → 10 Dec 2024; блог → 11 Dec 2024; CDN tarball → 2024-12-10; при этом CDN-даты для 7.2.1 (2024-12-20) и 7.2.2 (2025-01-06) противоречат rn (все три 9 Jan 2025). В JSON взято 2025-01-09 (rn как первоисточник), расхождение задокументировано. Рекомендация: при верификации опираться на фактические образы/исходники, а не на дату.
2. **6.0.0 дата**: rn 2022-02-14, lifecycle 2022-02-08, press release 2022-02-15. В JSON — 2022-02-14.
3. **4.2.0**: rn 2019-03-29, lifecycle 2019-04-02. 5.4.0: rn 2021-05-14, lifecycle 2021-05-17. 6.4.0: rn 2023-03-06, lifecycle 2023-03-07. 3.0.0: rn 2016-02-15, lifecycle 2016-02-16. 7.4.0: rn 2025-06-30, lifecycle 2025-07-01. 6.2.0: rn 2022-07-04, lifecycle 2022-07-05.
4. **6.2 «R&D preview»**: короткоживущий standard-релиз (8 месяцев поддержки), позиционировался как предпросмотр возможностей 6.4. Точная формулировка «R&D preview» в проверенных официальных страницах (rn6.2.0, lifecycle, блог) не найдена — в JSON помечен `special: "preview"` с примечанием. Формально это обычный standard-релиз с укороченным циклом.
5. **CDN-даты заливки tarball** местами сдвинуты на 1–2 дня от официальных (загрузка файла ≠ анонс) и недостоверны для 7.2. Для дат релизов использовались rn-страницы; CDN — как контроль.
6. **«PostgreSQL 8.1 or later»** для 3.0/4.0 — дословно из замороженной документации; фактически в те годы Zabbix тестировался на PG 9.x (3.0 era). Для контейнерной проверки 3.x берите PG 9.2–9.6.
7. **MySQL 8.0 с 3.x** — официально не поддерживается; с 4.0 поддерживается. MariaDB для 3.x/4.x официально «works», диапазоны версий не специфицированы.
8. **Точные версии компонентов** (PHP/nginx/openssl patch) в образах не зафиксированы в Dockerfile — значения в components — оценки по базовым дистрибутивам (см. §5). Для компонентных CVE (CVE-2021-32610 nginx и т.п.) требуется pull образа в фазе верификации.
9. **3.0.3 под CVE-2016-10134**: образа нет. Ближайший образ 3.0.4 — уже исправлен (фикс CVE-2016-10134 в 3.0.4). Для воспроизведения SQLi (CVE-2016-10134) придётся собирать 3.0.3 из исходников (tarball есть на CDN: https://cdn.zabbix.com/zabbix/sources/oldstable/3.0/zabbix-3.0.3.tar.gz) либо верифицировать статически.
10. **Git-теги**: в https://github.com/zabbix/zabbix тегов до 6.0.0 нет (проверено `git ls-remote --tags`); версии 2.2–5.4 существуют только как tarball'ы + rn-страницы.
11. **8.0** ещё не выпущен (8.0.0rc2 — свежайший тег; в CDN стабильных tarball 8.0 нет); в таблицу не включён, в lifecycle-странице — план Q4 2026.

## 8. Рекомендации для фазы верификации

- Для каждой ветки брать `stacks[branch].verify` (старейший патч с образом) — максимальное покрытие уязвимых версий из коробки.
- Для подверсий без образов (список §3 + docker_missing в JSON): либо сборка из исходников (CDN tarball), либо выбор ближайшего патча с образом и статическая проверка (diff).
- PG/MySQL-контейнеры выбирать по db_compat: 3.x → postgres:9.6/mysql:5.7; 4.x → postgres:11/mysql:5.7; 5.x → postgres:12/13/mysql:8.0; 6.x → postgres:13/14-alpine/mysql:8.0; 7.x → postgres:16/17-alpine/mysql:8.0-8.4.
- Фронтенд: для 3.x НЕ поднимать на PHP 7 (фронтенд не работает) — образы 3.0.x уже содержат правильный PHP 5; для 4.x/5.x образы содержат PHP 7; 6.x — PHP 7.4→8.x; 7.x — 8.3/8.4/8.5.
