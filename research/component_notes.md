# Компонентные CVE стека Zabbix (2016–2026) — конспект

Данные: NVD API (cves/2.0, 47 записей, 2026-10-28), CISA KEV, advisories вендоров, PoC-репозитории.
`research/component_records.json` — 40 записей схемы контракта (id уникальны, JSON валиден, проверено `python3 -m json.tool`).
Категории по полю `component`: php, php-fpm, apache, nginx, postgresql, mysql, mariadb, openssl, other.

## 1. Статус версий компонентов в образах Zabbix (подтверждено vs предполагаемо)

Данные по официальным docker-образам получены от субагента VersionDocker (Dockerfiles тегов `<ветка>.0` + документация Zabbix) — **подтверждено на уровне мажорной ветки**; точный патч-уровень = дефолт дистрибутива (помечен D, подтверждается только факт-чеком у цели):

| Ветка | PHP | Apache httpd | nginx (alpine) | OpenSSL (дистр.) | БД (compose/доки) |
|---|---|---|---|---|---|
| 3.0 (2016–2018) | 5.4.16 D (centos7), 5.5.9 D (trusty), 5.6 D (alpine) | 2.4.6 D (centos7), 2.4.7 D (trusty) | ~1.10 D | 1.0.1e/f D | MySQL 5.5/5.6/5.7, PG 9.2–9.6 |
| 4.0 (2018–2020) | 5.4.16 D (centos7), 7.2 D (bionic/alpine) | 2.4.6 D (centos7), 2.4.29 D (bionic) | 1.12–1.14 D | 1.0.2k+/1.1.1 D | MySQL 5.7/8.0, PG 10/11 |
| 5.0 (2020–2022) | 7.2 D (bionic/centos8), 7.3 D (alpine:3.11), позже 7.4 D (focal/alpine 3.13) | 2.4.29 D (bionic), 2.4.37 D (centos8), позже 2.4.41 D (focal) | 1.16–1.20 D | 1.1.1 D | MySQL 5.7/8.0, PG 10–13 |
| 6.0 (2022–2024) | 7.4 D (focal/alpine:3.15) | 2.4.41 D (focal) | 1.20–1.23 D | 1.1.1f D (focal) | MySQL 8.0, PG 13–15 |
| 6.4 (2023–2025) | 8.1 D (jammy/alpine:3.17) | 2.4.52 D (jammy) | 1.24+ D | 3.0.2 D (jammy) | MySQL 8.0, PG 13–16 |
| 7.0 (2024–2026) | 8.3 D (noble 8.3.6/alpine:3.20) | 2.4.58 D (noble) | 1.26+ D | 3.0.13 D (noble) | MySQL 8.0/9.x, PG 13–18 |

**«Подтверждено»** — мажорные версии выше. **«Предполагаемо по эпохе»** — патч-уровни (D) и всё, что в `applies_to_zabbix[].notes` помечено «номинально/условно». Версии БД в compose-файлах не пинуются (параметризуются `MYSQL_IMAGE_TAG`/`POSTGRESQL_IMAGE_TAG` с 7.0; в более ранних compose БД-сервиса нет вовсе) — диапазоны БД взяты из документации Zabbix по поддерживаемым версиям.

## 2. Таблица записей: component | диапазон | импакт | ветки Zabbix

| CVE | component | диапазон | импакт | Ветки Zabbix (статус) |
|---|---|---|---|---|
| CVE-2012-1823 | php | php-cgi <5.3.12, 5.4<5.4.2 | RCE | 3.0/4.0 — **не применимо** (образы: mod_php/php-fpm, не CGI) |
| CVE-2015-0273 | php | 5.4<5.4.38, 5.5<5.5.22, 5.6<5.6.6 | RCE (unserialize UAF) | 3.0, 4.0(centos7) — номинально; бэкпорт дистрибутива |
| CVE-2018-19518 | php | 5.6.0–5.6.38, 7.0–7.0.32, 7.1–7.1.24, 7.2–7.2.12 | RCE (imap_open) | 3.0–5.0 — условно (php-imap + вызов imap_open; Zabbix не использует) |
| CVE-2019-11043 | php-fpm | 7.1<7.1.33, 7.2<7.2.24, 7.3<7.3.11 | RCE, KEV | **4.0 (alpine, PHP 7.2-fpm)**, 5.0 ранние (7.3) — затронуты; nginx-образы Zabbix = nginx+php-fpm |
| CVE-2019-11045 | php | 7.2<7.2.26, 7.3<7.3.13, 7.4.0 | обход путей (DirectoryIterator \0) | 5.0 — низкая значимость |
| CVE-2019-11047 | php | 7.2<7.2.26, 7.3<7.3.13, 7.4.0 | info disclosure (EXIF overread) | 5.0 — условно (расширение exif) |
| CVE-2024-4577 | php | 8.1<8.1.29, 8.2<8.2.20, 8.3<8.3.8 (Windows+CGI) | RCE, KEV | 6.0/6.4/7.0 — **не применимо** (Linux-образы; только Windows+PHP-CGI) |
| CVE-2024-11233 | php | 8.1<8.1.31, 8.2<8.2.26, 8.3<8.3.14 | overread 1 байт | 6.4, 7.0 — номинально (бэкпорт) |
| CVE-2017-15715 | apache | 2.4.0–2.4.29 | FilesMatch-байпас | 3.0, 4.0/5.0 (bionic 2.4.29) — номинально; нет upload-механизма в Zabbix |
| CVE-2019-0211 | apache | 2.4.17–2.4.38 | локальный root, KEV | 4.0, 5.0 ранние (bionic 2.4.29) — затронуты; локальный вектор |
| CVE-2021-41773 | apache | 2.4.49 | LFI→RCE, KEV | — (образы Zabbix не содержат 2.4.49) |
| CVE-2021-42013 | apache | 2.4.49/2.4.50 | LFI→RCE, KEV | — (то же) |
| CVE-2021-44790 | apache | 2.4.0–2.4.51 (mod_lua) | буфер.overflow, pot. RCE | — (mod_lua не используется) |
| CVE-2023-25690 | apache | 2.4.0–2.4.55 (mod_proxy+RewriteRule) | request smuggling | — условно (Zabbix не проксируется через mod_proxy) |
| CVE-2024-38472 | apache | 2.4.0–2.4.59 (Windows) | SSRF/NTLM | — **не применимо** (Windows-only) |
| CVE-2024-38474 | apache | 2.4.0–2.4.59 (mod_rewrite) | RCE/source disclosure | 6.0, 6.4, 7.0 — номинально (httpd 2.4.41/2.4.52/2.4.58; бэкпорт) |
| CVE-2024-38475 | apache | 2.4.0–2.4.59 (mod_rewrite) | RCE/source disclosure, KEV | 6.0, 6.4, 7.0 — номинально; KEV — приоритет проверки |
| CVE-2024-38476 | apache | 2.4.0–2.4.59 (ядро) | info disc./SSRF/лок. скрипты | 6.0, 6.4, 7.0 — номинально |
| CVE-2017-7529 | nginx | 0.5.6–1.13.2 | integer overflow → info leak | 3.0, 4.0 (alpine nginx 1.10–1.14) — затронуты; 5.0+ нет |
| CVE-2019-9511 | nginx | HTTP/2 до 1.17.3/1.16.1 | DoS (Data Dribble) | 4.0/5.0 — условно (HTTP/2 только с TLS); DoS |
| CVE-2019-9513 | nginx | HTTP/2 до 1.17.3/1.16.1 | DoS (Resource Loop) | 4.0/5.0 — условно; DoS |
| CVE-2021-23017 | nginx | 0.6.18–1.20.0 | off-by-one, DoS/pot. RCE | 4.0, 5.0/6.0 — номинально (resolver не типовой конфиг) |
| CVE-2018-1058 | postgresql | 9.3–11 (до 9.3.22/…/11.1) | search_path hijack → RCE (superuser) | 3.0, 4.0/5.0 — затронуты до патча; нужна учётка БД с CREATE |
| CVE-2019-10164 | postgresql | 10.x<10.9, 11.x<11.4 | stack overflow (пароль) → DoS/pot. RCE | 4.0, 5.0 (PG 10/11) — затронуты; любой аутент. пользователь |
| CVE-2020-25695 | postgresql | до 13.1/12.5/11.10/10.15/9.6.20/9.5.24 | RCE (superuser) при CREATE в схеме | 3.0–5.0 — затронуты до патча |
| CVE-2023-5868 | postgresql | до 16.1/15.5/14.10/13.13/12.17 | info disclosure (unknown-типы) | 5.0–7.0 — затронуты до патча |
| CVE-2023-5869 | postgresql | до 16.2/15.5/14.10/13.13/12.17 | integer overflow → RCE (массивы) | 5.0–7.0 — затронуты до патча |
| CVE-2024-0985 | postgresql | до 16.2/15.6/14.11/13.14/12.18 | REFRESH MATVIEW → SQL-funcs от чужого имени | 6.0/6.4/7.0 — номинально |
| CVE-2024-10979 | postgresql | до 17.2/16.6/15.10/14.15/13.18 | PL/Perl env → RCE | 6.0/6.4/7.0 — условно (нужен plperl) |
| CVE-2025-1094 | postgresql | libpq до 17.3/16.7/15.11/14.16/13.19 | SQLi через PQescape* | 6.4/7.0 — условно (клиенты libpq; Zabbix использует параметризацию) |
| CVE-2016-6662 | mysql | MySQL ≤5.5.52/5.6.33/5.7.15; MariaDB <5.5.51/10.0.27/10.1.17 | RCE (my.cnf) | 3.0, 4.0 — затронуты до патча; нужны FILE/adm-привилегии |
| CVE-2016-6663 | mysql | MySQL <5.5.52/5.6.33/5.7.15; MariaDB <5.5.52/10.0.28/10.1.18 | priv-esc (tmp-файлы) | 3.0, 4.0 — затронуты до патча; локальный вектор |
| CVE-2014-0160 | openssl | 1.0.1–1.0.1f | Heartbleed, KEV | 3.0 — исторический чек (вне окна, если сервер обновлялся) |
| CVE-2016-2107 | openssl | 1.0.1<1.0.1t, 1.0.2<1.0.2h | padding oracle (дешифровка) | 3.0 — номинально; сложно эксплуатируемо |
| CVE-2016-6309 | openssl | 1.1.0a (только) | UAF, DoS/pot. RCE | — практически неприменимо (образы на 1.0.1/1.0.2) |
| CVE-2017-3737 | openssl | 1.0.2b–1.0.2m, 1.1.0–1.1.0g | Montgomery carry → DoS | 3.0/4.0 — номинально; низкая значимость |
| CVE-2022-3602 | openssl | 3.0.0–3.0.6 | X.509 overflow (4 байта) | 6.4 (jammy 3.0.2) — номинально; noble 3.0.13 не затронут |
| CVE-2022-3786 | openssl | 3.0.0–3.0.6 | X.509 buffer overrun | 6.4 — номинально |
| CVE-2023-0286 | openssl | 3.0<3.0.8, 1.1.1<1.1.1t, 1.0.2<1.0.2zg | X.400 type confusion | 5.0/6.0 (1.1.1), 6.4 (3.0.2) — номинально |
| CVE-2024-2961 | other (glibc) | glibc ≤2.39 (iconv) | RCE-примитив (iconv) | 3.0–7.0 (glibc 2.17–2.39) — номинально; Alpine (musl) не затронут |

## 3. Что проверено и исключено из records (обоснование)

- **CVE-2016-2049** — НЕ MySQL: это баг JanRain PHP OpenID library (php-openid, обход проверки `openid.realm`) → исключено, кандидат от пользователя был ошибочным.
- **CVE-2021-2022** (MySQL InnoDB) — DoS-only, «difficult to exploit», высокие привилегии → низкая ценность для сканнера, в records не включён.
- **CVE-2016-6664** (MySQL tmp-файлы DoS), **CVE-2012-2122** (MySQL auth-bypass 5.1–5.5, вне окна — историческая пометка), **CVE-2015-4024** (PHP multipart CPU DoS) — DoS/вне окна, в notes.
- **CVE-2024-10976 / 10978** (PG row security / SET ROLE) — требуют нехарактерных для Zabbix сценариев (row security, SET ROLE); низкая ценность.
- **CVE-2024-10977** (PG libpq: MITM подменяет текст ошибки, 3.7) — низкая ценность.
- **CVE-2023-5870** (PG pg_cancel_backend DoS, 2.2) — DoS.
- **CVE-2019-11044** (PHP 7.x int overflow, DoS/низкий импакт) — не включён.
- **CVE-2013-1899** (PG локальный RCE через socket) — вне окна (2013), фиксы давно в дистрибутивах.
- **MariaDB**: отдельных записей нет — публичных RCE/auth-bypass CVE в окне нет; семейство 6662/6663 покрывает MariaDB-форки (записано в `component_version_range` записей mysql); остальное — DoS-серии (CVE-2021-46661…, CVE-2022-32081…) вне скоупа.
- **HTTP/2 DoS-семейство** nginx (CVE-2018-16843/16844 и др.) — DoS, представлено двумя записями (9511/9513).
- **PHPMailer (CVE-2016-10033)** — библиотека, встроенная во фронтенд Zabbix 3.x–5.x (SMTP-медиатип); граничный случай между «ядром Zabbix» (другой субагент) и компонентами. Не включён: версия PHPMailer не фингерпринтится, а параметры SMTP во фронтенде админ-контролируемые (не атакующий). Отмечено для возможного follow-up.
- **SWEET32 (CVE-2016-2183)** — 3DES-шифры, конфигурационная слабость, не баг версии → только заметка.

## 4. Неоднозначное / предупреждения для сканнера

1. **Дистрибутивный бэкпорт — главный источник ложных срабатываний.** CentOS/Ubuntu/Alpine не меняют базовую версию пакета (напр. `php 5.4.16-*`, `httpd 2.4.6-*`, `openssl 3.0.2-*`), но бэкпортят фиксы. Мажорная версия из образа ≠ уязвимость. Рекомендация: флагать только при «base-версия < фикс + дистрибутив без известного бэкпорта» либо давать «вероятно» с пояснением.
2. **PHP-версия образа vs php-fpm vs mod_php vs CGI.** CVE-2019-11043 бьёт только по nginx+php-fpm сборкам (alpine-образы 4.0/ранних 5.0); CVE-2012-1823/2024-4577 — только CGI (в образах Zabbix отсутствует). Сканнеру нужно знать тип SAPI.
3. **Zabbix-фронтенд не даёт атакующему «сырые» входы** для большинства PHP-CVE (unserialize, imap_open, iconv, EXIF, DirectoryIterator): применимость помечена «условно/низкая» — это скорее фоновые риски, чем прямые векторы на Zabbix.
4. **Версии БД не пинуются** в compose: реальная версия PostgreSQL/MySQL цели определяется только факт-чеком (banner/запрос), диапазоны в записях — «до патча».
5. **CVE-2024-38474/38475/38476** затронули и «свежие» ветки (6.0/6.4/7.0, httpd 2.4.41–2.4.58 ≤ 2.4.59): это самые актуальные Apache-записи для сканера; 38475 — в KEV.
6. **OpenSSL 3.0**: noble (3.0.13) не затронут CVE-2022-3602/3786 (фикс в 3.0.7), но затронут 2023-0286 до бэкпорта; jammy (3.0.2) — все три номинально.
7. CVE-2016-6309 (OpenSSL 1.1.0a) и CVE-2021-41773/42013 (httpd 2.4.49/2.4.50) в образы Zabbix практически не попадают — включены для полноты и кастомных сборок.
8. KEV-статус (CISA, проверено по фиду 2026-10-28): CVE-2012-1823, CVE-2019-11043, CVE-2024-4577, CVE-2019-0211, CVE-2021-41773, CVE-2021-42013, CVE-2024-38475, CVE-2014-0160. Не в KEV (вопреки ожиданиям): CVE-2021-23017, CVE-2024-2961, CVE-2016-6662/6663.

## 5. Источники

- NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` (47 записей, 2026-10-28); severity/vector взяты из NVD (v3.1 → v3.0 → v2).
- CISA KEV feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- Advisories: php.net ChangeLog-5/7/8, httpd.apache.org/security/vulnerabilities_24.html, nginx.org/en/security_advisories.html, postgresql.org/support/security, openssl.org/news/vulnerabilities.html, access.redhat.com (RHSB-2022-004, CVE-2024-38476 и др.), mariadb.com blog.
- Версии образов Zabbix: субагент VersionDocker (Dockerfiles `<ветка>.0`), кросс-чекается с `research/versions.json` при его появлении.
- PoC: exploit-db (18834, 45914, 50383, 50406, 40360, 40678), metasploit (php_cgi_arg_injection, openssl_heartbleed, mysql_priv_esc), github (neex/phuip-fpizdam, Bo0oM/PHP_imap_open_exploit, dhmosfunk/CVE-2023-25690-POC), hackerone 159948, watchtowr CVE-2024-4577, ambionics CVE-2024-2961, X41 CVE-2021-23017, Tenable CVE-2019-0211, gist CVE-2017-7529.

Полный список ссылок — в поле `references` каждой записи `component_records.json`.
