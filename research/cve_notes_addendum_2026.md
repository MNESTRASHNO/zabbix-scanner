# Дополнение: пропущенные CVE 2026 (и связанные) — 2026-10-28

Пробел найден при сверии GHSA-записей с CVE-набором: GHSA-импорты упоминали
26 CVE-2026, а `research/cve_records.json` содержал 15. Восстановлено 17 записей
(1 — CVE-2025-66475 — NVD не отдаёт; остаётся покрытой через standalone-GHSA
GHSA-c4cc-x928-vjw9).

Источник: NVD API per-CVE (набор полей — как в контракте research), файл:
`research/cve_records_addendum_2026.json` — затем смержено в
`research/cve_records.json` (dedup по id, сортировка).

Добавленные id:
- CVE-2026-23920, 23922, 23923, 23926, 23927, 23929, 23930, 23931, 23934
- CVE-2026-59785, 59788
- CVE-2025-27231 (сосед 27232, ZBX- семейство oauth/SSO)
- CVE-2016-9140, CVE-2017-5929, CVE-2015-9251 (старые, связки с ZBX)
- CVE-2021-42550 (logback — партнёр ZBX-20383)
- CVE-2025-66578 (xmlseclibs — партнёр GHSA-c4cc-x928-vjw9)

## Ограничения
- Для большинства NVD-DEFINIERT rng из configurations пустые (NVD CPE для Zabbix
  у этих CVE не задан, только CVSS/описание) — `affected_versions` выведены из
  описаний (эвристика `before X.Y.Z`), помечены notes; требуют пересверки по
  официальным адвайзери (делается в audit-пасе).
- type/auth/component — по CWE/описанию, местами 'unknown'.
