# Addendum: missed 2026 CVEs (and related) — 2026-10-28

The gap was found while cross-checking GHSA records against the CVE set: the GHSA imports
mentioned 26 CVE-2026 entries while `research/cve_records.json` had 15. 17 records were restored
(1 — CVE-2025-66475 — is not served by NVD; it stays covered via the standalone GHSA
GHSA-c4cc-x928-vjw9).

Source: NVD API per-CVE (field set — as in the research contract), file:
`research/cve_records_addendum_2026.json` — then merged into
`research/cve_records.json` (dedup by id, sorting).

Added ids:
- CVE-2026-23920, 23922, 23923, 23926, 23927, 23929, 23930, 23931, 23934
- CVE-2026-59785, 59788
- CVE-2025-27231 (neighbor of 27232, ZBX- oauth/SSO family)
- CVE-2016-9140, CVE-2017-5929, CVE-2015-9251 (old, bundled with ZBX)
- CVE-2021-42550 (logback — partner of ZBX-20383)
- CVE-2025-66578 (xmlseclibs — partner of GHSA-c4cc-x928-vjw9)

## Limitations
- For most of the NVD-DEFINED rng the configurations are empty (no NVD CPE is set for Zabbix
  on these CVEs, only CVSS/description) — `affected_versions` were derived from
  descriptions (the `before X.Y.Z` heuristic), flagged in notes; they need a re-check against
  official advisories (done in the audit pass).
- type/auth/component — from CWE/description, sometimes 'unknown'.
