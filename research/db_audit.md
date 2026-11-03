# db/vulns.json Range Audit (read-only)

Date: 2026-10-28. Auditor: DbRangeAudit. Sources: db/vulns.json (184 records kind=cve/advisory), research/versions.json (patches per branch), NVD API, support.zabbix.com (ZBX tickets), release notes zabbix.com/rn, research/cve_records.json.

## Summary

| Defect class | Count | Essence |
|---|---|---|
| fixed-overlap | 85 | max covers already-fixed versions (false hits) |
| phantom-version | 27 | min/max/branches absent from versions.json (unverifiable/non-existent) |
| ghsa-empty | 13 | advisory-kind GHSA records with empty affected_versions (zombies, never match) |
| cross-branch-max | 11 | max from a foreign branch — **already normalized** in the DB (max reset to unknown), residual risk unbounded |
| branch-gap | 8 | extra/missing branches vs official advisories |
| empty-range | 1 | CVE with fully empty ranges (CVE-2021-46088) |
| **Total** | **145** | |

### Critical (false hits on fixed versions)

1. **CVE-2022-23131** — affected contains branches 4.0/5.0 (4.0.0–4.0.36, 5.0.0–5.0.18) that are NOT in the official ticket ZBX-20350 (SAML): it has Affects 5.4.7 (+NVD: 5.4.0–5.4.8, 6.0.0alpha1). The record’s fix set (4.0.37/5.0.19/5.4.9/6.0.0beta2) matches ZBX-20383 (Java Gateway logback), not ZBX-20350 (5.4.9rc2/6.0.0beta1) → false hits on 4.0.x ≤4.0.36 and 5.0.x ≤5.0.18.
2. **CVE-2023-29449/29450/29451** — branch 6.4: max=6.4.4 with fix 6.4.0rc1/6.4.2rc1/6.4.1rc1: fixed 6.4.x match (NVD for 29450 explicitly excludes 6.4.2).
3. **CVE-2020-15803** — 3.0/4.0/5.0: max = the fix rc itself (3.0.32rc1/4.0.22rc1/5.0.2rc1) — the range = the fixed version.
4. **CVE-2022-43515** — 5.0/6.2: max = the fix rc (5.0.30rc1/6.2.5rc1).
5. **CVE-2021-27927** — 5.0: max 5.0.9 ≥ fix 5.0.8rc1 (matches 5.0.8rc1/5.0.8/5.0.9).
6. **25 ZBX-* advisories (70 ranges)** — max = the fix version without the 'max exclusive' marker (e.g. ZBX-10272: 2.2.21/3.0.13/3.2.10/3.4.4 = fixes; ZBX-13260: 3.2.11 — the last patch of branch 3.2): fixed versions match.

### False negatives
- **CVE-2022-35229** 4.0: max='4.0.0' (exclusive) — only <4.0.0 matches → 4.0.1–4.0.42 missed.
- **CVE-2023-29449/29450/29451**: branch 6.2 missing (fixes 6.2.8rc1/6.2.9rc2 exist; release notes 6.2.8/6.2.9 contain ZBX-22589/22588/22587) → 6.2.x missed.
- **CVE-2021-46088**: all ranges unknown (fill in from NVD).

---

## 1. Cross-branch max (max from another branch)

Unresolved numeric cross-branch max values: **none** (0 cases: the numeric prefix of max matches the branch). All 11 cases are **already normalized** in the DB: max reset to `unknown` with a marker in notes. Residual risk — `max=unknown` is treated as no upper bound (matches the whole branch, including fixed versions).

| id | branch | min | max (current) | fixed_versions | what it was |
|---|---|---|---|---|---|
| CVE-2016-10742 | 3.1 | 3.1.0 | unknown | 2.2.21rc1,3.0.13rc1,3.2.10rc1,3.4.4rc1 | was 3.2.9 (foreign branch) |
| CVE-2016-10742 | 3.3 | 3.3.0 | unknown | 2.2.21rc1,3.0.13rc1,3.2.10rc1,3.4.4rc1 | was 3.4.3 (foreign branch) |
| CVE-2020-11800 | 2.2 | 2.2.0 | unknown | 3.0.31rc1 | was 3.0.31 (foreign branch) |
| ZBX-10660 | 2.0 | unknown | unknown |  | was 5.0 (foreign branch) |
| ZBX-14975 | 3.4 | unknown | unknown |  | was 7.4 (foreign branch) |
| ZBX-16765 | 3.0 | unknown | unknown |  | was 5.2 (foreign branch) |
| ZBX-17742 | 5.0 | unknown | unknown |  | was 6.4 (foreign branch) |
| ZBX-18134 | 5.0 | unknown | unknown | 5.4.0alpha1 | was 5.4 (foreign branch) |
| ZBX-18224 | 5.0 | unknown | unknown | 5.4.0 | was 5.2 (foreign branch) |
| ZBX-21376 | 6.0 | unknown | unknown |  | was 7.4 (foreign branch) |
| ZBX-24939 | 6.0 | unknown | unknown |  | was 7.4 (foreign branch) |

---

## 2. Max covers already-fixed versions (fixed-overlap)

Rule: fix F of the same branch in fixed_versions, max not marked 'exclusive' and max ≥ F → the range matches the fixed version.

### 2a. CVE

| id | branch | min | max | fix (same branch) | recommendation |
|---|---|---|---|---|---|
| CVE-2009-4498 | 1.6 | 1.6.6 | 1.6.8 | 1.6.8 | max -> 1.6.7 (the previous patch before fix 1.6.8), or mark notes='max exclusive' (affected < 1.6.8) |
| CVE-2009-4499 | 1.6 | 1.6.6 | 1.6.7 | 1.6.7 | max -> 1.6.6 (the previous patch before fix 1.6.7), or mark notes='max exclusive' (affected < 1.6.7) |
| CVE-2009-4501 | 1.6 | 1.6.6 | 1.6.7 | 1.6.7 | max -> 1.6.6 (the previous patch before fix 1.6.7), or mark notes='max exclusive' (affected < 1.6.7) |
| CVE-2009-4502 | 1.6 | unknown | 1.6.6 | 1.6.6 | max -> 1.6.5 (the previous patch before fix 1.6.6), or mark notes='max exclusive' (affected < 1.6.6) |
| CVE-2011-3265 | 1.8 | 1.8 | 1.8.6rc2 | 1.8.6 | max -> 1.8.5 (the previous patch before fix 1.8.6), or mark notes='max exclusive' (affected < 1.8.6) |
| CVE-2013-5743 | 2.1 | 2.1.0 | 2.1.7 | 2.1.7 | max -> 2.1.6 (the previous patch before fix 2.1.7), or mark notes='max exclusive' (affected < 2.1.7) |
| CVE-2020-15803 | 3.0 | 3.0.32rc1 | 3.0.32rc1 | 3.0.32rc1 | max -> 3.0.31 (the previous patch before fix 3.0.32rc1), or mark notes='max exclusive' (affected < 3.0.32rc1) |
| CVE-2020-15803 | 4.0 | 4.0.0 | 4.0.22rc1 | 4.0.22rc1 | max -> 4.0.21 (the previous patch before fix 4.0.22rc1), or mark notes='max exclusive' (affected < 4.0.22rc1) |
| CVE-2020-15803 | 5.0 | 5.0.0 | 5.0.2rc1 | 5.0.2rc1 | max -> 5.0.1 (the previous patch before fix 5.0.2rc1), or mark notes='max exclusive' (affected < 5.0.2rc1) |
| CVE-2021-27927 | 5.0 | 5.0.0 | 5.0.9 | 5.0.8rc1 | max -> 5.0.7 (the previous patch before fix 5.0.8rc1), or mark notes='max exclusive' (affected < 5.0.8rc1) |
| CVE-2022-43515 | 5.0 | 5.0.0 | 5.0.30rc1 | 5.0.30rc1 | max -> 5.0.29 (the previous patch before fix 5.0.30rc1), or mark notes='max exclusive' (affected < 5.0.30rc1) |
| CVE-2022-43515 | 6.2 | 6.2.0 | 6.2.5rc1 | 6.2.5rc1 | max -> 6.2.4 (the previous patch before fix 6.2.5rc1), or mark notes='max exclusive' (affected < 6.2.5rc1) |
| CVE-2023-29449 | 6.4 | 6.4.0alpha1 | 6.4.4 | 6.4.0rc1 | mark notes='max exclusive' (affected < 6.4.0rc1) |
| CVE-2023-29450 | 6.4 | 6.4.0 | 6.4.4 | 6.4.2rc1 | max -> 6.4.1 (the previous patch before fix 6.4.2rc1), or mark notes='max exclusive' (affected < 6.4.2rc1) |
| CVE-2023-29451 | 6.4 | 6.4.0alpha1 | 6.4.4 | 6.4.1rc1 | max -> 6.4.0 (the previous patch before fix 6.4.1rc1), or mark notes='max exclusive' (affected < 6.4.1rc1) |

### 2b. ZBX-* advisories (max == the fix version, without the 'exclusive' marker)

| id | branch | min | max (=fix) | full fixed_versions | recommendation |
|---|---|---|---|---|---|
| ZBX-10272 | 2.2 | unknown | 2.2.21 | 2.2.21,3.0.13,3.2.10,3.4.4 | max -> 2.2.20 (the previous patch before fix 2.2.21), or mark notes='max exclusive' (affected < 2.2.21) |
| ZBX-10272 | 3.0 | unknown | 3.0.13 | 2.2.21,3.0.13,3.2.10,3.4.4 | max -> 3.0.12 (the previous patch before fix 3.0.13), or mark notes='max exclusive' (affected < 3.0.13) |
| ZBX-10272 | 3.2 | unknown | 3.2.10 | 2.2.21,3.0.13,3.2.10,3.4.4 | max -> 3.2.9 (the previous patch before fix 3.2.10), or mark notes='max exclusive' (affected < 3.2.10) |
| ZBX-10272 | 3.4 | unknown | 3.4.4 | 2.2.21,3.0.13,3.2.10,3.4.4 | max -> 3.4.3 (the previous patch before fix 3.4.4), or mark notes='max exclusive' (affected < 3.4.4) |
| ZBX-10318 | 3.0 | unknown | 3.0.2 | 3.0.2 | max -> 3.0.1 (the previous patch before fix 3.0.2), or mark notes='max exclusive' (affected < 3.0.2) |
| ZBX-10319 | 2.2 | unknown | 2.2.12 | 2.2.12,2.4.8,3.0.1 | max -> 2.2.11 (the previous patch before fix 2.2.12), or mark notes='max exclusive' (affected < 2.2.12) |
| ZBX-10319 | 2.4 | unknown | 2.4.8 | 2.2.12,2.4.8,3.0.1 | max -> 2.4.7 (the previous patch before fix 2.4.8), or mark notes='max exclusive' (affected < 2.4.8) |
| ZBX-10319 | 3.0 | unknown | 3.0.1 | 2.2.12,2.4.8,3.0.1 | max -> 3.0.0 (the previous patch before fix 3.0.1), or mark notes='max exclusive' (affected < 3.0.1) |
| ZBX-10404 | 3.0 | unknown | 3.0.27 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 3.0.26 (the previous patch before fix 3.0.27), or mark notes='max exclusive' (affected < 3.0.27) |
| ZBX-10404 | 4.0 | unknown | 4.0.7 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.0.6 (the previous patch before fix 4.0.7), or mark notes='max exclusive' (affected < 4.0.7) |
| ZBX-10404 | 4.2 | unknown | 4.2.1 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.2.0 (the previous patch before fix 4.2.1), or mark notes='max exclusive' (affected < 4.2.1) |
| ZBX-11483 | 2.0 | unknown | 2.0.20 | 2.0.20,2.2.16,3.0.6,3.2.2,3.4.0alpha1 | max -> 2.0.19 (the previous patch before fix 2.0.20), or mark notes='max exclusive' (affected < 2.0.20) |
| ZBX-11483 | 2.2 | unknown | 2.2.16 | 2.0.20,2.2.16,3.0.6,3.2.2,3.4.0alpha1 | max -> 2.2.15 (the previous patch before fix 2.2.16), or mark notes='max exclusive' (affected < 2.2.16) |
| ZBX-11483 | 3.0 | unknown | 3.0.6 | 2.0.20,2.2.16,3.0.6,3.2.2,3.4.0alpha1 | max -> 3.0.5 (the previous patch before fix 3.0.6), or mark notes='max exclusive' (affected < 3.0.6) |
| ZBX-11483 | 3.2 | unknown | 3.2.2 | 2.0.20,2.2.16,3.0.6,3.2.2,3.4.0alpha1 | max -> 3.2.1 (the previous patch before fix 3.2.2), or mark notes='max exclusive' (affected < 3.2.2) |
| ZBX-12768 | 2.2 | unknown | 2.2.20 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 2.2.19 (the previous patch before fix 2.2.20), or mark notes='max exclusive' (affected < 2.2.20) |
| ZBX-12768 | 3.0 | unknown | 3.0.11 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.0.10 (the previous patch before fix 3.0.11), or mark notes='max exclusive' (affected < 3.0.11) |
| ZBX-12768 | 3.2 | unknown | 3.2.8 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.2.7 (the previous patch before fix 3.2.8), or mark notes='max exclusive' (affected < 3.2.8) |
| ZBX-12768 | 3.4 | unknown | 3.4.2 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.4.1 (the previous patch before fix 3.4.2), or mark notes='max exclusive' (affected < 3.4.2) |
| ZBX-12769 | 2.2 | unknown | 2.2.20 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 2.2.19 (the previous patch before fix 2.2.20), or mark notes='max exclusive' (affected < 2.2.20) |
| ZBX-12769 | 3.0 | unknown | 3.0.11 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.0.10 (the previous patch before fix 3.0.11), or mark notes='max exclusive' (affected < 3.0.11) |
| ZBX-12769 | 3.2 | unknown | 3.2.8 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.2.7 (the previous patch before fix 3.2.8), or mark notes='max exclusive' (affected < 3.2.8) |
| ZBX-12769 | 3.4 | unknown | 3.4.2 | 2.2.20,3.0.11,3.2.8,3.4.2 | max -> 3.4.1 (the previous patch before fix 3.4.2), or mark notes='max exclusive' (affected < 3.4.2) |
| ZBX-13260 | 3.0 | unknown | 3.0.14 | 3.0.14,3.2.11,3.4.5 | max -> 3.0.13 (the previous patch before fix 3.0.14), or mark notes='max exclusive' (affected < 3.0.14) |
| ZBX-13260 | 3.2 | unknown | 3.2.11 | 3.0.14,3.2.11,3.4.5 | max -> 3.2.10 (the previous patch before fix 3.2.11), or mark notes='max exclusive' (affected < 3.2.11) |
| ZBX-13260 | 3.4 | unknown | 3.4.5 | 3.0.14,3.2.11,3.4.5 | max -> 3.4.4 (the previous patch before fix 3.4.5), or mark notes='max exclusive' (affected < 3.4.5) |
| ZBX-13261 | 2.2 | unknown | 2.2.21 | 2.2.21,3.0.14,3.2.11,3.4.5 | max -> 2.2.20 (the previous patch before fix 2.2.21), or mark notes='max exclusive' (affected < 2.2.21) |
| ZBX-13261 | 3.0 | unknown | 3.0.14 | 2.2.21,3.0.14,3.2.11,3.4.5 | max -> 3.0.13 (the previous patch before fix 3.0.14), or mark notes='max exclusive' (affected < 3.0.14) |
| ZBX-13261 | 3.2 | unknown | 3.2.11 | 2.2.21,3.0.14,3.2.11,3.4.5 | max -> 3.2.10 (the previous patch before fix 3.2.11), or mark notes='max exclusive' (affected < 3.2.11) |
| ZBX-13261 | 3.4 | unknown | 3.4.5 | 2.2.21,3.0.14,3.2.11,3.4.5 | max -> 3.4.4 (the previous patch before fix 3.4.5), or mark notes='max exclusive' (affected < 3.4.5) |
| ZBX-13345 | 3.0 | unknown | 3.0.15 | 3.0.15,3.4.7,4.0.0alpha3 | max -> 3.0.14 (the previous patch before fix 3.0.15), or mark notes='max exclusive' (affected < 3.0.15) |
| ZBX-13345 | 3.4 | unknown | 3.4.7 | 3.0.15,3.4.7,4.0.0alpha3 | max -> 3.4.6 (the previous patch before fix 3.4.7), or mark notes='max exclusive' (affected < 3.4.7) |
| ZBX-14336 | 3.0 | unknown | 3.0.17 | 3.0.17,3.4.9,4.0.0alpha6 | max -> 3.0.16 (the previous patch before fix 3.0.17), or mark notes='max exclusive' (affected < 3.0.17) |
| ZBX-14336 | 3.4 | unknown | 3.4.9 | 3.0.17,3.4.9,4.0.0alpha6 | max -> 3.4.8 (the previous patch before fix 3.4.9), or mark notes='max exclusive' (affected < 3.4.9) |
| ZBX-14337 | 3.4 | unknown | 3.4.9 | 3.4.9,4.0.0alpha6 | max -> 3.4.8 (the previous patch before fix 3.4.9), or mark notes='max exclusive' (affected < 3.4.9) |
| ZBX-15708 | 4.0 | unknown | 4.0.7 | 4.0.7,4.2.1,4.4.0alpha1 | max -> 4.0.6 (the previous patch before fix 4.0.7), or mark notes='max exclusive' (affected < 4.0.7) |
| ZBX-15708 | 4.2 | unknown | 4.2.1 | 4.0.7,4.2.1,4.4.0alpha1 | max -> 4.2.0 (the previous patch before fix 4.2.1), or mark notes='max exclusive' (affected < 4.2.1) |
| ZBX-15870 | 3.0 | unknown | 3.0.27 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 3.0.26 (the previous patch before fix 3.0.27), or mark notes='max exclusive' (affected < 3.0.27) |
| ZBX-15870 | 4.0 | unknown | 4.0.7 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.0.6 (the previous patch before fix 4.0.7), or mark notes='max exclusive' (affected < 4.0.7) |
| ZBX-15870 | 4.2 | unknown | 4.2.1 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.2.0 (the previous patch before fix 4.2.1), or mark notes='max exclusive' (affected < 4.2.1) |
| ZBX-16019 | 3.0 | unknown | 3.0.27 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 3.0.26 (the previous patch before fix 3.0.27), or mark notes='max exclusive' (affected < 3.0.27) |
| ZBX-16019 | 4.0 | unknown | 4.0.7 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.0.6 (the previous patch before fix 4.0.7), or mark notes='max exclusive' (affected < 4.0.7) |
| ZBX-16019 | 4.2 | unknown | 4.2.1 | 3.0.27,4.0.7,4.2.1,4.4.0alpha1 | max -> 4.2.0 (the previous patch before fix 4.2.1), or mark notes='max exclusive' (affected < 4.2.1) |
| ZBX-16103 | 4.0 | unknown | 4.0.11 | 4.0.11,4.2.5,4.4.0alpha1 | max -> 4.0.10 (the previous patch before fix 4.0.11), or mark notes='max exclusive' (affected < 4.0.11) |
| ZBX-16103 | 4.2 | unknown | 4.2.5 | 4.0.11,4.2.5,4.4.0alpha1 | max -> 4.2.4 (the previous patch before fix 4.2.5), or mark notes='max exclusive' (affected < 4.2.5) |
| ZBX-16750 | 3.0 | unknown | 3.0.29 | 3.0.29,4.0.14,4.2.8,4.4.1,5.0.0alpha1 | max -> 3.0.28 (the previous patch before fix 3.0.29), or mark notes='max exclusive' (affected < 3.0.29) |
| ZBX-16750 | 4.0 | unknown | 4.0.14 | 3.0.29,4.0.14,4.2.8,4.4.1,5.0.0alpha1 | max -> 4.0.13 (the previous patch before fix 4.0.14), or mark notes='max exclusive' (affected < 4.0.14) |
| ZBX-16750 | 4.2 | unknown | 4.2.8 | 3.0.29,4.0.14,4.2.8,4.4.1,5.0.0alpha1 | max -> 4.2.7 (the previous patch before fix 4.2.8), or mark notes='max exclusive' (affected < 4.2.8) |
| ZBX-16750 | 4.4 | unknown | 4.4.1 | 3.0.29,4.0.14,4.2.8,4.4.1,5.0.0alpha1 | max -> 4.4.0 (the previous patch before fix 4.4.1), or mark notes='max exclusive' (affected < 4.4.1) |
| ZBX-17101 | 3.0 | unknown | 3.0.29 | 3.0.29,4.0.16,4.4.4,5.0.0alpha1 | max -> 3.0.28 (the previous patch before fix 3.0.29), or mark notes='max exclusive' (affected < 3.0.29) |
| ZBX-17101 | 4.0 | unknown | 4.0.16 | 3.0.29,4.0.16,4.4.4,5.0.0alpha1 | max -> 4.0.15 (the previous patch before fix 4.0.16), or mark notes='max exclusive' (affected < 4.0.16) |
| ZBX-17101 | 4.4 | unknown | 4.4.4 | 3.0.29,4.0.16,4.4.4,5.0.0alpha1 | max -> 4.4.3 (the previous patch before fix 4.4.4), or mark notes='max exclusive' (affected < 4.4.4) |
| ZBX-17997 | 5.0 | unknown | 5.0.3 | 5.0.3,5.2.0alpha1 | max -> 5.0.2 (the previous patch before fix 5.0.3), or mark notes='max exclusive' (affected < 5.0.3) |
| ZBX-17997 | 5.2 | unknown | 5.2.0alpha1 | 5.0.3,5.2.0alpha1 | mark notes='max exclusive' (affected < 5.2.0alpha1) |
| ZBX-18884 | 4.0 | unknown | 4.0.28 | 4.0.28,5.0.8,5.2.4,5.4.0alpha1 | max -> 4.0.27 (the previous patch before fix 4.0.28), or mark notes='max exclusive' (affected < 4.0.28) |
| ZBX-18884 | 5.0 | unknown | 5.0.8 | 4.0.28,5.0.8,5.2.4,5.4.0alpha1 | max -> 5.0.7 (the previous patch before fix 5.0.8), or mark notes='max exclusive' (affected < 5.0.8) |
| ZBX-18884 | 5.2 | unknown | 5.2.4 | 4.0.28,5.0.8,5.2.4,5.4.0alpha1 | max -> 5.2.3 (the previous patch before fix 5.2.4), or mark notes='max exclusive' (affected < 5.2.4) |
| ZBX-19149 | 4.0 | unknown | 4.0.30 | 4.0.30,5.0.10,5.2.6,5.4.0beta1 | max -> 4.0.29 (the previous patch before fix 4.0.30), or mark notes='max exclusive' (affected < 4.0.30) |
| ZBX-19149 | 5.0 | unknown | 5.0.10 | 4.0.30,5.0.10,5.2.6,5.4.0beta1 | max -> 5.0.9 (the previous patch before fix 5.0.10), or mark notes='max exclusive' (affected < 5.0.10) |
| ZBX-19149 | 5.2 | unknown | 5.2.6 | 4.0.30,5.0.10,5.2.6,5.4.0beta1 | max -> 5.2.5 (the previous patch before fix 5.2.6), or mark notes='max exclusive' (affected < 5.2.6) |
| ZBX-19300 | 4.0 | unknown | 4.0.32 | 4.0.32,5.0.13,5.2.7,5.4.1,6.0.0alpha1 | max -> 4.0.31 (the previous patch before fix 4.0.32), or mark notes='max exclusive' (affected < 4.0.32) |
| ZBX-19300 | 5.0 | unknown | 5.0.13 | 4.0.32,5.0.13,5.2.7,5.4.1,6.0.0alpha1 | max -> 5.0.12 (the previous patch before fix 5.0.13), or mark notes='max exclusive' (affected < 5.0.13) |
| ZBX-19300 | 5.2 | unknown | 5.2.7 | 4.0.32,5.0.13,5.2.7,5.4.1,6.0.0alpha1 | max -> 5.2.6 (the previous patch before fix 5.2.7), or mark notes='max exclusive' (affected < 5.2.7) |
| ZBX-19300 | 5.4 | unknown | 5.4.1 | 4.0.32,5.0.13,5.2.7,5.4.1,6.0.0alpha1 | max -> 5.4.0 (the previous patch before fix 5.4.1), or mark notes='max exclusive' (affected < 5.4.1) |
| ZBX-22718 | 6.0 | unknown | 6.0.17 | 6.0.17,6.4.2,7.0.0alpha1 | max -> 6.0.16 (the previous patch before fix 6.0.17), or mark notes='max exclusive' (affected < 6.0.17) |
| ZBX-22718 | 6.4 | unknown | 6.4.2 | 6.0.17,6.4.2,7.0.0alpha1 | max -> 6.4.1 (the previous patch before fix 6.4.2), or mark notes='max exclusive' (affected < 6.4.2) |
| ZBX-22719 | 6.0 | unknown | 6.0.17 | 6.0.17,6.4.2,7.0.0alpha1 | max -> 6.0.16 (the previous patch before fix 6.0.17), or mark notes='max exclusive' (affected < 6.0.17) |
| ZBX-22719 | 6.4 | unknown | 6.4.2 | 6.0.17,6.4.2,7.0.0alpha1 | max -> 6.4.1 (the previous patch before fix 6.4.2), or mark notes='max exclusive' (affected < 6.4.2) |
| ZBX-22727 | 6.0 | unknown | 6.0.18 | 6.0.18,6.4.2,7.0.0alpha1 | max -> 6.0.17 (the previous patch before fix 6.0.18), or mark notes='max exclusive' (affected < 6.0.18) |
| ZBX-22727 | 6.4 | unknown | 6.4.2 | 6.0.18,6.4.2,7.0.0alpha1 | max -> 6.4.1 (the previous patch before fix 6.4.2), or mark notes='max exclusive' (affected < 6.4.2) |

Note: for branches 2.4/3.2/4.2/5.2 max = the branch’s last real patch (2.4.8, 3.2.11, 4.2.8, 5.2.7) — a false hit on the branch’s final release.

---

## 3. Ranges wider than real patches / non-existent versions (phantom-version)

### 3a. Specific records

| id | branch | min | max | fixed_versions | problem | recommendation |
|---|---|---|---|---|---|---|
| CVE-2022-35229 | 4.0 | unknown | '4.0.0' | 4.0.43rc1,5.0.25rc1,6.0.5rc1,6.2.0rc1 | branch 4.0: min=unknown, max='4.0.0' (with the max exclusive marker); fixed_versions=['4.0.43rc1','5.0.25rc1','6.0.5rc1','6.2.0rc1']. '4.0.0' is not a patch and | max -> 4.0.42 (last vulnerable), or max=4.0.43rc1 with the 'max exclusive' marker |
| CVE-2016-10742 | 3.1 | 3.1.0 | unknown | 2.2.21rc1,3.0.13rc1,3.2.10rc1,3.4.4rc1 | branch 3.1: min=3.1.0, max=unknown; branch 3.3: min=3.3.0, max=unknown; fixed_versions=['2.2.21rc1','3.0.13rc1','3.2.10rc1','3.4.4rc1']. Branches 3.1/3.3 are miss | bound them (3.1/3.3 are unreleased: max=3.1.0/3.3.0 or mark the branch as non-release/no data) |
| CVE-2020-11800 | 2.2 | 2.2.0 | unknown | 3.0.31rc1 | branch 2.2: min=2.2.0, max=unknown; fixed_versions=['3.0.31rc1']. max=unknown → unbounded: the whole branch 2.2 matches (including fixed 2.2.21+) | max -> 2.2.20 (the last patch before the fix; the fix is only specified for 3.0 — verify the official scope) |
| CVE-2020-15803 | 4.4 | '4.4' | 4.4.9 | 3.0.32rc1,4.0.22rc1,5.0.2rc1,5.2.0alpha1 | branch 4.4: min='4.4', max=4.4.9; fixed_versions=['3.0.32rc1','4.0.22rc1','5.0.2rc1','5.2.0alpha1']. min='4.4' is not a patch version (a branch marker); patches['4.4 | min -> 4.4.0; check the official advisory on whether 4.4 is vulnerable (if not — remove the 4.4 range) |
| ZBX-16792 | 5.0 | unknown | '5.0' |  | branch 5.0: min=unknown, max='5.0'; fixed_versions=[]. max='5.0' is a branch marker instead of a patch version (patches['5.0'] does not contain '5.0') | set a concrete version (e.g. 5.0.0..5.0.2, per the advisory text) or mark as 'whole branch' |
| ZBX-20383 | - | - | - | 4.0.37,5.0.19,5.4.9,6.0.0beta2 | branch 2.0: max='2.X', branch 3.0: max='3.X' — placeholders from the official advisory ZBX-20383 ('2.0-2.X', '3.0-3.X'); fixed_versions=['4.0.37','5.0.19','5.4.9 | expand '2.X' into branches 2.0/2.2/2.4 and '3.X' into 3.0/3.2/3.4, or teach the matcher to treat 'X' as a wildcard |
| CVE-2019-15132 | - | - | - | 4.2 | fixed_versions=['4.2'] is a branch marker, not a version; the record has no affected branch 4.2 (affected: 4.0<=4.0.26, 4.4.0alpha1, 5.0<=5.0.5, 5.2<=5.2.1 — matches N | pin the fix version down to a concrete one (4.2.7rc1?) — currently '4.2' is unverifiable by the matcher |
| CVE-2010-2790 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.3rc1 | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2010-5049 | 1.3 | '1.3.1beta' | '1.3beta' | unknown | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-2904 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.6 | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-3263 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.6,1.9.4 (alpha) | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-3264 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.6 | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-3265 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.6 | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-4615 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.10,1.9.9 (beta) | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2011-5027 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.10,1.9.9 (beta) | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |
| CVE-2012-3435 | 1.3 | '1.3.1beta' | '1.3beta' | 1.8.15rc1,2.0.2rc1,2.1.0 | branch 1.3: min='1.3.1beta', max='1.3beta' and branch 1.5: min='1.5.1beta', max='1.5beta' — INVERTED ranges (min > max in numeric notation); versions do not e | fix the order (min=1.3.0/1.5.0, max=1.3.1beta/1.5.1beta) or remove the unreleased branches — verify the actual Zabbix 1.3/1.5 version notation (2009-2012) |

### 3b. Systemic: branches without patch tables in versions.json

The following branches are **absent** from versions.json (patches = empty), but are used in affected: `1.1, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0, 2.1, 2.3, 3.1, 3.3` → all ranges on them (2007–2014 records and CVE-2016-10742) are unverifiable. Inverted ranges (min > max) in branches 1.3/1.5: CVE-2010-2790, CVE-2010-5049, CVE-2011-2904, CVE-2011-3263, CVE-2011-3264, CVE-2011-3265, CVE-2011-4615, CVE-2011-5027, CVE-2012-3435.

---

## 4. Empty affected_versions for CVE

kind=cve with fully empty affected_versions — **0** records. There is 1 record where all ranges = unknown/unknown:

| id | branch | min | max | essence | recommendation |
|---|---|---|---|---|---|
| CVE-2021-46088 | 4.0/4.2/4.4/5.0 | unknown | unknown | RCE: the 'Zabbix Admin' role can execute shell scripts | Fill in from NVD: 4.0 ≤4.0.34; 4.2 ≤4.2.8; 4.4 ≤4.4.11 (note: 4.4.11 is missing from versions.json, the last real patch is 4.4.10); 5.0 ≤5.0.20 |

---

## 5. Missing/extra branches vs official advisories (15 target CVEs)

Cross-checked against: NVD API, support.zabbix.com (Jira), release notes zabbix.com/rn. **Matched (12 of 15):** CVE-2016-10134 (2.2/3.0), CVE-2017-2824/-25/-26 (2.0/2.2/2.4/3.0/3.2 per ZBX-12075; 2.4 min/max=unknown — see below), CVE-2022-23134 (5.4/6.0 per NVD/ZBX-20384), CVE-2023-32725 (6.0/6.4/7.0), CVE-2024-22116 (6.4.9–6.4.15 + 7.0 dev), CVE-2024-22120 (6.0/6.4/7.0, exclusive), CVE-2024-42327 (6.0/6.4/7.0), CVE-2025-27232 (7.4 only!), CVE-2025-27233 (6.0/7.0/7.2, precise per ZBX-26987), CVE-2025-27234 (5.0 only, per ZBX-26985), CVE-2025-27240 (6.0/6.4/7.0), CVE-2019-17382 (4.4.0, fix 4.4.1).

**Discrepancies:**

| CVE | DB affected | Official | Problem |
|---|---|---|---|
| **CVE-2022-23131** | 4.0≤4.0.36, 5.0≤5.0.18, 5.4≤5.4.8, 6.0alpha1–beta1; fx 4.0.37/5.0.19/5.4.9/6.0.0beta2 | ZBX-20350: Affects 5.4.7, Fix 5.4.9rc2/6.0.0beta1; NVD: 5.4.0–5.4.8 + 6.0.0alpha1; rn4.0.37/rn5.0.19 DO NOT contain ZBX-20350 | **Extra branches 4.0/5.0** (data mixed with ZBX-20383 Java Gateway) → false hits |
| **CVE-2023-29449** | 5.0/6.0/6.4 (6.4: max 6.4.4) | fix 6.2.8rc1; rn6.2.8: ZBX-22589 | **no 6.2**; 6.4 max ≥ fix 6.4.0rc1 (false hits) |
| **CVE-2023-29450** | 5.0/6.0/6.4 (6.4: max 6.4.4) | fix 6.2.9rc2; NVD excludes 6.4.2 | **no 6.2**; 6.4 max ≥ fix 6.4.2rc1 |
| **CVE-2023-29451** | 6.0/6.4 (6.4: max 6.4.4) | ZBX-22587: Affects 6.0.14/6.2.8/6.4.0; fix 6.2.9rc2 | **no 6.2**; 6.4 max ≥ fix 6.4.1rc1 |
| **CVE-2025-49642** (extra) | 6.0/7.0 | fix 7.2.6 exists | [INFERENCE] branch 7.2 probably missing |

Additionally: CVE-2017-2824/-25/-26 branch 2.4 (min=max=unknown): pin max=2.4.8 (the last real patch; NVD in places mentions a non-existent 2.4.9rc1).

---

## 6. GHSA zombies (advisory, empty affected_versions)

12 GHSA records with empty affected_versions (summary — an Unreviewed CVE import; **none** of these CVE records exists in db/vulns.json) + the deliberate ZBX-20349 placeholder:

| id | imported CVE | CVE in DB | recommendation |
|---|---|---|---|
| GHSA-2h5x-h7x4-hm9h | CVE-2026-23920 | no | import CVE-2026-23920 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-4mp5-p9jh-3rv5 | CVE-2026-23923 | no | import CVE-2026-23923 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-88jj-c4p9-959j | CVE-2026-23930 | no | import CVE-2026-23930 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-9gr5-72qc-m8xc | CVE-2026-23931 | no | import CVE-2026-23931 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-c945-v35p-v696 | CVE-2025-27231 | no | import CVE-2025-27231 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-j6gv-xg9q-8h4p | CVE-2026-23934 | no | import CVE-2026-23934 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-pr2j-9fvv-cqvq | CVE-2026-59785 | no | import CVE-2026-59785 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-q964-q8gh-7pcw | CVE-2026-59788 | no | import CVE-2026-59788 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-r8x9-p5v6-vx46 | CVE-2026-23927 | no | import CVE-2026-23927 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-v7c2-5wfc-rfff | CVE-2026-23926 | no | import CVE-2026-23926 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-wx93-p8qg-2gp4 | CVE-2026-23922 | no | import CVE-2026-23922 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| GHSA-x27p-fpr7-4wpm | CVE-2026-23929 | no | import CVE-2026-23929 with ranges from the official advisory (ZBV-2026-08-18-* etc.), or explicitly mark the record unreviewed/excluded and exclude it from matching |
| ZBX-20349 | — | — | mark it explicitly (notes: not applicable/excluded) and exclude it from matching so that it creates no noise |

---

## Methodology

- kind=cve/advisory: 184 records (the contract states '172'; actually 132 CVE + 52 advisory = 184).
- Check 2: comparison via a numeric key (3 segments); alpha/beta/rc sequences (alpha < beta < rc < final) were taken into account: fixed-overlap includes only max ≥ fix or max == fix-rc; pre-release pairs (alpha3 < alpha4 etc.) were excluded as correct.
- Known-correct (NOT defects): CVE-2022-23132 (branch 4.0.36 confirmed by the ZBX-20341 Affects list; no fix for 4.0 — same as official), CVE-2022-23134, ZBX-20383 '2.X'/'3.X' (the verbatim official notation of ZBX-20383).
- Sources: services.nvd.nist.gov/rest/json/cves/2.0, support.zabbix.com/browse/ZBX-20341, ZBX-20350, ZBX-20383, ZBX-20384, ZBX-12075, ZBX-22587-22589, ZBX-26985, ZBX-26987; zabbix.com/rn/rn4.0.37, rn5.0.19, rn6.2.8, rn6.2.9; zabbix_security_advisories.rss.