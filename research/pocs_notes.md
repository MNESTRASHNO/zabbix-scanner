# Zabbix PoC map — notes on the mechanics of public exploits

Sources: exploit-db (local clone of gitlab.com/exploit-database/exploitdb), metasploit-framework (local clone), vulhub, NVD API, ZBX tickets (support.zabbix.com), SonarSource, HackTricks, 0xdf, GitHub search. All URLs are in `pocs.json`.

> Marked `[INFERENCE]` — statements not directly confirmed by a source, derived from adjacent data.

---

## CVE-2016-10134 — SQLi (jsrpc.php / latest.php), Zabbix 2.2.x–3.0.3 → fixed in 3.0.4

- **Two vectors**:
  1. `jsrpc.php` parameter `profileIdx2` — error-based ('Duplicate entry' via `COUNT(*) ... GROUP BY`), **works without authentication** (the sid in the URL is not validated; EDB 40353 hardcodes `sid=0bcd4ade648214dc`; vulhub — `?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)`).
  2. `latest.php` parameter `toggle_ids[]` — **stacked query** via `CProfile::insertDB()`: `INSERT INTO profiles (...) VALUES (...); <SQL>` (1n3, EDB 40237, seclists fulldisclosure/Aug/60). Requires a session (login or guest).
- Public PoCs: EDB 40353 (python2), EDB 40237, MSF `auxiliary/gather/zabbix_toggleids_sqli` (bperry; POST `latest.php?output=ajax&sid=...` + `favobj=toggle&toggle_ids[]=348 <sql>&toggle_open_state=0`), vulhub.
- **⇒ RCE chain**: SQLi → the administrator sessionid from `zabbix.sessions` → login → script/API RCE (EDB 39937 'Zabbix API JSON-RPC RCE', packetstorm 137454).

## CVE-2016-10135 — NOT Zabbix (important!)

Per NVD/cvelist, `CVE-2016-10135` is an **LG MTKLogger** vulnerability (Android, MTK chipsets), CNA `cve@mitre.org`; it has nothing to do with Zabbix. The task list most likely contains a misattribution (in several outdated lists 10134/10135 go together as 'Zabbix SQLi'). The Zabbix injection carries only CVE-2016-10134. Map 10135 as non-Zabbix; no PoC.

## CVE-2017-2824 — RCE in the Zabbix Server trapper (port 10051)

- Mechanics (Talos TALOS-2017-0325, vulhub): the server executes a remote command for a registered host, substituting the host interface address stored in the DB into the shell command (without escaping).
- PoC (vulhub `exploit.py`, python3):
  1. `{"request":"active checks","host":"vulhub","ip":";touch /tmp/success"}` → TCP 10051 (registration via auto-registration; **requires the enabled Auto-registration 'Add host' action**);
  2. hostid enumeration: `{"request":"command","scriptid":1,"hostid":"<id>"}` → on a match, `;touch /tmp/success` executes on the server as `zabbix`.
- Affected: 2.0.x<2.0.21, 2.2.x<2.2.18, 2.4.x, 3.0.x<3.0.9, 3.2.x<3.2.5. No Metasploit module. (CVE-2017-2825 — an adjacent DoS, out of scope.)

## CVE-2019-17382 — anonymous access to the dashboard

- `GET /zabbix.php?action=dashboard.view&dashboardid=1` without an account → 200 + dashboard contents; an anonymous user can create Dashboards/Reports/Screens/Maps (visible to everyone, including the admin).
- PoCs: EDB 47467 (text+curl), EDB 47474 (perl/LWP). ZBX-16789. Fixed in 4.4.1 (Snyk `[,4.4.1)`); in LTS branches backported later (Debian).

## CVE-2022-23131 — SAML SSO authentication bypass (cookie forging without the key)

- **Root cause**: the client-side session is the `zbx_session = base64(JSON)` cookie. `CEncryptedCookieSession::checkSign()` is called **only** when extracting `sessionid` (`extractSessionId()`), and for the other fields (including `saml_data`) — **never**. `index_sso.php`, when `saml_data` is present, calls `user.loginByUsername($saml_data['username_attribute'], ...)` without signature verification (SonarSource).
- **Cookie forging algorithm (PoCs Mr-xn/random-robbie/jweny):**
  1. GET `/` (anonymously) → obtain `zbx_session`;
  2. decode → JSON `{"sessionid":"<32hex>","sign":"<hex>"}` (5.0/5.4) / `+serverCheckResult,serverCheckTime` (6.0.0beta);
  3. add `"saml_data":{"username_attribute":"Admin"}` (the victim's username is known in advance), do **not** touch `sessionid`/`sign`;
  4. re-encode → GET `/index_sso.php` → log in as Admin.
  No signature computation: `sign` is reused from the user's own anonymous cookie. `[INFERENCE]` on 6.0.0beta the format includes the serverCheck fields (see the 0xdf PoC for 6.4.x — the same fields there).
- Conditions: **SAML SSO enabled** (not the default); know the username (Admin); guest — if enabled. Fixes: 4.0.37/5.0.19/5.4.9/6.0.0beta2 (commits 0395828a, eea1f70a). CISA KEV, active exploitation since 2022.
- Chain after the bypass: admin → script/item RCE (CVE-2021-46088, EDB 50816, MSF zabbix_script_exec).

## CVE-2022-23134 — reconfiguration via setup.php (step 6)

- **Root cause**: `setup.php` stores step progress in the same unverifiable session; `CSetupWizard::stage6()` assembles `conf/zabbix.conf.php` from `getConfig()` (a wrapper over `$_SESSION`) and saves the file — the cookie signature is not checked.
- **PoC (TheN00bBuilder):** cookie `zbx_session = base64url({"step":"6","default_timezone":"system","DB_TYPE":"MYSQL","DB_SERVER":"<ip>","DB_PORT":3306,"DB_DATABASE":"zabbix","DB_USER":"zabbix","DB_PASSWORD":"..."})`, then `POST /zabbix/setup.php` (data `sid`, `form_refresh=1`, `next[5]=Next step`) → the frontend is repointed to the attacker's DB → login with known credentials → full access. Precondition: the attacker's MySQL with the zabbix schema and user (`mysql_native_password` for MySQL 8!).
- Affected: 5.4.0–5.4.8rc1, 6.0.0a1–beta1 (NIST); fixed in 5.4.9/6.0.0beta2 (commit 20943ae3). CISA KEV. SonarSource notes room for development: `phar://` via `file_exists()` during DB validation, `LOAD DATA LOCAL` (disabled in newer PHP).

## CVE-2023-32725 — zbx_session leakage via the URL widget (scheduled reports)

- Mechanics (ZBX-23854, CWE-565, CVSS 9.6/8.8): the URL widget loads an arbitrary URL; during a test/execution of a scheduled report (Admin/Super admin only), the `zbx_session` of the report's author is sent to the receiving site → session hijack → privileges.
- Affected: 6.0.0–6.0.21 (fixed 6.0.22), 6.4.0–6.4.6 (fixed 6.4.7), 7.0.0a1–a3 (fixed a4/a5). No PoC code (the attack is trivial: your own web server + URL widget).

## CVE-2024-22116 — RCE via script parameters (Ping) — 'Zabbix 7.0.x RCE' #1

- ZBX-25016: script parameters are not escaped by default; a restricted admin exploits script execution (Ping) in Monitoring→Hosts → arbitrary code. 6.4.9–6.4.15 (fixed 6.4.16rc1), 7.0.0a1–rc3 (fixed 7.0.0rc3). No standalone PoC (editing parameters in the UI/API).

## CVE-2024-22117 / 22119 / 22121

- **22117**: Map URL `sysmapelementurlid` — sequence manipulation (ID+1) blocks other users from adding URLs (DoS/access control). No PoC.
- **22119**: stored XSS via the 'Name' field on the Graph page (invalid validation). No PoC.
- **22121**: a non-admin can change/delete agent configuration functions (integrity/availability). No PoC.
- All three are condition-checks for the scanner (not exploit-class).

## CVE-2024-22120 — time-based blind SQLi (audit log clientip) → Admin → RCE — 'Zabbix 7.0.x RCE' #2

- **Root cause**: on `script.execute` the Audit Log entry contains `clientip` (the connecting IP) unescaped → time-based blind SQLi. The attack goes **over TCP 10051** (trapper protocol, frame `ZBXD\x01` + 8-byte LE length), not via the web (HackTricks/0xdf/ZBX-24505).
- **Steps (W01fh4cker/CVE-2024-22120-RCE + 0xdf HTB Watcher):**
  1. low-priv/guest session → `sessionid` from `zbx_session` (base64), `hostid`, an allowed `scriptid` (in the lab 1/2, not 3);
  2. on 10051: `{"request":"command","sid":<sid>,"scriptid":"2","hostid":"10084","clientip":"' + (SQL) + '"}`;
  3. SQL: `(select CASE WHEN ascii(substr((select session_key from config),POS,1))=ORD THEN sleep(10) ELSE sleep(1) END)` → extract `session_key` (32 hex); then the admin `sessionid` from `sessions where userid=1`;
  4. forge the cookie: `sign = HMAC-SHA256(key=session_key, data=JSON(sessionid/serverCheckResult/serverCheckTime, sorted keys, compact))`, `zbx_session = base64(JSON+sign)` → `GET /zabbix.php?action=dashboard.view`;
  5. RCE: `api_jsonrpc.php` `script.create` (`scope:2`) → `script.execute` → the global script executes on the Zabbix Server as `zabbix` (`[INFERENCE]` — details from the toolkit's scripts).
- Affected: 6.0.0–6.0.27 (fixed 6.0.28), 6.4.0–6.4.12 (fixed 6.4.13), 7.0.0a1–beta1 (fixed beta2). Zabbix rates it high-privileges, NVD low; check permissions by role/host/script manually.

## CVE-2024-22122 / 22123 — SMS/GSM media

- **22122** (ZBX-25012): AT command injection via the unvalidated 'Number' field when testing/sending an SMS → arbitrary AT commands on the GSM modem. No PoC.
- **22123**: 'GSM modem file' can be set to an arbitrary file (including a log): zabbix_server writes AT commands into it, the log breaks, and part of its contents leaks into the UI (mini arbitrary file read). No PoC.

## CVE-2024-42327 — SQLi in the API (user.get selectRole) → Admin → RCE — 'Zabbix 7.0.x RCE' #3

- **Root cause** (ZBX-25623): `CUser::addRelatedObjects` in `CUser.get` does not escape the values of select fields (`selectRole` and others); the method is available to **any** user with API access (the User role by default) — not admin, unlike the 'script' RCE.
- **PoCs**: EDB 52230 (detection), BridgerAlderson (the full chain: user.login → time-based SQLi → admin sessionid → host.get/interface.get → item.create `system.run[reverseshell]`), godylockz (privesc, threads/sleep-time settings).
- Affected: 6.0.0–6.0.31 (fixed 6.0.32), 6.4.0–6.4.16 (fixed 6.4.17), 7.0.0 (fixed 7.0.1). CVSS 9.9. The RCE part requires a reachable host and `AllowKey=system.run[*]`.

## CVE-2025-* (smartctl, oauth.authorize, SQLi autoremoval) — no PoC

- **CVE-2025-27233/27234** (Agent 2 smartctl; HackerOne kelsier / Janis Nulle): the `src/go/plugins/smart` plugin does not sanitize the `smart.disk.get` parameters → argument injection into `smartctl`; 27233 — NTLMv2 leak on Windows (6.0.0–6.0.39 → fixed 6.0.40; 7.0.0–7.0.10 → 7.0.11; 7.2.0–7.2.4 → 7.2.5), 27234 — RCE in 5.0 (5.0.0–5.0.46 → 5.0.47). Workaround: AllowKey/DenyKey. Injection details not publicly disclosed.
- **CVE-2025-27232** (oauth.authorize arbitrary file read; HackerOne o4ncL1, ZBX-27282): Super Admin, crafted HTTP to `oauth.authorize` → web server LFI; ONLY 7.4.0–7.4.2, fixed in 7.4.3. Details not disclosed.
- **CVE-2025-27240** (ZBX-26986): second-order SQLi during autoremoval of auto-registered hosts via 'Visible name'.
- **CVE-2025-27236/27238, CVE-2025-49641/49642/49643, CVE-2025-10630** (Grafana-Zabbix ReDoS): info-disclosure/DoS class; no PoC code in public sources — not included in `pocs.json`.

## Adjacent reference tools

- **MSF `auxiliary/scanner/http/zabbix_login`** — default-credential scanner (Admin/zabbix) — useful for fingerprinting/initial access.
- **MSF `exploits/multi/http/zabbix_script_exec`** (CVE-2013-3628) — post-auth RCE (script/item techniques), works up to 6.0.0 — see the record in pocs.json.
- **MSF `exploits/linux/misc/zabbix_server_exec`** (CVE-2009-4498, trapper) and **`exploits/unix/misc/zabbix_agent_exec`** (CVE-2009-4502) — historical PoCs (out of scope, reference).
- **Zabbix default creds**: Admin/zabbix (5 failures → 30 s lockout); guest is disabled by default (HackTricks).
- **zbx_session cookie format (summary)**: base64(JSON); fields are version-dependent: 5.0/5.4 — `sessionid`,`sign`; 6.0+ — `sessionid`,`serverCheckResult`,`serverCheckTime`,`sign`. Signature: up to 5.4.8 — the `CEncryptHelper::sign` construction (AES-ECB-based, used as the sign); starting with the fix (5.4.9+/6.0) — HMAC-SHA256(key=`session_key` from `config.session_key`, data=JSON sorted+compact), sign is hex inside base64(JSON). In 2.x–4.x (pre-5.0) — a simple `zbx_sessionid` cookie (32 hex). Always verify against the frontend code of the specific version — the format changed empirically.

## Ambiguities / open questions

1. **CVE-2016-10135** — almost certainly not Zabbix (see above); if desired, the original source of the error could be tracked down in the tracker, but NVD/cvelist are unambiguous.
2. **CVE-2022-23131/23134** — the exact JSON cookie format depends on the branch; the PoC scripts were written for 5.4.x; for 6.0.0beta the serverCheck fields are added ([INFERENCE] per 0xdf/6.4x).
3. **CVE-2024-22120** — disagreement between Zabbix (high priv) and NVD (low priv): how exactly 'clientip' gets into the audit (the connection IP over 10051) — confirmed by 0xdf.
4. **CVE-2024-22116** — the exact 6.0.x range: public data only shows 6.4.9+/7.0.0a1+; for 6.0.x check manually.
5. **CVE-2025-27232/27233/27234** — no public PoCs; when scanning, only condition-checks (version + presence of the plugin/feature).
6. The fix versions for 22117/22119/22121-22123 are not specified in the public NVD cpe records (no ranges given) — for the vuln-DB records (peer CveResearch) take them from the ZBX tickets.
