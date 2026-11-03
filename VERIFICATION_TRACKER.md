# Verification Tracker

_Auto-generated 2026-10-29 from db/verifications.json_

**42 modules** (removed: 22121 Windows-MSI, 6693 overflow-unreachable, 23132/27237 not remote): **29 EXPLOITED** · 13 check-pass · 0 condition-only. _Registry has grown to **48 ids** since this matrix was generated (CVE-2026-23923, CVE-2026-23925, TRAPPER-SCRIPT-EXEC aux) — per-CVE rows below are unchanged; see Empirical boundaries + Changelog for the new work._

| CVE | capability | verdict | verified on | evidence |
|---|---|---|---|---|
| CVE-2006-6692 | exploit | **EXPLOITED** | 1.1.2 (source build, pre-2006-10-06) | REMOTE RCE PROVEN end-to-end via the scanner module Cve |
| CVE-2013-3628 | exploit | **EXPLOITED** | 5.4.8-alpine | post-auth global-script RCE confirmed on 5.4.8. |
| CVE-2013-3738 | range-report | **EXPLOITED** | 2.0.6; 2.0.6 (zlex_web_206); 2.0.6 (zlex_web_206) | ZBX-6652 artifact verified LIVE: payload 'http://ZBXRFI; ok:True — unsanitized items[ |
| CVE-2013-5572 | exploit | **EXPLOITED** | 2.0.5 | Cleartext LDAP bind password recovered from Authenticat |
| CVE-2016-10134 | exploit | **EXPLOITED** | 3.0.3 | Unauthenticated error-based SQLi via jsrpc.php profileI |
| CVE-2016-4338 | exploit | **EXPLOITED** | 3.0.2-agent (real, source-built zabbix-agentd 3.0.2) | All three vectors verified end-to-end via 'zscan -m act |
| CVE-2019-17382 | exploit | **check-pass** | 4.4.10-alpine | Stored-XSS payload injected successfully on 4.4.10 (dry |
| CVE-2020-11800 | exploit | **EXPLOITED** | 3.0.30 | Trapper RCE via auto-registration ip injection: active- |
| CVE-2021-46088 | exploit | **EXPLOITED** | 5.4.8-alpine; 6.0.27-alpine; 6.0.31-alpine; 6.0.49-alpine; 6.2.9-alpine; 6.4.21-alpine; 5.0.5; 5.0.47; 5.2.7; 5.4.8; 5.4.12 | script.create+execute on server container: uid=1997(zab; --cmd one-shot, --shell pers |
| CVE-2022-23131 | exploit | **EXPLOITED** | 5.4.8-alpine | Full chain: forged zbx_session (reused anon sessionid/s |
| CVE-2022-23133 | exploit | **check-pass** | 5.0.5-alpine; 5.0.5 | Stored-XSS injection sink confirmed injectable (dry mod; Dry-mode payload built (605B |
| CVE-2022-23134 | exploit | **EXPLOITED** | 5.4.8-alpine | Full takeover verified: forged zbx_session {step:6 + DB |
| CVE-2022-24349 | exploit | **XSS executed (RCE-leg blocked)** | 5.0.5; 5.4.8 | Reflected XSS via actionconf.php eventsource -> onClick operation_details.open raw concat (ZBX-20680/DEV-2077 fix f8eb1de4e244: eventsource flag null->P_SYS). Live: headless victim alert 'Hi! It's a XSS from MN3STRASHN0' + ?v=1 beacon on /actionconf.php?form=create&eventsource=<expr>; script.create via victim session blocked (api needs body sessionid; cookie HttpOnly; sid token = last 16 hex -> 'Session terminated') |
| CVE-2022-24917 | exploit | **check-pass** | 5.0.5-alpine; 5.0.5 | Stored-XSS injection sink confirmed injectable (dry mod; Dry-mode payload built (605B |
| CVE-2022-24918 | exploit | **check-pass** | 5.0.5-alpine; 5.0.5 | Stored-XSS injection sink confirmed injectable (dry mod; Dry-mode payload built (605B |
| CVE-2022-24919 | exploit | **check-pass** | 5.0.5-alpine; 5.0.5 | Stored-XSS injection sink confirmed injectable (dry mod; Dry-mode payload built (605B |
| CVE-2022-46768 | exploit | **EXPLOITED** | 6.0.11-alpine | POST /report {'url':'file:///etc/passwd','parameters':{ |
| CVE-2023-29450 | exploit | **EXPLOITED** | 5.0.5 | JS preprocessing file read via an internal item (type  |
| CVE-2023-32727 | exploit | **EXPLOITED** | 5.0.5 | Oracle: item type 3 'Simple check' key icmpping[<ip>;sl |
| CVE-2023-32728 | exploit | **check-pass** | 5.0.46-alpine agent2 | Arg-injection primitive confirmed: marker ZBXINJECT2334 |
| CVE-2024-22116 | exploit | **EXPLOITED** | 6.4.15-ubuntu (self-built docker stack, MySQL 8.0) | RCE confirmed on 6.4.15: actual vector = user macro |
| CVE-2024-22120 | exploit | **EXPLOITED** | 6.0.27-alpine | Blind time-based SQLi via trapper audit clientip verifi |
| CVE-2024-36460 | exploit | **check-pass** | 7.0.0-alpine; 6.0.27-alpine; 6.0.31-alpine; 7.0.0-alpine | auditlog.get exists on 7.0 and returns records matching; auditlog.get search details= |
| CVE-2024-36464 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Detector verified live: mediatype.get(output extend) re; mediatype.get(output extend) |
| CVE-2024-36465 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Time-based SQLi via API groupBy (CApiService): groupBy ; Full chain exploited on fres |
| CVE-2024-36466 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | 7.4 cookie canonical = base64(json {sessionid, sign}) w; Forged cookie accepted on 7. |
| CVE-2024-36467 | exploit | **EXPLOITED** | 7.0.0-alpine; 6.0.27-alpine; 6.0.31-alpine; 5.0.5; 7.0.0-alpine | user.update added the low user to 'Zabbix administrator; user.update usrgrps escalati |
| CVE-2024-36469 | exploit | **EXPLOITED** | 7.0.0 | user.login timing oracle rebuilt: paired interleav |
| CVE-2024-42325 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine | user.get returns cross-user login-attempt metadata (gue; user.get returns cross-user  |
| CVE-2024-42327 | exploit | **EXPLOITED** | 6.0.31-alpine; 7.0.0-alpine; 7.0.0-alpine | time-based SQLi via user.get selectRole (pg_sleep oracl; Same chain re-verified on 7. |
| CVE-2025-27232 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | LFI via oauth.authorize: state.token_url=file:///etc/pa; LFI via oauth.authorize conf |
| CVE-2025-27233 | exploit | **check-pass** | 7.0.10-alpine agent2 | Argument injection proven: smart.disk.get[device,mode]  |
| CVE-2025-27234 | exploit | **EXPLOITED** | 7.0.10-alpine agent2; 5.0.30-alpine agent2; 5.0.30-alpine agent2 (zbxscan module) | Sanitization ABSENT (params verbatim), but the call goes through ex; smart.disk.get device/mode - |
| CVE-2025-27240 | exploit | **EXPLOITED** | 7.0.0-alpine; 6.0.27-alpine; 7.0.0-alpine | Secondary-order SQLi live on zlab_7_0_0 (web 47467, tra; Live on zlab_6_0_27 (web 454 |
| CVE-2026-1199 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine; 7.4.16-alpine | >5 simultaneous wrong logins passed without lockout — t; >5 simultaneous wrong logins |
| CVE-2026-23921 | exploit | **EXPLOITED** | 7.0.0 | Actual vector found: CApiService::applyQuerySortOpti |
| CVE-2026-23924 | exploit | **EXPLOITED** | 7.0.10-alpine agent2; 7.0.10-alpine agent2 (affected 7.0.0-7.0.22) | docker.sock mounted into agent2: docker.containers leak; FULL PoC - argument injectio |
| CVE-2026-23925 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Low user (role User) with host-group write rights creat; Fresh 7.0.0 stack (zlab_7_0_ |
| CVE-2026-23928 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine | XSS injection sink confirmed injectable on 7.0.0 (dry m; XSS payload built (605 bytes |
| CVE-2026-23933 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | Cookie canonical 7.4 cracked: sign=HMAC-SHA256(seed, co; Cookie forge succeeded on fr |
| CVE-2026-59786 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine | Heartbeat accepted/processed without TLS authentication; Heartbeat {'request':'active |
| ZBX-18134 | exploit | **EXPLOITED** | 5.0.5-alpine; 5.0.5-alpine | host.get output includes tls_psk/tls_psk_identity for a; PSK leak confirmed live: hos |

---

---

## Empirical boundaries (docker bisect, 2026-11)

Verified on real docker stacks — boundaries are empirical, not advisory. Ranges in `db/vulns.json` incorporate these (see `scripts/build_db.py` CURATIONS).

| CVE | Empirical boundary | Evidence |
|---|---|---|
| CVE-2025-27234 | shell-RCE 5.0.25–5.0.38; 5.0.39 argv-only; 5.0.44 whitelist; 5.0.10 no params; 6.x–7.x argv-only | touch-marker bisect on stacks |
| CVE-2026-23925 | vulnerable 6.0.40 / 7.0.17 / 7.2.11; fixed 6.0.41 / 7.0.18 / **7.2.12** / 7.4.2+ | refined probe: low User-role user, import into a group WITHOUT rights; **7.2 widening — silent fix in 7.2.12, absent from advisory** |
| CVE-2023-32727 | 5.0.5 ✗ (no shell stage — fping receives the whole key param as one hostname); 5.0.14 ✓ / 5.0.25 ✓ low-user RCE + reverse shell; 5.0.44 ✗ | item-error signature differential |
| CVE-2024-22120 | 5.0 NOT affected (trapper SQLi oracle absent; advisory range 6.0+) | pg_sleep oracle dead on 5.0 lab |
| CVE-2021-46088 | all branches 4.0–7.4 (privilege-hygiene: Admin script-RCE, no fix exists) | widened per operator instruction |
| CVE-2024-36460 | +7.0 all / +7.2 / +7.4 (beyond advisory) | sweep |
| CVE-2024-36464 | +4.0 (beyond advisory) | sweep |

### Rejected false positives (fixed in modules)
- **CVE-2016-10134** — empty extraction must not be a PASS (`ok:False` on empty extract).
- **CVE-2022-23134** — wizard-progress markers gate the check; fresh installs don't count.
- **CVE-2020-11800 / CVE-2013-3628** — api-script-Admin fallback is the CVE-2021-46088 impact, not these CVEs.
- **CVE-2025-42325** — no media leak under a low-priv user.
- **CVE-2026-1199** — "no lockout" is not a feature; a hit requires ≥5 answered unblocked attempts.

### Prod findings (authorized, 5.0.5 target)
- **CVE-2023-29450 confirmed unauthenticated** (guest): `/etc/hostname` → server hostname, `/etc/passwd` full read; zabbix conf files permission-denied (hardened). Module now picks a server-monitored (non-proxy) host, supports `--max-wait`/`--host` and reports lastclock (never-polled vs patched).
- **Trapper script-exec as guest**: raw `{"request":"command"}` frames execute global scripts without UI. New auxiliary module **TRAPPER-SCRIPT-EXEC** sweeps scriptids and reports executed/denied (on the audited target, scriptid 1=ping, 2=traceroute, 3=Detect OS — nmap executed on the server).
- Arbitrary RCE on 5.0.5 via guest: **not reachable** — DNS/IP interface fields charset-validated, visible name unused by scripts, agent TLS-only, no icmpping shell stage, no 22120 oracle.
- Guest host inventory leak: ~30 hosts (server/db/web boxes, ~120 minions, SNMP gear).
- Prod item latency ~330 s (config cache) — probes need `--max-wait 300`.

## Changelog (this working tree)

### fingerprint
- Version fallback when `apiinfo.version` is disabled (containers/Docker): branch guess from HTML/doc-link markers, `version_approx`/`version_source` fields (`~7.4.x` display, patch unknown).
- Condition probes: `sso_enabled` (SAML on/off via index_sso.php bounce), `agent_port_open` (10050), `server_port_open` (10051).

### exploits
- agent2/trapper modules fail fast when their service port is unreachable on the target host.
- CVE-2026-23925 refined probe: superadmin provisions a low User-role user with RW on one group only; import into a no-rights group distinguishes vulnerable/fixed; anti-false-PASS role checks (custom api.mode=0 roles rejected).
- CVE-2023-32727: documented `--cmd`/`--sleep`, `--host` override, editable/monitored host selection, in-band output marker, trailing-`&` template fix (`&;` syntax error).
- CVE-2023-29450: monitored-host selection, `--max-wait`, `--host`, lastclock diagnostics.
- CVE-2024-22120: `--web-target` (API and trapper on different hosts).
- TRAPPER-SCRIPT-EXEC: new auxiliary module (no CVE; manual `-exp` only).
- CVE-2025-27234 agent2 protocol fixes (NOTSUPPORTED fallback, header shapes, argv probe truncation).
- Empty-password bug: `args.get("password") or "zabbix"` → `args.get("password", "zabbix")` — guest/'' logins were silently broken.
- ConnectionRefused/RequestException guards: all 47 exploit `run()` paths return clean dicts against closed ports.

### cli / autopwn
- Suggestions gated on `condition_status == "pass"`; user/password shell-quoted (empty → `--password ''`); JSON export includes the new fingerprint fields and drops failed conditions.

### Verification (final state of this tree)
- Synthetic check()-sweep: 8 versions × 2 port-states × 48 modules = 768 checks, 0 exceptions.
- pytest `tests/test_fingerprint.py`: 19/19.
- Live smoke (7.4.3 stack): fingerprint fields, module gates, CVE-2021-46088 RCE end-to-end (`uid=1997(zabbix)`).
