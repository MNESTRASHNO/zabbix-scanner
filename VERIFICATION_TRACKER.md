# Verification Tracker

_Auto-generated 2026-10-29 from db/verifications.json_

**42 modules** (removed: 22121 Windows-MSI, 6693 overflow-unreachable, 23132/27237 not remote): **29 EXPLOITED** · 13 check-pass · 0 condition-only.

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
| CVE-2023-29450 | exploit | **EXPLOITED** | 5.0.5 | JS preprocessing file read через внутренний item (type  |
| CVE-2023-32727 | exploit | **EXPLOITED** | 5.0.5 | Oracle: item type 3 'Simple check' key icmpping[<ip>;sl |
| CVE-2023-32728 | exploit | **check-pass** | 5.0.46-alpine agent2 | Arg-injection primitive confirmed: marker ZBXINJECT2334 |
| CVE-2024-22116 | exploit | **EXPLOITED** | 6.4.15-ubuntu (self-built docker stack, MySQL 8.0) | RCE подтверждён на 6.4.15: реальный вектор = user macro |
| CVE-2024-22120 | exploit | **EXPLOITED** | 6.0.27-alpine | Blind time-based SQLi via trapper audit clientip verifi |
| CVE-2024-36460 | exploit | **check-pass** | 7.0.0-alpine; 6.0.27-alpine; 6.0.31-alpine; 7.0.0-alpine | auditlog.get exists on 7.0 and returns records matching; auditlog.get search details= |
| CVE-2024-36464 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Detector verified live: mediatype.get(output extend) re; mediatype.get(output extend) |
| CVE-2024-36465 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Time-based SQLi via API groupBy (CApiService): groupBy ; Full chain exploited on fres |
| CVE-2024-36466 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | 7.4 cookie canonical = base64(json {sessionid, sign}) w; Forged cookie accepted on 7. |
| CVE-2024-36467 | exploit | **EXPLOITED** | 7.0.0-alpine; 6.0.27-alpine; 6.0.31-alpine; 5.0.5; 7.0.0-alpine | user.update added the low user to 'Zabbix administrator; user.update usrgrps escalati |
| CVE-2024-36469 | exploit | **EXPLOITED** | 7.0.0 | user.login timing oracle переработан: парные интерливир |
| CVE-2024-42325 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine | user.get returns cross-user login-attempt metadata (gue; user.get returns cross-user  |
| CVE-2024-42327 | exploit | **EXPLOITED** | 6.0.31-alpine; 7.0.0-alpine; 7.0.0-alpine | time-based SQLi via user.get selectRole (pg_sleep oracl; Same chain re-verified on 7. |
| CVE-2025-27232 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | LFI via oauth.authorize: state.token_url=file:///etc/pa; LFI via oauth.authorize conf |
| CVE-2025-27233 | exploit | **check-pass** | 7.0.10-alpine agent2 | Argument injection proven: smart.disk.get[device,mode]  |
| CVE-2025-27234 | exploit | **EXPLOITED** | 7.0.10-alpine agent2; 5.0.30-alpine agent2; 5.0.30-alpine agent2 (zbxscan module) | Санитизации НЕТ (параметры verbatim), но вызов через ex; smart.disk.get device/mode - |
| CVE-2025-27240 | exploit | **EXPLOITED** | 7.0.0-alpine; 6.0.27-alpine; 7.0.0-alpine | Secondary-order SQLi live on zlab_7_0_0 (web 47467, tra; Live on zlab_6_0_27 (web 454 |
| CVE-2026-1199 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine; 7.4.16-alpine | >5 simultaneous wrong logins passed without lockout — t; >5 simultaneous wrong logins |
| CVE-2026-23921 | exploit | **EXPLOITED** | 7.0.0 | Реальный вектор найден: CApiService::applyQuerySortOpti |
| CVE-2026-23924 | exploit | **EXPLOITED** | 7.0.10-alpine agent2; 7.0.10-alpine agent2 (affected 7.0.0-7.0.22) | docker.sock mounted into agent2: docker.containers leak; FULL PoC - argument injectio |
| CVE-2026-23925 | exploit | **EXPLOITED** | 7.0.0-alpine; 7.0.0-alpine | Low user (role User) with host-group write rights creat; Fresh 7.0.0 stack (zlab_7_0_ |
| CVE-2026-23928 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine | XSS injection sink confirmed injectable on 7.0.0 (dry m; XSS payload built (605 bytes |
| CVE-2026-23933 | exploit | **EXPLOITED** | 7.4.2-alpine; 7.4.2-alpine | Cookie canonical 7.4 cracked: sign=HMAC-SHA256(seed, co; Cookie forge succeeded on fr |
| CVE-2026-59786 | exploit | **check-pass** | 7.0.0-alpine; 7.0.0-alpine; 7.4.2-alpine | Heartbeat accepted/processed without TLS authentication; Heartbeat {'request':'active |
| ZBX-18134 | exploit | **EXPLOITED** | 5.0.5-alpine; 5.0.5-alpine | host.get output includes tls_psk/tls_psk_identity for a; PSK leak confirmed live: hos |
