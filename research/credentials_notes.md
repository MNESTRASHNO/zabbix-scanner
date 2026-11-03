# Zabbix credentials (2016–2026): research notes

Data file: `credentials.json` (9 records; all `(target, username, password, source)` combinations are unique).
All pairs are taken only from verified sources; anything unconfirmed is in a separate section at the bottom.

---

## 1. Official defaults (category=default)

| target | username | password | Branches | Source |
|---|---|---|---|---|
| frontend (web login) | `Admin` | `zabbix` | **all** (1.8 → 8.0; verified on 1.8, 2.0, 2.2, 2.4, 3.0, 4.0, 5.0, 6.0, 7.0, 7.2, 7.4, 8.0) | Quickstart 'Login and configuring user': `https://www.zabbix.com/documentation/current/en/manual/quickstart/login` (same for `/3.0`, `/4.0`, `/5.0`, `/6.0`, `/7.2`; in 7.0 the URL moved: `.../7.0/en/manual/quickstart/basic_config/login`) |
| api (user.login) | `Admin` | `zabbix` | all | `https://www.zabbix.com/documentation/7.2/en/manual/api/reference/user/login` (auth examples in `.../7.0/en/manual/api`, Authentication section) |
| docker-compose (env) | `zabbix` | `zabbix` | 5.0–7.4 | `https://github.com/zabbix/zabbix-docker` → `env_vars/.env_db_pgsql`, `env_vars/.env_db_mysql` (6.0, 7.0, 7.4 branches) + `https://www.zabbix.com/documentation/5.0/en/manual/installation/containers` |
| database (MySQL/PostgreSQL) | `zabbix` | `zabbix` (docker) / set by the admin (bare-metal) | all | `https://www.zabbix.com/documentation/5.0/en/manual/installation/containers` |
| api (tokens) | — | — | 6.0+ | **No default API tokens exist** (informational record) — `https://www.zabbix.com/documentation/7.0/en/manual/api`, Authentication section |

Key quotes:

- Frontend: 'Enter the user name **Admin** with password **zabbix** to log in as a Zabbix superuser' — the text is identical in all branches.
- Docker env (official container docs 5.0): 'MYSQL_USER … By default, value is 'zabbix'', 'MYSQL_PASSWORD … By default, value is 'zabbix''; the same for `POSTGRES_USER`/`POSTGRES_PASSWORD`; `DB_SERVER_HOST` defaults to `mysql-server`/`postgres-server`; the DB is `zabbix`. In zabbix-docker these same defaults are in `env_vars/` (connected in compose as secrets/env_file; the defaults are commented out as `# MYSQL_PASSWORD=zabbix`, etc.).
- BM (bare-metal) installation: the documentation requires creating the DB user `zabbix` with a password **chosen by the administrator** — there is no fixed default DB password for package/source builds.

---

## 2. per-version

| target | username | password | Branches | Note / source |
|---|---|---|---|---|
| frontend | `guest` | (empty) | enabled by default: 2.x, 3.0, 4.0 < 4.0.15 | 'As a guest, you may access monitoring pages in Zabbix **without being logged in**' (3.0). No password is set. No default permissions. |
| frontend | `guest` | (empty) | disabled by default: from 4.0.15 | 4.0: 'Starting with Zabbix 4.0.15, the 'guest' user is **disabled by default**. To re-enable it, add it to the Guests user group'. |
| frontend | `guest` | (empty) | 5.0–7.2 (disabled) | 5.0: 'disabled by default'; 6.0: 'before Zabbix 6.0.28, automatic guest login was possible'; 7.0+: 'To enable the user, remove the predefined **Disabled** group'. |
| api | — | — | ≤5.2 | login parameter is **`user`**; 5.4+: **`username`** (in 6.0 `user` is deprecated, removed in 7.0) — the Parameters table of `.../manual/api/reference/user/login` across branches 3.0/4.0/4.4/5.0/5.2/5.4/6.0/7.0/7.2. |

There are NO anomalies in the **Admin/zabbix password itself** across 3.0–7.2 — the default has never changed (including in 1.8: the docs already say 'Admin with password zabbix').

---

## 3. popular (wordlists / scanners / blogs)

| target | username | password | Source |
|---|---|---|---|
| frontend | `Admin` | `zabbix` | ProjectDiscovery nuclei-templates `http/default-logins/zabbix/zabbix-default-login.yaml` (POST name/password to `/index.php`, `/zabbix/index.php`; matcher 302 → `zabbix.php?action=dashboard.view`) |
| frontend | `Admin` | `zabbix` | SecLists `Passwords/Default-Credentials/default-passwords.csv` — the line `zabbix,Admin,zabbix` (the only zabbix pair in all of SecLists; default-passwords.txt has only the password line `zabbix`) |
| frontend | `guest` | (empty) | Metasploit `modules/auxiliary/scanner/http/zabbix_login.rb` — 'Zabbix Server Brute Force Utility': tests `Admin:zabbix` and guest mode ('This Zabbix instance has Guest mode enabled') |
| frontend | `Admin` | `zabbix` | AccessChecker blog `https://www.accesschecker.net/en/software/zabbix` (claims 'case-sensitive', references the official documentation) |

All popular sources repeat the same `Admin`/`zabbix` pair — no other confirmed pairs were found in wordlists for Zabbix.

---

## 4. user.login — request format per branch

Endpoint: `POST http(s)://<host>/zabbix/api_jsonrpc.php` (JSON-RPC 2.0).

| Branch | Username parameter | Request |
|---|---|---|
| ≤ 5.2 (3.0, 4.0, 4.4, 5.0, 5.2) | `user` | `{"jsonrpc":"2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"id":1}` |
| 5.4, 6.0 | `username` (in 6.0 `user` is still accepted, deprecated) | `{"jsonrpc":"2.0","method":"user.login","params":{"username":"Admin","password":"zabbix"},"id":1}` |
| 7.0, 7.2, 7.4 (current), 8.0 | `username` (only) | the same; optionally `"userData":true` → the response contains the user object instead of a sessionid |

Response: `{"jsonrpc":"2.0","result":"<sessionid>","id":1}` (24 chars, hex). The method is called **without** the `auth` field.

⚠️ **Correction to the task statement**: the task said '7.0+ requires passing `user` instead of `username`' — in fact it is **the opposite**: `user` was used BEFORE 5.2, and from **5.4** `username` is required (in 7.0+ `user` is no longer documented). Verified against the Parameters tables of each branch's documentation.

API authentication in 6.0+ is also possible with an API token: the `auth` field in JSON-RPC or the `Authorization: Bearer <token>` header; the token is created by the user manually (Users > API tokens / the `token.create` method) — **no default tokens exist** (see the Authentication section of `.../7.0/en/manual/api`).

---

## 5. What is NOT confirmed (excluded from credentials.json)

| Pair / fact | Status |
|---|---|
| `admin/admin` (old 1.8/2.0) | ❌ Not confirmed: already in 1.8 the documentation gives `Admin`/`zabbix`. A legend from earlier versions (<1.8), outside the 2016–2026 window. |
| `admin/zabbix` (lowercase) | ⚠️ No source pair found. Works only when the 'Case sensitive login' option is disabled (exists since ~4.0, **enabled by default**: 'Unmark the checkbox to disable case-sensitive login … enabled by default' — `.../manual/web_interface/frontend_sections/administration/authentication`, branches 4.0/5.0/6.0). In 3.x the setting is not documented. |
| `zabbix`/`zabbix` as a frontend web login | ❌ Not confirmed: these are the DB/docker credentials, not the UI. No such zabbix pair for the frontend exists in wordlists. |
| `guest`/`guest` | ❌ Not confirmed by any source. |
| `cirt.net/passwords` → zabbix | ⚠️ Unavailable: cirt.net returns a Cloudflare block (and cannot be fetched via web.archive.org). The SecLists collection `cirt-net_collection.txt` has no zabbix entries. |
| root password of the Zabbix appliance (OVA) | ⚠️ Not confirmed by the official documentation (the `manual/quickstart/appliance` pages contain no explicit credentials). Not included. |
| guest login via the API | ⚠️ Not confirmed: the permissionless guest exists for unauthenticated web access; the `user.login("guest","")` scenario is not described in the documentation. |

---

## 6. Sources (summary)

Official (default/per-version):
- `https://www.zabbix.com/documentation/{3.0|4.0|5.0|6.0|7.0|7.2|current}/en/manual/quickstart/login` (+ `7.0/en/manual/quickstart/basic_config/login`)
- `https://www.zabbix.com/documentation/{2.0|3.0|4.4|5.0|5.2|5.4|6.0|7.0|7.2}/en/manual/api/reference/user/login`
- `https://www.zabbix.com/documentation/7.0/en/manual/api` (Authentication; token)
- `https://www.zabbix.com/documentation/{3.0|4.0|5.0|6.0|7.0|7.2}/en/manual/config/users_and_usergroups/user` (guest)
- `https://www.zabbix.com/documentation/{5.0|current}/en/manual/installation/containers` (docker env)
- `https://www.zabbix.com/documentation/{4.0|5.0|6.0}/en/manual/web_interface/frontend_sections/administration/authentication` (case-sensitive login)

Wordlists/scanners (popular):
- `https://github.com/danielmiessler/SecLists` → `Passwords/Default-Credentials/default-passwords.csv`, `cirt-net_collection.txt`
- `https://github.com/projectdiscovery/nuclei-templates` → `http/default-logins/zabbix/zabbix-default-login.yaml`
- `https://github.com/rapid7/metasploit-framework` → `modules/auxiliary/scanner/http/zabbix_login.rb`
- `https://www.accesschecker.net/en/software/zabbix`

Docker repo: `https://github.com/zabbix/zabbix-docker` (6.0, 7.0, 7.4 branches; `env_vars/.env_db_{mysql,pgsql}`).
